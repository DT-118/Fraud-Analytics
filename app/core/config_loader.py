"""
Thread-safe hot-reloading YAML configuration loader.

Each HotConfig instance owns one YAML file. The configuration is loaded on
first access and cached for the configured TTL. An explicit invalidate() can
force the next get() to reload immediately, which is used by the admin
configuration-reload endpoint.

Reload policy:
    - Initial load failure: fail fast. The application must not silently start
      with missing or invalid required configuration.
    - Subsequent reload failure: keep the last known-good configuration and
      log the failure. A transient filesystem/configuration issue must not
      interrupt fraud scoring with an invalid or empty configuration.

Concurrency:
    - Cache hits do not acquire the lock.
    - Reload uses a lock and double-checks the cache to avoid duplicate disk I/O
      when multiple threads cross the TTL boundary simultaneously.

"""

from __future__ import annotations
import threading
import time
from pathlib import Path
from typing import Any
import yaml
from core.logger import logger


DEFAULT_CONFIG_TTL_SECONDS = 300.0  # 300 seconds = 5 minutes


class HotConfig:
    """Load and cache a YAML mapping with safe concurrent hot reloads."""

    def __init__(
        self,
        path: Path,
        ttl_seconds: float = DEFAULT_CONFIG_TTL_SECONDS,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be greater than zero")

        self._path = Path(path)
        self._ttl_seconds = float(ttl_seconds)
        self._cache: dict[str, Any] | None = None
        self._loaded_at = 0.0
        self._lock = threading.Lock()

    def get(self) -> dict[str, Any]:
        """
        Return the current configuration.

        Returns the cached configuration while it is fresh. When the cache
        expires, one thread reloads the file while other concurrent callers
        wait for the same known-good result.
        """
        now = time.monotonic()

        if (
            self._cache is not None
            and now - self._loaded_at < self._ttl_seconds
        ):
            return self._cache

        return self._reload()

    def invalidate(self) -> None:
        """Mark the cached configuration stale so the next get() reloads it."""
        with self._lock:
            self._loaded_at = 0.0

    def _reload(self) -> dict[str, Any]:
        """Load the YAML file, retaining the last known-good value on failure."""
        with self._lock:
            now = time.monotonic()

            # Another thread may have completed the reload while this thread
            # waited for the lock.
            if (
                self._cache is not None
                and now - self._loaded_at < self._ttl_seconds
            ):
                return self._cache

            try:
                with self._path.open("r", encoding="utf-8") as config_file:
                    data = yaml.safe_load(config_file)

                # Every application config file is expected to be a YAML
                # mapping. Accepting lists/scalars here would make the failure
                # appear much later as an unrelated application error.
                if data is None:
                    data = {}

                if not isinstance(data, dict):
                    raise ValueError(
                        f"Expected a YAML mapping, got {type(data).__name__}"
                    )

            except Exception as exc:
                if self._cache is not None:
                    logger.warning(
                        "[CONFIG] Reload failed for %s; using last known-good "
                        "configuration: %s",
                        self._path,
                        exc,
                    )
                    return self._cache

                logger.error(
                    "[CONFIG] Initial load failed for %s: %s",
                    self._path,
                    exc,
                )
                raise RuntimeError(
                    f"Required configuration failed to load: {self._path}"
                ) from exc

            self._cache = data
            self._loaded_at = time.monotonic()

            logger.info("[CONFIG] Loaded %s", self._path)
            return self._cache