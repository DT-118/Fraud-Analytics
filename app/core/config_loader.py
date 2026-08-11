"""
config_loader.py

Shared hot-reload YAML config loader.

Each HotConfig instance owns one YAML file.  The first .get() call loads
the file; subsequent calls return the cached value until the TTL expires,
then reload transparently.  If a reload fails the stale cache is returned
and a warning is logged — scoring is never blocked by a transient disk error.

If the initial load fails (file missing, unreadable, or invalid YAML) a
RuntimeError is raised immediately so misconfigured deployments fail fast
rather than silently using empty configuration.

Thread safety:
  - get()     is lock-free on the hot path (cache hit)
  - _reload() uses a lock + double-check so only one thread pays the disk I/O
              cost when the TTL expires under concurrent load.

Usage:
    _weights_config = HotConfig(_CONFIG_DIR / "service_weights.yaml")

    def some_function():
        cfg = _weights_config.get()   # dict, always returns something
"""

import threading
import time
from pathlib import Path

import yaml

from core.logger import logger

_DEFAULT_TTL: float = 300.0   # 5 minutes


class HotConfig:
    """Thread-safe hot-reloading YAML config."""

    def __init__(self, path: Path, ttl: float = _DEFAULT_TTL) -> None:
        self._path      = path
        self._ttl       = ttl
        self._cache: dict | None = None
        self._loaded_at: float   = 0.0
        self._lock = threading.Lock()

    def get(self) -> dict:
        """Return current config, reloading from disk if the TTL has expired."""
        now = time.monotonic()
        # Fast path: no lock needed for a cache hit
        if self._cache is not None and (now - self._loaded_at) < self._ttl:
            return self._cache
        return self._reload()

    def invalidate(self) -> None:
        """Force the next .get() to reload from disk (used by admin API)."""
        with self._lock:
            self._loaded_at = 0.0

    def _reload(self) -> dict:
        with self._lock:
            # Double-check: another thread may have reloaded while we waited for the lock
            now = time.monotonic()
            if self._cache is not None and (now - self._loaded_at) < self._ttl:
                return self._cache

            try:
                with open(self._path) as f:
                    data = yaml.safe_load(f) or {}
                self._cache     = data
                self._loaded_at = time.monotonic()
                logger.info("[CONFIG] Loaded %s", self._path.name)
                return self._cache

            except Exception as exc:
                if self._cache is not None:
                    # Transient reload failure — serve stale cache rather than blocking scoring
                    logger.warning(
                        "[CONFIG] Reload failed for %s — using stale cache: %s",
                        self._path.name, exc,
                    )
                    return self._cache

                # Initial load failure — fail fast: misconfigured deployments must not start
                logger.error("[CONFIG] Initial load failed for %s: %s", self._path.name, exc)
                raise RuntimeError(
                    f"Required config file failed to load: {self._path}"
                ) from exc
