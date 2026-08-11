"""
geo_features.py

Per-service territorial boundary check (geo_policy.yaml).

Distinct from auth_features.geo_mismatch (which detects a *change* in location):
  - geo_mismatch  = user moved compared to their last known location (behavioural)
  - is_outside_uae = user is currently outside the allowed zone (policy)

GEO-01 in rules.yaml thresholds on is_outside_uae.  It carries weight 80 so that
being outside the allowed zone alone drives score to CRITICAL → BLOCK.

Per-service allowed prefixes (geo_policy.yaml):
  AUTH/WALLET/CONSENT  — ["AE"] only
  ENROLL               — ["AE","GB","US","DE","IN","FR","SA","PK"]
                         (citizens may enroll at UAE embassies abroad)

Fail-open on missing geo: returns 0 if geo_loc is absent so GEO-01 does not fire.
"""

from pathlib import Path
from typing import Optional

from core.config_loader import HotConfig

_geo_policy_config = HotConfig(
    Path(__file__).parent.parent / "config/geo_policy.yaml"
)


def _get_allowed_prefixes(service: Optional[str]) -> list[str]:
    cfg = _geo_policy_config.get()
    key = (service or "").upper()
    service_cfg = cfg.get(key, cfg.get("default", {}))
    return [p.upper() for p in service_cfg.get("allowed_prefixes", ["AE"])]


def build_geo_features(context, service: Optional[str] = None) -> dict:
    """
    Return {"is_outside_uae": 0 | 1}.
    0 — geo_loc absent (fail-open) or starts with an allowed prefix for this service
    1 — geo_loc present and outside the allowed zone
    """
    geo_loc = getattr(context.security_payload, "geo_loc", None)
    if not geo_loc:
        return {"is_outside_uae": 0}

    geo_upper = geo_loc.upper()
    allowed = _get_allowed_prefixes(service)
    is_outside = 0 if any(geo_upper.startswith(p) for p in allowed) else 1
    return {"is_outside_uae": is_outside}
