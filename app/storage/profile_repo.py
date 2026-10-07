"""
profile_repo.py

Persistence layer for dynamic risk profiles.

Two tables:
  user_service_risk_profile   — one row per (subject_id, service)
  user_identity_risk_profile  — one row per subject_id (composite)

Scoped to the 4 services this engine actually handles: AUTH, LOGIN,
CONSENT, WALLET.

-----------------------------------------------------------------------------
Per-service score = three independent signals blended together
-----------------------------------------------------------------------------
1. SLOW tier (rolling_score) — days-scale EWMA, tracks cross-session drift.
     α  = e^{-λ_k × Δt_days}   where λ_k = ln(2) / H_k  (H_k = per-service
     half-life from service_weights.yaml's service_half_life block)
     new_rolling = old_rolling × α  +  new_score × (1 − α)

2. FAST/BURST tier (burst_average) — minutes-scale, TRUE decay-weighted
     average over raw recent scores (not a recursive EWMA approximation),
     kept in Redis with a short TTL:
       Rc = (Σ wᵢ · sᵢ) / (Σ wᵢ),   wᵢ = e^{-λ_fast(T − tᵢ)}
     This is what reacts within a single burst of events seconds/minutes
     apart, which the slow tier (by design) barely moves on.

   blended_rolling = burst.blend_weight · burst_average
                      + (1 − burst.blend_weight) · rolling_score

3. Escalation penalty (escalation_score) — independent additive bump when a
     single event's risk_level crosses a configured trigger (HIGH/CRITICAL),
     decaying on its OWN half-life (usually slower than both tiers above),
     so a severe event stays visible even after both the slow and burst
     tiers would otherwise have diluted or faded it out.

   effective_score = min(100, blended_rolling + escalation_score)

effective_score (NOT rolling_score alone) is what propagates into the
composite identity score — this is what lets a burst-visible or
escalation-flagged severe event actually move the subject's overall risk.

-----------------------------------------------------------------------------
Composite identity score
-----------------------------------------------------------------------------
R_new = Σ (β_k · effective_score_k)  +  B_cross · e^{-λ_slow · Δt_since_flag}

  β_k — per-service composite weight (service_weights.yaml composite_weights).
        If renormalize_active_weights is true (default), β_k is renormalized
        to sum to 1.0 across only the services that currently have data for
        this subject — a brand-new subject's single AUTH event then carries
        its full weight instead of being diluted by weight budget reserved
        for services that haven't fired yet.

  B_cross — flat cross-service bonus, decayed on a slow half-life from the
            most recent cross-service detection. The flag lapses once the
            decayed bonus falls below cross_service_flag_min_bonus; a fresh
            detection restarts the decay clock.

composite_score (S_t) = a SECOND smoothing pass on top of R_new:
  S_t = composite_smoothing_alpha · R_new  +  (1 − composite_smoothing_alpha) · S_(t-1)
Cold start (no prior row) skips smoothing: S_t = R_new on the first event.
This is what keeps the stored composite from snapping to R_new the instant
one service's effective_score jumps (e.g. an escalation bump firing) —
it climbs toward R_new gradually instead.

contributing_factors — a ranked (descending by contribution) breakdown of
  which service, plus the cross-service bonus if active, drove the current
  composite_score. Stored as JSONB, surfaced by fetch_identity_profile().

Identity profile additionally maintains, per subject:
  - previous_composite_score + risk_trend  (RISING / STABLE / FALLING / NEW)
  - effective_events N_eff  (decayed event count, an effective sample size)
  - confidence = 1 − e^{-N_eff / κ}  and a derived profile_status
    (PROVISIONAL / ESTABLISHED / UNDER_REVIEW)
"""
from __future__ import annotations
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from psycopg2.extras import Json
from core.config_loader import HotConfig
from core.errors import ErrorCode
from core.logger import logger
from storage.redis_client import redis_client
from core.constants import VALID_SERVICES

# Profile defaults. Values can be overridden in service_weights.yaml.
# Half-lives are expressed in DAYS (slow tier) or MINUTES (burst tier) and
# converted to λ = ln(2)/H at use time, so config authors reason in the
# intuitive unit ("evidence counts half as much after H") rather than raw λ.
# ---------------------------------------------------------------------------
_DEFAULT_SERVICE_HALF_LIFE_DAYS: float = 7.0     # routine per-service activity (slow tier)
_DEFAULT_CROSS_HALF_LIFE_DAYS:   float = 60.0   # confirmed cross-service fraud
_DEFAULT_CROSS_FLAG_MIN_BONUS:   float = 3.75    # flag lapses below this decayed bonus
_DEFAULT_CONFIDENCE_KAPPA:       float = 5.0     # N_eff scale for confidence
_DEFAULT_ESTABLISHED_THRESHOLD:  float = 0.6     # confidence ≥ this ⇒ ESTABLISHED
_TREND_DEADBAND:                 float = 1.0     # |ΔC| ≤ this ⇒ STABLE (anti-jitter)

# Escalation-penalty defaults — used only if service_weights.yaml's
# `escalation` block is absent or partially specified.
_DEFAULT_ESCALATION_ENABLED:     bool  = True
_DEFAULT_ESCALATION_TRIGGERS:    dict  = {"HIGH": 15, "CRITICAL": 30}
_DEFAULT_ESCALATION_HALF_LIFE:   float = 14.0

# Burst-tier defaults — used only if service_weights.yaml's `burst` block
# is absent or partially specified.
_DEFAULT_BURST_HALF_LIFE_MIN:    float = 5.0
_DEFAULT_BURST_WINDOW_MIN:       float = 30.0
_DEFAULT_BURST_BLEND_WEIGHT:     float = 0.4

# Composite smoothing default.
_DEFAULT_COMPOSITE_ALPHA:        float = 0.3

_weights_config = HotConfig(Path(__file__).parent.parent / "config/service_weights.yaml")

def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

def _profile_config() -> dict:
    """
    Load all profile tuning parameters from service_weights.yaml, with safe
    defaults if any key is absent.  Hot-reloaded via HotConfig.
    """
    cfg = _weights_config.get()
    return {
        "weights": cfg.get("composite_weights", {
            "AUTH": 0.40, "LOGIN": 0.25, "WALLET": 0.25, "CONSENT": 0.10,
        }),
        "renormalize_active": bool(cfg.get("renormalize_active_weights", True)),
        "cross_bonus":        float(cfg.get("cross_service_bonus", 15)),
        "service_half_life":  cfg.get("service_half_life", {}) or {},
        "default_service_hl": float(cfg.get("default_service_half_life_days",
                                            _DEFAULT_SERVICE_HALF_LIFE_DAYS)),
        "cross_hl":           float(cfg.get("cross_service_half_life_days",
                                            _DEFAULT_CROSS_HALF_LIFE_DAYS)),
        "cross_flag_floor":   float(cfg.get("cross_service_flag_min_bonus",
                                            _DEFAULT_CROSS_FLAG_MIN_BONUS)),
        "kappa":              float(cfg.get("confidence_kappa",
                                            _DEFAULT_CONFIDENCE_KAPPA)),
        "established_thr":    float(cfg.get("established_threshold",
                                            _DEFAULT_ESTABLISHED_THRESHOLD)),
        "escalation":         cfg.get("escalation", {}) or {},
        "burst":              cfg.get("burst", {}) or {},
        "composite_alpha":    float(cfg.get("composite_smoothing_alpha",
                                            _DEFAULT_COMPOSITE_ALPHA)),
    }


def _escalation_settings() -> tuple[bool, dict, float]:
    """
    Resolve (enabled, trigger_penalties, half_life_days) for the escalation
    penalty from service_weights.yaml's `escalation` block, falling back to
    module defaults for any missing key.
    """
    esc_cfg = _profile_config()["escalation"]
    enabled = bool(esc_cfg.get("enabled", _DEFAULT_ESCALATION_ENABLED))
    triggers = esc_cfg.get("trigger_penalties", _DEFAULT_ESCALATION_TRIGGERS) or {}
    half_life = float(esc_cfg.get("half_life_days", _DEFAULT_ESCALATION_HALF_LIFE))
    return enabled, triggers, half_life


def _burst_settings(service: str) -> tuple[float, float, float]:
    """
    Resolve (half_life_minutes, window_minutes, blend_weight) for the burst
    tier, for a given service, falling back to module defaults for any
    missing key.
    """
    burst_cfg = _profile_config()["burst"]
    half_lives = burst_cfg.get("half_life_minutes", {}) or {}
    half_life_min = float(half_lives.get(
        service, burst_cfg.get("default_half_life_minutes", _DEFAULT_BURST_HALF_LIFE_MIN)
    ))
    window_min = float(burst_cfg.get("window_minutes", _DEFAULT_BURST_WINDOW_MIN))
    blend_weight = float(burst_cfg.get("blend_weight", _DEFAULT_BURST_BLEND_WEIGHT))
    return half_life_min, window_min, blend_weight


def _decay_factor(last_event_time: Optional[datetime], half_life_days: float, reference_time: Optional[datetime] = None) -> float:
    """
    Return EWMA decay factor α = e^{-λ × Δt_days} with λ = ln(2)/half_life_days.

    Per-signal: the caller passes the half-life appropriate to the signal.
    Returns 0.0 if there is no prior event (⇒ the incoming value is taken in
    full), and 1.0 defensively if half_life_days is non-positive.
    """
    if last_event_time is None:
        return 0.0
    if half_life_days <= 0:
        return 1.0
    now = reference_time if reference_time is not None else datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    if last_event_time.tzinfo is None:
        last_event_time = last_event_time.replace(tzinfo=timezone.utc)
    delta_days = max(0.0, (now - last_event_time).total_seconds() / 86400.0)
    lam = math.log(2) / half_life_days
    return math.exp(-lam * delta_days)


def _burst_key(subject_id: str, service: str) -> str:
    return f"burst:scores:{subject_id}:{service}"


def _compute_burst_average(
    subject_id: str,
    service: str,
    new_score: int,
    event_time: datetime,
) -> float:
    """
    Rc = (Σ wᵢ·sᵢ) / (Σ wᵢ), wᵢ = e^(−λ(T−tᵢ)) — computed literally over the
    raw events seen in the last `window_minutes`, stored in Redis. This is a
    true weighted average of recent raw scores (not a recursive EWMA blend),
    so it reacts within a single burst the way the slow, days-scale
    rolling_score never can.

    Fails open: any Redis error returns new_score alone (i.e. behaves as if
    this were the only event in the window).
    """
    half_life_min, window_min, _ = _burst_settings(service)
    half_life_seconds = half_life_min * 60.0
    window_seconds = window_min * 60.0

    now_ts = event_time.timestamp() if event_time.tzinfo else \
        event_time.replace(tzinfo=timezone.utc).timestamp()

    try:
        key = _burst_key(subject_id, service)
        raw = redis_client.get(key)
        entries = json.loads(raw) if raw else []
        # Drop anything outside the window before adding the new event.
        entries = [e for e in entries if (now_ts - e["ts"]) <= window_seconds]
        entries.append({"ts": now_ts, "score": new_score})

        numerator = 0.0
        denominator = 0.0
        for e in entries:
            delta_seconds = max(0.0, now_ts - e["ts"])
            w = math.exp(-(math.log(2) / half_life_seconds) * delta_seconds)
            numerator += w * e["score"]
            denominator += w

        redis_client.setex(key, int(window_seconds) + 60, json.dumps(entries))

        return round(numerator / denominator, 2) if denominator > 0 else float(new_score)

    except Exception as exc:
        logger.warning(
            "[PROFILE] burst average failed subject_id=%s service=%s — using new_score alone: %s",
            subject_id, service, exc,
        )
        return float(new_score)


def upsert_service_profile(
    db_connection,
    subject_id: str,
    service: str,
    new_score: int,
    event_id: str,
    event_time: datetime,
    risk_level: str,
) -> dict:
    """
    Upsert the per-service score: slow-tier EWMA (rolling_score), fast-tier
    burst average (burst_average, Redis-only), their blend (blended_rolling),
    and the independent escalation penalty (escalation_score).

    rolling_score     — days-scale EWMA, unchanged math from earlier phases.
                         Diluted almost to nothing within a fast burst — by
                         design, it tracks slow drift, not bursts.
    burst_average      — minutes-scale true decay-weighted average over raw
                         recent scores (Redis-only, not persisted to this
                         row). Reacts within a single burst.
    blended_rolling     — burst.blend_weight · burst_average
                          + (1 − burst.blend_weight) · rolling_score
    escalation_score    — decays on its own (usually slower) half-life,
                         bumped when this event's risk_level matches a
                         configured trigger. Represents "something severe
                         happened recently", independent of both tiers above.
    effective_score      — min(100, blended_rolling + escalation_score). This
                         is what gets propagated to the composite identity
                         score, NOT rolling_score alone.

    Returns:
      {"rolling_score", "burst_average", "blended_rolling",
       "escalation_score", "effective_score"}
    """
    fetch_sql = """
        SELECT rolling_score, last_event_time, event_count,
               escalation_score, escalation_updated_at,
               last_event_id, last_risk_level
        FROM   user_service_risk_profile
        WHERE  subject_id = %s AND service = %s
        FOR UPDATE
    """
    upsert_sql = """
        INSERT INTO user_service_risk_profile (
            subject_id, service, rolling_score, last_blended_score, event_count,
            last_event_id, last_event_time, last_risk_level, escalation_score, escalation_updated_at,
            updated_at
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        ON CONFLICT (subject_id, service) DO UPDATE SET
            rolling_score          = EXCLUDED.rolling_score,
            last_blended_score     = EXCLUDED.last_blended_score,
            event_count            = EXCLUDED.event_count,
            last_event_id          = EXCLUDED.last_event_id,
            last_event_time        = EXCLUDED.last_event_time,
            last_risk_level        = EXCLUDED.last_risk_level,
            escalation_score       = EXCLUDED.escalation_score,
            escalation_updated_at  = EXCLUDED.escalation_updated_at,
            updated_at             = NOW()
    """
    try:
        with db_connection.cursor() as cur:
            cur.execute(fetch_sql, (subject_id, service))
            row = cur.fetchone()

        cfg = _profile_config()
        esc_enabled, esc_triggers, esc_half_life = _escalation_settings()

        if row:
            (old_rolling, last_event_time, event_count,
             old_escalation, escalation_updated_at,
             old_last_event_id, old_last_risk_level) = row
            old_escalation = float(old_escalation) if old_escalation is not None else 0.0

            half_life = float(cfg["service_half_life"].get(service, cfg["default_service_hl"]))
            alpha = _decay_factor(last_event_time, half_life, reference_time=event_time)
            new_rolling = round(float(old_rolling) * alpha + new_score * (1.0 - alpha), 2)
            new_count = event_count + 1
        else:
            new_rolling = float(new_score)
            new_count = 1
            old_escalation = 0.0
            escalation_updated_at = None
            last_event_time = None
            old_last_event_id = None
            old_last_risk_level = None

        new_rolling = min(100.0, max(0.0, new_rolling))

        # --- Fast/burst tier: true decay-weighted average over raw events ---
        burst_avg = _compute_burst_average(subject_id, service, new_score, event_time)
        _, _, blend_weight = _burst_settings(service)
        blended_rolling = round(
            blend_weight * burst_avg + (1.0 - blend_weight) * new_rolling, 2
        )
        blended_rolling = min(100.0, max(0.0, blended_rolling))

        # --- Escalation penalty: decay what's there, then bump if triggered ---
        if esc_enabled:
            esc_ref = event_time
            if escalation_updated_at is not None and _aware(escalation_updated_at) > _aware(event_time):
                esc_ref = escalation_updated_at      # never move the clock backwards
            esc_decay = _decay_factor(escalation_updated_at, esc_half_life, reference_time=esc_ref)
            decayed_escalation = old_escalation * esc_decay
            bump = float(esc_triggers.get(risk_level, 0))
            new_escalation = round(decayed_escalation + bump, 2)
            new_escalation_updated_at = esc_ref
        else:
            new_escalation = 0.0
            new_escalation_updated_at = None

        new_escalation = min(100.0, max(0.0, new_escalation))
        effective_score = min(100.0, round(blended_rolling + new_escalation, 2))

        # A late-arriving event still counts toward the scores, but must not
        # overwrite the "latest event" fields with older values.
        stored_event_id, stored_event_time, stored_risk_level = event_id, event_time, risk_level
        if last_event_time is not None and _aware(event_time) < _aware(last_event_time):
            stored_event_id = old_last_event_id
            stored_event_time = last_event_time
            stored_risk_level = old_last_risk_level

        with db_connection.cursor() as cur:
            cur.execute(upsert_sql, (
                subject_id, service, new_rolling, blended_rolling, new_count,
                stored_event_id, stored_event_time, stored_risk_level,
                new_escalation, new_escalation_updated_at,
            ))

        return {
            "rolling_score":    new_rolling,
            "burst_average":    burst_avg,
            "blended_rolling":  blended_rolling,
            "escalation_score": new_escalation,
            "effective_score":  effective_score,
        }

    except Exception as exc:
        logger.exception("%s: upsert_service_profile failed subject_id=%s service=%s",
                         ErrorCode.DATABASE_ERROR, subject_id, service)
        raise RuntimeError(ErrorCode.DATABASE_ERROR) from exc


def upsert_identity_profile(
    db_connection,
    subject_id: str,
    event_time: datetime,
    service_scores: dict[str, float],
    cross_service_flag: bool = False,
    cross_service_flag_reason: Optional[str] = None,
) -> float:
    """
    Recompute and persist the composite identity risk profile.

    R_new = min(100, Σ (β_k · effective_score_k) + B_cross · e^{-λ_slow · Δt})
      β_k renormalized to only services with data in service_scores if
      renormalize_active_weights is true (default) — see _profile_config().

    composite_score (S_t) = a second smoothing pass on top of R_new:
      S_t = composite_alpha · R_new + (1 − composite_alpha) · S_(t-1)
      Cold start (no prior row): S_t = R_new.

    contributing_factors — ranked (desc by contribution) list of
      {service, effective_score, weight, contribution}, plus the
      cross-service bonus entry if active. Stored as JSONB.

    Also maintained on the identity row:
      - previous_composite_score + risk_trend  (RISING / STABLE / FALLING / NEW)
      - effective_events N_eff — a decayed event count (effective sample size),
        updated N_eff ← N_eff · α_count + 1
      - confidence = 1 − e^{-N_eff/κ}  and a derived profile_status
        (UNDER_REVIEW if a cross-service flag is active, else ESTABLISHED once
        confidence clears the threshold, else PROVISIONAL)

    highest_risk_level tracks the historical maximum — it only ever increases.
    Returns the new composite_score (S_t).

    CONCURRENCY NOTE: SELECT ... FOR UPDATE then a separate
    INSERT ... ON CONFLICT DO UPDATE within the caller's transaction — the
    row lock serializes concurrent identity updates for the SAME subject_id,
    required because this version carries running state
    (previous_composite_score, N_eff, trend) that would silently corrupt
    under a lost-update race if two events for the same subject were
    processed concurrently (fraud_service.py's async executor, 4 workers).
    """
    cfg = _profile_config()
    service_weights = cfg["weights"]

    fetch_sql = """
        SELECT composite_score, effective_events, COALESCE(last_event_time, updated_at),
               cross_service_flag, cross_service_flag_at
        FROM   user_identity_risk_profile
        WHERE  subject_id = %s
        FOR UPDATE
    """
    with db_connection.cursor() as cur:
        cur.execute(fetch_sql, (subject_id,))
        prior = cur.fetchone()

    if prior:
        prev_composite   = float(prior[0])
        prev_neff        = float(prior[1]) if prior[1] is not None else 0.0
        prev_updated     = prior[2]
        existing_flag    = bool(prior[3])
        existing_flag_at = prior[4]
    else:
        prev_composite, prev_neff, prev_updated = None, 0.0, None
        existing_flag, existing_flag_at = False, None

    # --- Weight renormalization across only the services with data ------------
    active_services = {svc: sc for svc, sc in service_scores.items() if svc in VALID_SERVICES}
    active_weights = {svc: service_weights.get(svc, 0.0) for svc in active_services}
    total_active_weight = sum(active_weights.values())

    if cfg["renormalize_active"] and total_active_weight > 0:
        normalized_weights = {
            svc: round(w / total_active_weight, 4) for svc, w in active_weights.items()
        }
    else:
        normalized_weights = active_weights

    weighted = sum(
        normalized_weights.get(svc, 0.0) * score for svc, score in active_services.items()
    )

    # --- Slow-decaying cross-service escalation -------------------------------
    flag_expired = False
    effective_flag = False
    cross_bonus = 0.0
    if cross_service_flag:
        # fresh detection: full bonus, decay clock restarts at this event
        effective_flag = True
        cross_bonus = cfg["cross_bonus"]
    elif existing_flag:
        flag_at = existing_flag_at or event_time
        decayed = cfg["cross_bonus"] * _decay_factor(
            flag_at, cfg["cross_hl"], reference_time=event_time
        )
        if decayed < cfg["cross_flag_floor"]:
            flag_expired = True          # flag lapses (cleared in the SQL below)
        else:
            effective_flag = True
            cross_bonus = decayed

    r_new = min(100.0, round(weighted + cross_bonus, 2))

    # --- Composite-level smoothing (Formula 5, second layer) -------------------
    composite_alpha = cfg["composite_alpha"]
    if prev_composite is None:
        composite = r_new
    else:
        composite = round(
            composite_alpha * r_new + (1.0 - composite_alpha) * prev_composite, 2
        )
    composite = min(100.0, max(0.0, composite))

    # --- Ranked contributing factors -------------------------------------------
    contributing_factors = []
    for svc, score in active_services.items():
        w = normalized_weights.get(svc, 0.0)
        contributing_factors.append({
            "service":          svc,
            "effective_score":  round(score, 2),
            "weight":           w,
            "contribution":     round(w * score, 2),
        })
    if cross_bonus > 0:
        contributing_factors.append({
            "service":          "CROSS_SERVICE_PATTERN",
            "effective_score":  None,
            "weight":           None,
            "contribution":     round(cross_bonus, 2),
        })
    contributing_factors.sort(key=lambda f: f["contribution"], reverse=True)

    # --- Risk trend (with a small dead-band to suppress jitter) ---------------
    if prev_composite is None:
        risk_trend = "NEW"
    else:
        delta = composite - prev_composite
        if delta > _TREND_DEADBAND:
            risk_trend = "RISING"
        elif delta < -_TREND_DEADBAND:
            risk_trend = "FALLING"
        else:
            risk_trend = "STABLE"

    # --- Effective sample size (decayed event count) → confidence → status ----
    count_alpha = _decay_factor(prev_updated, cfg["default_service_hl"], reference_time=event_time) if prev_updated else 0.0
    new_neff = round(prev_neff * count_alpha + 1.0, 3)
    confidence = round(1.0 - math.exp(-new_neff / cfg["kappa"]), 3)

    if effective_flag:
        profile_status = "UNDER_REVIEW"
    elif confidence >= cfg["established_thr"]:
        profile_status = "ESTABLISHED"
    else:
        profile_status = "PROVISIONAL"

    # --- Composite band (feeds the monotonic highest_risk_level) --------------
    # Deliberately the SMOOTHED composite, not a single event's level: the
    # historical-highest level only reaches CRITICAL when the profile builds up
    # to it. A lone CRITICAL event is handled by the per-event liveness check.
    from scoring.engine import classify_score_band
    current_band = classify_score_band(composite)
    upsert_sql = """
        INSERT INTO user_identity_risk_profile (
            subject_id, composite_score, previous_composite_score, risk_trend,
            auth_score, login_score, consent_score, wallet_score,
            cross_service_flag, cross_service_flag_reason, cross_service_flag_at,
            effective_events, confidence, profile_status,
            contributing_factors,
            total_events, highest_risk_level, last_event_time, updated_at
        )
        VALUES (
            %s, %s, NULL, %s,
            %s, %s, %s, %s,
            %s, %s,
            CASE WHEN %s THEN %s::timestamptz ELSE NULL END,
            %s, %s, %s,
            %s,
            1,
            %s,
            %s,
            NOW()
        )
        ON CONFLICT (subject_id) DO UPDATE SET
            previous_composite_score  = user_identity_risk_profile.composite_score,
            composite_score           = EXCLUDED.composite_score,
            risk_trend                = EXCLUDED.risk_trend,
            auth_score                = EXCLUDED.auth_score,
            login_score              = EXCLUDED.login_score,
            consent_score             = EXCLUDED.consent_score,
            wallet_score              = EXCLUDED.wallet_score,
            cross_service_flag        = CASE
                                            WHEN %s THEN FALSE
                                            ELSE EXCLUDED.cross_service_flag
                                                 OR user_identity_risk_profile.cross_service_flag
            END,
            cross_service_flag_reason = CASE
                                            WHEN %s THEN NULL
                                            WHEN EXCLUDED.cross_service_flag
                                            THEN EXCLUDED.cross_service_flag_reason
                                            ELSE user_identity_risk_profile.cross_service_flag_reason
            END,
            cross_service_flag_at     = CASE
                                            WHEN %s THEN NULL
                                            WHEN EXCLUDED.cross_service_flag
                                            THEN GREATEST(user_identity_risk_profile.cross_service_flag_at,
                                                          EXCLUDED.cross_service_flag_at)
                                            ELSE user_identity_risk_profile.cross_service_flag_at
            END,
            last_event_time = GREATEST(user_identity_risk_profile.last_event_time, EXCLUDED.last_event_time),
            effective_events          = EXCLUDED.effective_events,
            confidence                = EXCLUDED.confidence,
            profile_status            = EXCLUDED.profile_status,
            contributing_factors      = EXCLUDED.contributing_factors,
            total_events              = user_identity_risk_profile.total_events + 1,
            highest_risk_level        = CASE
                WHEN EXCLUDED.highest_risk_level = 'CRITICAL' THEN 'CRITICAL'
                WHEN EXCLUDED.highest_risk_level = 'HIGH'
                     AND user_identity_risk_profile.highest_risk_level <> 'CRITICAL'
                     THEN 'HIGH'
                WHEN EXCLUDED.highest_risk_level = 'MEDIUM'
                     AND user_identity_risk_profile.highest_risk_level NOT IN ('CRITICAL', 'HIGH')
                     THEN 'MEDIUM'
                WHEN EXCLUDED.highest_risk_level = 'LOW'
                     AND user_identity_risk_profile.highest_risk_level = 'NORISK'
                     THEN 'LOW'
                ELSE user_identity_risk_profile.highest_risk_level
            END,
            updated_at                = NOW()
    """
    try:
        auth_s    = service_scores.get("AUTH", 0.0)
        login_s  = service_scores.get("LOGIN", 0.0)
        consent_s = service_scores.get("CONSENT", 0.0)
        wallet_s  = service_scores.get("WALLET", 0.0)

        with db_connection.cursor() as cur:
            cur.execute(upsert_sql, (
                subject_id, composite, risk_trend,
                auth_s, login_s, consent_s, wallet_s,
                cross_service_flag, cross_service_flag_reason,
                cross_service_flag, event_time,   # CASE WHEN %s THEN %s::timestamptz
                new_neff, confidence, profile_status,
                Json(contributing_factors),
                current_band,
                event_time,                        # last_event_time
                flag_expired, flag_expired, flag_expired,
            ))

        return composite
    except Exception as exc:
        logger.exception("%s: upsert_identity_profile failed subject_id=%s",
                         ErrorCode.DATABASE_ERROR, subject_id)
        raise RuntimeError(ErrorCode.DATABASE_ERROR) from exc


def fetch_cross_service_flag(db_connection, subject_id: str) -> bool:
    """
    Return the current cross_service_flag for a subject, or False if no profile exists.
    Lightweight single-column SELECT.
    """
    sql = """
        SELECT cross_service_flag
        FROM   user_identity_risk_profile
        WHERE  subject_id = %s
    """
    try:
        with db_connection.cursor() as cur:
            cur.execute(sql, (subject_id,))
            row = cur.fetchone()
        return bool(row[0]) if row else False
    except Exception as exc:
        logger.warning("[PROFILE] fetch_cross_service_flag failed subject_id=%s: %s",
                       subject_id, exc)
        return False


def fetch_service_profiles(db_connection, subject_id: str) -> list[dict]:
    """
    Return all per-service profile rows for a given subject_id.

    effective_score is reconstructed from PERSISTED last_blended_score +
    escalation_score when available (exact match to what fed the composite
    at the last write). Rows written before last_blended_score existed will
    have it as NULL — for those, effective_score falls back to
    rolling_score + escalation_score, the prior approximation.
    """
    sql = """
        SELECT service, rolling_score, event_count,
               last_event_id, last_event_time,
               last_risk_level, updated_at,
               escalation_score, last_blended_score
        FROM   user_service_risk_profile
        WHERE  subject_id = %s
        ORDER BY service
    """
    try:
        with db_connection.cursor() as cur:
            cur.execute(sql, (subject_id,))
            rows = cur.fetchall()

        result = []
        for r in rows:
            rolling_score = float(r[1])
            escalation_score = float(r[7]) if r[7] is not None else 0.0
            blended_score = float(r[8]) if r[8] is not None else rolling_score
            result.append({
                "service":           r[0],
                "rolling_score":     rolling_score,
                "event_count":       r[2],
                "last_event_id":     str(r[3]) if r[3] else None,
                "last_event_time":   r[4].isoformat() if r[4] else None,
                "last_risk_level":   r[5],
                "updated_at":        r[6].isoformat() if r[6] else None,
                "escalation_score":  escalation_score,
                "effective_score":   min(100.0, round(blended_score + escalation_score, 2)),
            })
        return result
    except Exception as exc:
        logger.exception("%s: fetch_service_profiles failed subject_id=%s",
                         ErrorCode.DATABASE_ERROR, subject_id)
        raise RuntimeError(ErrorCode.DATABASE_ERROR) from exc


def fetch_highest_risk_level(db_connection, subject_id: str) -> str:
    """
    Return the user's historical highest risk level.
    Returns NORISK if no profile exists.
    """
    sql = """
        SELECT highest_risk_level
        FROM user_identity_risk_profile
        WHERE subject_id = %s
    """
    try:
        with db_connection.cursor() as cur:
            cur.execute(sql, (subject_id,))
            row = cur.fetchone()
        return row[0] if row and row[0] else "NORISK"
    except Exception as exc:
        logger.warning(
            "[PROFILE] fetch_highest_risk_level failed subject_id=%s: %s",
            subject_id, exc,
        )
        return "NORISK"


def fetch_identity_profile(db_connection, subject_id: str) -> Optional[dict]:
    """Return the composite identity profile row, or None if not yet built."""
    sql = """
        SELECT composite_score, auth_score, login_score, consent_score, wallet_score,
               cross_service_flag, cross_service_flag_reason, cross_service_flag_at,
               total_events, highest_risk_level, updated_at,
               previous_composite_score, risk_trend,
               effective_events, confidence, profile_status,
               contributing_factors
        FROM   user_identity_risk_profile
        WHERE  subject_id = %s
    """
    try:
        with db_connection.cursor() as cur:
            cur.execute(sql, (subject_id,))
            row = cur.fetchone()

        if not row:
            return None
        
        from scoring.engine import classify_score_band
        composite = float(row[0])
        overall_level = classify_score_band(composite)

        return {
            "composite_score":            composite,
            "overall_risk_level":         overall_level,
            "service_scores": {
                "AUTH":    float(row[1]),
                "LOGIN":   float(row[2]),
                "CONSENT": float(row[3]),
                "WALLET":  float(row[4]),
            },
            "cross_service_flag":          row[5],
            "cross_service_flag_reason":   row[6],
            "cross_service_flag_at":       row[7].isoformat() if row[7] else None,
            "total_events":                row[8],
            "highest_risk_level":          row[9],
            "updated_at":                  row[10].isoformat() if row[10] else None,
            "previous_composite_score":    float(row[11]) if row[11] is not None else None,
            "risk_trend":                  row[12],
            "effective_events":            float(row[13]) if row[13] is not None else 0.0,
            "confidence":                  float(row[14]) if row[14] is not None else 0.0,
            "profile_status":              row[15],
            "contributing_factors":        row[16] if row[16] is not None else [],
        }
    except Exception as exc:
        logger.exception("%s: fetch_identity_profile failed subject_id=%s",
                         ErrorCode.DATABASE_ERROR, subject_id)
        raise RuntimeError(ErrorCode.DATABASE_ERROR) from exc


def fetch_service_subject_profiles(
    db_connection, service: str, page: int = 1, limit: int = 50
) -> dict:
    """
    Return every subject_id's risk profile row for a given service.

    Used for the service-wide roster view (all users under AUTH/LOGIN/
    CONSENT/WALLET), as opposed to fetch_service_profiles which is
    per-subject across all services.
    """
    offset = (page - 1) * limit

    count_sql = """
        SELECT COUNT(*) FROM user_service_risk_profile WHERE service = %s
    """
    avg_sql = """
        SELECT AVG(rolling_score) FROM user_service_risk_profile WHERE service = %s
    """
    risk_breakdown_sql = """
        SELECT COALESCE(last_risk_level, 'UNKNOWN'), COUNT(*)
        FROM user_service_risk_profile
        WHERE service = %s
        GROUP BY 1
    """
    data_sql = """
        SELECT subject_id, rolling_score, event_count,
               last_event_id, last_event_time,
               last_risk_level, updated_at,
               escalation_score, last_blended_score
        FROM user_service_risk_profile
        WHERE service = %s
        ORDER BY LEAST(100, COALESCE(last_blended_score, rolling_score) + escalation_score) DESC,
                subject_id ASC
        LIMIT %s OFFSET %s
    """

    try:
        with db_connection.cursor() as cur:
            cur.execute(count_sql, (service,))
            total = cur.fetchone()[0]

            cur.execute(avg_sql, (service,))
            avg_rolling = cur.fetchone()[0]

            cur.execute(risk_breakdown_sql, (service,))
            risk_level_breakdown = {r[0]: r[1] for r in cur.fetchall()}

            cur.execute(data_sql, (service, limit, offset))
            rows = cur.fetchall()

        data = []
        for r in rows:
            rolling_score = float(r[1])
            escalation_score = float(r[7]) if r[7] is not None else 0.0
            blended_score = float(r[8]) if r[8] is not None else rolling_score
            data.append({
                "subject_id":        r[0],
                "rolling_score":     rolling_score,
                "event_count":       r[2],
                "last_event_id":     str(r[3]) if r[3] else None,
                "last_event_time":   r[4].isoformat() if r[4] else None,
                "last_risk_level":   r[5],
                "updated_at":        r[6].isoformat() if r[6] else None,
                "escalation_score":  escalation_score,
                "effective_score":   min(100.0, round(blended_score + escalation_score, 2)),
            })

        return {
            "service": service,
            "summary": {
                "total_subjects":       int(total or 0),
                "avg_rolling_score":    round(float(avg_rolling or 0), 2),
                "risk_level_breakdown": risk_level_breakdown,
            },
            "data":        data,
            "page":        page,
            "limit":       limit,
            "total":       int(total or 0),
            "total_pages": (int(total or 0) + limit - 1) // limit,
        }

    except Exception as exc:
        logger.exception("%s: fetch_service_subject_profiles failed service=%s",
                         ErrorCode.DATABASE_ERROR, service)
        raise RuntimeError(ErrorCode.DATABASE_ERROR) from exc