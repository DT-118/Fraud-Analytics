-- =============================================================================
-- Phase 10 Migration: Ranked Contributing Factors on Composite Identity Profile
-- =============================================================================
-- Applies on top of phase7_migration.sql + phase8_migration.sql.
--
-- Adds one column to user_identity_risk_profile: contributing_factors.
-- Populated by storage/profile_repo.py's upsert_identity_profile() on every
-- write. Stores a ranked breakdown of which service (AUTH/ENROLL/CONSENT/
-- WALLET) contributed how much to the composite_score, plus the
-- cross-service escalation bonus if active. Shape:
--
--   [
--     {"service": "AUTH", "effective_score": 26.62, "weight": 1.0, "contribution": 26.62},
--     {"service": "WALLET", "effective_score": 0.0, "weight": 0.0, "contribution": 0.0},
--     ...
--     {"service": "CROSS_SERVICE_PATTERN", "effective_score": null, "weight": null, "contribution": 4.2}
--   ]
--
-- Sorted descending by "contribution" — index 0 is always the single
-- largest driver of the current composite score.
--
-- No burst-tier columns are added here — the fast/burst rolling average
-- (Formula 1+2 literal implementation) lives entirely in Redis
-- (burst:scores:{subject_id}:{service}), scoped to a short rolling window,
-- and is intentionally NOT persisted to Postgres: it is meant to fade once
-- the burst window passes, same as its Redis TTL already enforces.
--
-- Safe to run multiple times: ADD COLUMN is guarded with IF NOT EXISTS.
-- =============================================================================

BEGIN;

ALTER TABLE user_identity_risk_profile
    ADD COLUMN IF NOT EXISTS contributing_factors JSONB;

-- ---------------------------------------------------------------------------
-- Verify
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    ASSERT (
        SELECT COUNT(*) FROM information_schema.columns
        WHERE table_name = 'user_identity_risk_profile'
          AND column_name = 'contributing_factors'
    ) = 1, 'Phase 10 column missing';

    RAISE NOTICE 'Phase 10 migration applied OK — contributing_factors column added.';
END $$;

COMMIT;