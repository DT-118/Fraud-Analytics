-- =============================================================================
-- Phase 5 Migration: Personal Baseline & Behavioral Deviation
-- =============================================================================
-- Applies on top of phase4_migration.sql.
--
-- Implements the personal baseline system from the diagram:
--   Stage 1 — per-service deviation tolerance config (one-time registration)
--   Stage 3 — per-user per-feature rolling mean/variance (Welford's algorithm)
-- =============================================================================


-- ---------------------------------------------------------------------------
-- user_feature_baseline
-- One row per (subject_id, service, feature_name).
-- Stores running mean and M2 (variance accumulator) for Welford's algorithm.
-- Updated asynchronously after each scored event via background thread.
--
-- Welford's online variance:
--   delta  = x - old_mean
--   n_new  = n + 1
--   mean   = old_mean + delta / n_new
--   delta2 = x - new_mean
--   M2     = old_M2 + delta * delta2
--   std_dev = sqrt(M2 / (n-1))  for n >= 2
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_feature_baseline (
    id              SERIAL PRIMARY KEY,
    subject_id      VARCHAR(128)        NOT NULL,
    service         VARCHAR(20)         NOT NULL,  -- AUTH | ENROLL | WALLET | CONSENT
    feature_name    VARCHAR(100)        NOT NULL,
    mean            DOUBLE PRECISION    NOT NULL DEFAULT 0.0,
    m2              DOUBLE PRECISION    NOT NULL DEFAULT 0.0,
    sample_count    INTEGER             NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ         NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_ufb UNIQUE (subject_id, service, feature_name)
);

CREATE INDEX IF NOT EXISTS idx_ufb_subject_service
    ON user_feature_baseline (subject_id, service);


-- ---------------------------------------------------------------------------
-- service_deviation_config
-- Stores per-service (and optionally per-feature) z-score tolerance.
-- Services call POST /v2/service/config to register; seeded with safe defaults.
--
-- tolerance_sigma: z-score threshold above which deviation is notable.
--   Default 2.5 → ~1.2% of normal events (below 0.001% FP budget when
--   combined with at least one other triggered rule).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS service_deviation_config (
    id              SERIAL PRIMARY KEY,
    service         VARCHAR(20)         NOT NULL,
    feature_name    VARCHAR(100)        NOT NULL DEFAULT '*',  -- '*' = all features
    tolerance_sigma DOUBLE PRECISION    NOT NULL DEFAULT 2.5,
    enabled         BOOLEAN             NOT NULL DEFAULT TRUE,
    updated_at      TIMESTAMPTZ         NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_sdc UNIQUE (service, feature_name)
);

-- Safe defaults — one row per service using '*' as the catch-all feature
INSERT INTO service_deviation_config (service, feature_name, tolerance_sigma) VALUES
    ('AUTH',    '*', 2.5),
    ('ENROLL',  '*', 2.0),
    ('WALLET',  '*', 2.0),
    ('CONSENT', '*', 2.5)
ON CONFLICT (service, feature_name) DO NOTHING;


-- ---------------------------------------------------------------------------
-- Verification
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    ASSERT (SELECT COUNT(*) FROM information_schema.tables
            WHERE table_name = 'user_feature_baseline') = 1,
        'user_feature_baseline table missing';
    ASSERT (SELECT COUNT(*) FROM information_schema.tables
            WHERE table_name = 'service_deviation_config') = 1,
        'service_deviation_config table missing';
    RAISE NOTICE 'Phase 5 migration verified OK';
END $$;
