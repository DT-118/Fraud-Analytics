-- =============================================================================
-- Phase 3 Migration: Dynamic Risk Profiles
-- =============================================================================
-- Applies on top of phase1_migration.sql.
-- Run as the DB owner or a role with CREATE TABLE / CREATE INDEX privileges.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Per-service rolling risk profile
-- One row per (subject_id, service). Upserted on every scored event.
-- rolling_score is time-decayed via the EWMA formula in profile_repo.py.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_service_risk_profile (
    id                  SERIAL PRIMARY KEY,
    subject_id          VARCHAR(128)    NOT NULL,
    service             VARCHAR(20)     NOT NULL,   -- AUTH|ENROLL|CONSENT|WALLET
    rolling_score       NUMERIC(5,2)    NOT NULL DEFAULT 0,
    event_count         INTEGER         NOT NULL DEFAULT 0,
    last_event_id       UUID,
    last_event_time     TIMESTAMPTZ,
    last_risk_level     VARCHAR(20),
    last_action_taken   VARCHAR(20),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_service_profile UNIQUE (subject_id, service),
    CONSTRAINT chk_service CHECK (service IN ('AUTH','ENROLL','CONSENT','WALLET')),
    CONSTRAINT chk_rolling_score CHECK (rolling_score BETWEEN 0 AND 100)
);

CREATE INDEX IF NOT EXISTS idx_srp_subject
    ON user_service_risk_profile (subject_id);

CREATE INDEX IF NOT EXISTS idx_srp_updated
    ON user_service_risk_profile (updated_at DESC);

-- ---------------------------------------------------------------------------
-- Composite identity risk profile
-- One row per subject_id. Aggregates all four service scores with
-- service weights: AUTH 40%, ENROLL 25%, WALLET 25%, CONSENT 10%.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_identity_risk_profile (
    id                      SERIAL PRIMARY KEY,
    subject_id              VARCHAR(128)    NOT NULL UNIQUE,
    composite_score         NUMERIC(5,2)    NOT NULL DEFAULT 0,
    auth_score              NUMERIC(5,2)    NOT NULL DEFAULT 0,
    enroll_score            NUMERIC(5,2)    NOT NULL DEFAULT 0,
    consent_score           NUMERIC(5,2)    NOT NULL DEFAULT 0,
    wallet_score            NUMERIC(5,2)    NOT NULL DEFAULT 0,
    cross_service_flag      BOOLEAN         NOT NULL DEFAULT FALSE,
    cross_service_flag_reason VARCHAR(255),
    cross_service_flag_at   TIMESTAMPTZ,
    total_events            INTEGER         NOT NULL DEFAULT 0,
    highest_risk_level      VARCHAR(20),
    updated_at              TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_composite CHECK (composite_score BETWEEN 0 AND 100)
);

CREATE INDEX IF NOT EXISTS idx_irp_composite
    ON user_identity_risk_profile (composite_score DESC);

CREATE INDEX IF NOT EXISTS idx_irp_cross_flag
    ON user_identity_risk_profile (cross_service_flag)
    WHERE cross_service_flag = TRUE;

-- ---------------------------------------------------------------------------
-- Verification
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    ASSERT (SELECT COUNT(*) FROM information_schema.tables
            WHERE table_name = 'user_service_risk_profile') = 1,
        'user_service_risk_profile table missing';

    ASSERT (SELECT COUNT(*) FROM information_schema.tables
            WHERE table_name = 'user_identity_risk_profile') = 1,
        'user_identity_risk_profile table missing';

    RAISE NOTICE 'Phase 3 migration verified OK';
END $$;
