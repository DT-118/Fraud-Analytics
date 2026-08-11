-- =============================================================================
-- FRAUD MANAGEMENT — FULL SCHEMA (built from scratch)
-- =============================================================================
-- Consolidates everything the current codebase actually needs into one file.
-- No "phase" migrations, no action-resolution columns required as NOT NULL,
-- no biometric-penalty columns (never existed in DB — was in-memory only).
--
-- Safe to run top-to-bottom against a brand new, empty database.
-- =============================================================================

BEGIN;

-- gen_random_uuid() needs pgcrypto on some PG builds; harmless if already core.
CREATE EXTENSION IF NOT EXISTS pgcrypto;


-- =============================================================================
-- users  — frontend login only, unCHrelated to the fraud engine itself
-- =============================================================================
CREATE TABLE IF NOT EXISTS users (
    id          UUID                        NOT NULL DEFAULT gen_random_uuid(),
    name        VARCHAR(100)                NOT NULL,
    mobile      VARCHAR(15)                 NOT NULL,
    username    VARCHAR(50)                 NOT NULL,
    password    VARCHAR(255)                NOT NULL,
    role        VARCHAR(20)                 NOT NULL DEFAULT 'SERVICE_PROVIDER',
    is_active   BOOLEAN                     NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ                 NOT NULL DEFAULT NOW(),

    CONSTRAINT users_pkey PRIMARY KEY (id),
    CONSTRAINT users_mobile_key UNIQUE (mobile),
    CONSTRAINT users_username_key UNIQUE (username),
    CONSTRAINT users_role_check CHECK (role IN ('ADMIN', 'SERVICE_PROVIDER'))
);

CREATE INDEX IF NOT EXISTS idx_users_mobile   ON users (mobile);
CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);


-- =============================================================================
-- fraud_events  — raw incoming event log (append-only)
-- =============================================================================
-- NOTE: actor_type, actor_id, emirates_id_hash are REQUIRED by
-- storage/event_repo.py's INSERT but were missing from the DB you showed me
-- earlier — added here so inserts don't fail with "column does not exist".
-- =============================================================================
CREATE TABLE IF NOT EXISTS fraud_events (
    id                  UUID                        NOT NULL DEFAULT gen_random_uuid(),
    schema_version      TEXT                        NOT NULL DEFAULT '2.0',
    event_type          TEXT                        NOT NULL,
    action              TEXT                        NOT NULL,   -- action_taxonomy: login|enroll|consent|wallet
    event_id            UUID                        NOT NULL,
    correlation_id      TEXT                        NOT NULL,
    transaction_id      TEXT,
    session_id          TEXT,
    request_id          TEXT,
    subject_id          TEXT                        NOT NULL,
    emirates_id_hash    TEXT,
    role                TEXT,
    exception_code      TEXT,
    actor_type          TEXT,
    actor_id            TEXT,
    event_time          TIMESTAMPTZ                 NOT NULL,
    environment         TEXT                        NOT NULL,
    service_name        TEXT                        NOT NULL,
    security_payload    JSONB,
    biometric_payload   JSONB,
    document_payload    JSONB,
    consent_payload     JSONB,
    wallet_payload      JSONB,
    source              TEXT                        NOT NULL,
    created_at          TIMESTAMPTZ                 NOT NULL DEFAULT NOW(),

    CONSTRAINT fraud_events_pkey PRIMARY KEY (id),
    CONSTRAINT idx_fraud_events_event_id UNIQUE (event_id),   -- required by ON CONFLICT (event_id)
    CONSTRAINT fraud_events_schema_version_check CHECK (schema_version = '2.0')
);

CREATE INDEX IF NOT EXISTS idx_fraud_events_created_at     ON fraud_events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_fraud_events_event_time     ON fraud_events (event_time DESC);
CREATE INDEX IF NOT EXISTS idx_fraud_events_event_type     ON fraud_events (event_type);
CREATE INDEX IF NOT EXISTS idx_fraud_events_source         ON fraud_events (source);
CREATE INDEX IF NOT EXISTS idx_fraud_events_subject_id     ON fraud_events (subject_id);
CREATE INDEX IF NOT EXISTS idx_fraud_events_role           ON fraud_events (role) WHERE role IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_fraud_events_emirates_hash  ON fraud_events (emirates_id_hash) WHERE emirates_id_hash IS NOT NULL;


-- =============================================================================
-- fraud_decisions  — scored outcome per event (append-only, immutable record)
-- =============================================================================
-- policy_action is NULLABLE — the engine no longer resolves/suggests an
-- enforcement action, so this column will always be written as NULL.
-- emirates_id_hash added — required by storage/decision_repo.py's INSERT.
-- =============================================================================
CREATE TABLE IF NOT EXISTS fraud_decisions (
    id                  UUID                        NOT NULL DEFAULT gen_random_uuid(),
    event_id            UUID                        NOT NULL,
    fraud_type          TEXT                        NOT NULL,
    subject_id          TEXT                        NOT NULL,
    emirates_id_hash    TEXT,
    role                TEXT,
    exception_code      TEXT,
    score               INTEGER                     NOT NULL,
    risk_level          TEXT                        NOT NULL,
    policy_action       TEXT,                                    -- nullable: action resolution disabled
    triggered_rules     TEXT[]                      NOT NULL,
    rule_weights        JSONB                       NOT NULL DEFAULT '{}',
    features            JSONB                       NOT NULL,
    source              TEXT                        NOT NULL,
    config_version      TEXT                        NOT NULL,
    created_at          TIMESTAMPTZ                 NOT NULL DEFAULT NOW(),

    CONSTRAINT fraud_decisions_pkey PRIMARY KEY (id),
    CONSTRAINT fraud_decisions_event_id_key UNIQUE (event_id),  -- required by ON CONFLICT (event_id)
    CONSTRAINT fraud_decisions_score_check CHECK (score >= 0 AND score <= 100)
);

CREATE INDEX IF NOT EXISTS idx_fraud_decisions_action          ON fraud_decisions (policy_action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_fraud_decisions_created_at      ON fraud_decisions (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_fraud_decisions_fraud_type      ON fraud_decisions (fraud_type);
CREATE INDEX IF NOT EXISTS idx_fraud_decisions_risk_level      ON fraud_decisions (risk_level);
CREATE INDEX IF NOT EXISTS idx_fraud_decisions_source          ON fraud_decisions (source);
CREATE INDEX IF NOT EXISTS idx_fraud_decisions_subject_id      ON fraud_decisions (subject_id);
CREATE INDEX IF NOT EXISTS idx_fraud_decisions_emirates_hash   ON fraud_decisions (emirates_id_hash) WHERE emirates_id_hash IS NOT NULL;


-- =============================================================================
-- user_service_risk_profile — per-service rolling risk score (Phase 3 logic)
-- =============================================================================
-- last_action_taken is already nullable by design — always written as NULL now.
-- =============================================================================
CREATE TABLE IF NOT EXISTS user_service_risk_profile (
    id                  SERIAL                      PRIMARY KEY,
    subject_id          VARCHAR(128)                NOT NULL,
    service             VARCHAR(20)                 NOT NULL,   -- AUTH|ENROLL|CONSENT|WALLET
    rolling_score       NUMERIC(5,2)                NOT NULL DEFAULT 0,
    event_count         INTEGER                     NOT NULL DEFAULT 0,
    last_event_id       UUID,
    last_event_time     TIMESTAMPTZ,
    last_risk_level     VARCHAR(20),
    last_action_taken   VARCHAR(20),                             -- nullable: always NULL now
    updated_at          TIMESTAMPTZ                 NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_service_profile UNIQUE (subject_id, service),
    CONSTRAINT chk_service CHECK (service IN ('AUTH','ENROLL','CONSENT','WALLET')),
    CONSTRAINT chk_rolling_score CHECK (rolling_score BETWEEN 0 AND 100)
);

CREATE INDEX IF NOT EXISTS idx_srp_subject ON user_service_risk_profile (subject_id);
CREATE INDEX IF NOT EXISTS idx_srp_updated ON user_service_risk_profile (updated_at DESC);


-- =============================================================================
-- user_identity_risk_profile — composite identity score across all services
-- =============================================================================
CREATE TABLE IF NOT EXISTS user_identity_risk_profile (
    id                          SERIAL              PRIMARY KEY,
    subject_id                  VARCHAR(128)        NOT NULL UNIQUE,
    composite_score             NUMERIC(5,2)        NOT NULL DEFAULT 0,
    auth_score                  NUMERIC(5,2)        NOT NULL DEFAULT 0,
    enroll_score                NUMERIC(5,2)        NOT NULL DEFAULT 0,
    consent_score                NUMERIC(5,2)        NOT NULL DEFAULT 0,
    wallet_score                NUMERIC(5,2)        NOT NULL DEFAULT 0,
    cross_service_flag          BOOLEAN             NOT NULL DEFAULT FALSE,
    cross_service_flag_reason   VARCHAR(255),
    cross_service_flag_at       TIMESTAMPTZ,
    total_events                INTEGER             NOT NULL DEFAULT 0,
    highest_risk_level          VARCHAR(20),
    updated_at                  TIMESTAMPTZ         NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_composite CHECK (composite_score BETWEEN 0 AND 100)
);

CREATE INDEX IF NOT EXISTS idx_irp_composite   ON user_identity_risk_profile (composite_score DESC);
CREATE INDEX IF NOT EXISTS idx_irp_cross_flag  ON user_identity_risk_profile (cross_service_flag) WHERE cross_service_flag = TRUE;


-- =============================================================================
-- fraud_sessions — durable audit copy of Redis session state
-- =============================================================================
CREATE TABLE IF NOT EXISTS fraud_sessions (
    id                  SERIAL                      PRIMARY KEY,
    session_id          VARCHAR(128)                NOT NULL UNIQUE,
    subject_id          VARCHAR(128)                NOT NULL,
    event_count         INTEGER                     NOT NULL DEFAULT 0,
    high_event_count    INTEGER                     NOT NULL DEFAULT 0,
    has_critical        BOOLEAN                     NOT NULL DEFAULT FALSE,
    max_score           INTEGER                     NOT NULL DEFAULT 0,
    session_risk_level  VARCHAR(20),
    first_event_at      TIMESTAMPTZ,
    last_event_at       TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ                 NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fs_subject ON fraud_sessions (subject_id);
CREATE INDEX IF NOT EXISTS idx_fs_updated ON fraud_sessions (updated_at DESC);


-- =============================================================================
-- device_trust — reserved for future use; no code currently reads/writes this
-- (device_features.py tracks device trust in Redis only, not this table)
-- =============================================================================
CREATE TABLE IF NOT EXISTS device_trust (
    id              SERIAL                          PRIMARY KEY,
    device_id       VARCHAR(256)                    NOT NULL UNIQUE,
    subject_count   INTEGER                         NOT NULL DEFAULT 1,
    is_flagged      BOOLEAN                         NOT NULL DEFAULT FALSE,
    flag_reason     VARCHAR(100),
    first_seen_at   TIMESTAMPTZ                     NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ                     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ                     NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dt_flagged ON device_trust (is_flagged) WHERE is_flagged = TRUE;


-- =============================================================================
-- ip_reputation — manually managed blocklist, mirrored into Redis at startup
-- =============================================================================
CREATE TABLE IF NOT EXISTS ip_reputation (
    id          SERIAL                              PRIMARY KEY,
    src_ip      VARCHAR(45)                          NOT NULL UNIQUE,  -- IPv4 + IPv6
    flag_reason VARCHAR(100)                         NOT NULL,
    flagged_at  TIMESTAMPTZ                          NOT NULL DEFAULT NOW(),
    flagged_by  VARCHAR(128),
    is_active   BOOLEAN                              NOT NULL DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_ir_active ON ip_reputation (src_ip) WHERE is_active = TRUE;


-- =============================================================================
-- user_feature_baseline — Welford's online mean/variance per user/feature
-- =============================================================================
CREATE TABLE IF NOT EXISTS user_feature_baseline (
    id              SERIAL                          PRIMARY KEY,
    subject_id      VARCHAR(128)                    NOT NULL,
    service         VARCHAR(20)                     NOT NULL,  -- AUTH|ENROLL|WALLET|CONSENT
    feature_name    VARCHAR(100)                    NOT NULL,
    mean            DOUBLE PRECISION                NOT NULL DEFAULT 0.0,
    m2              DOUBLE PRECISION                NOT NULL DEFAULT 0.0,
    sample_count    INTEGER                         NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ                     NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_ufb UNIQUE (subject_id, service, feature_name)
);

CREATE INDEX IF NOT EXISTS idx_ufb_subject_service ON user_feature_baseline (subject_id, service);


-- =============================================================================
-- service_deviation_config — per-service z-score tolerance for baselines
-- =============================================================================
CREATE TABLE IF NOT EXISTS service_deviation_config (
    id              SERIAL                          PRIMARY KEY,
    service         VARCHAR(20)                     NOT NULL,
    feature_name    VARCHAR(100)                    NOT NULL DEFAULT '*',
    tolerance_sigma DOUBLE PRECISION                NOT NULL DEFAULT 2.5,
    enabled         BOOLEAN                         NOT NULL DEFAULT TRUE,
    updated_at      TIMESTAMPTZ                     NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_sdc UNIQUE (service, feature_name)
);

INSERT INTO service_deviation_config (service, feature_name, tolerance_sigma) VALUES
    ('AUTH',    '*', 2.5),
    ('ENROLL',  '*', 2.0),
    ('WALLET',  '*', 2.0),
    ('CONSENT', '*', 2.5)
ON CONFLICT (service, feature_name) DO NOTHING;


-- =============================================================================
-- Verification
-- =============================================================================
DO $$
BEGIN
    ASSERT (SELECT COUNT(*) FROM information_schema.tables
            WHERE table_name = 'users') = 1, 'users table missing';
    ASSERT (SELECT COUNT(*) FROM information_schema.tables
            WHERE table_name = 'fraud_events') = 1, 'fraud_events table missing';
    ASSERT (SELECT COUNT(*) FROM information_schema.tables
            WHERE table_name = 'fraud_decisions') = 1, 'fraud_decisions table missing';
    ASSERT (SELECT COUNT(*) FROM information_schema.tables
            WHERE table_name = 'user_service_risk_profile') = 1, 'user_service_risk_profile table missing';
    ASSERT (SELECT COUNT(*) FROM information_schema.tables
            WHERE table_name = 'user_identity_risk_profile') = 1, 'user_identity_risk_profile table missing';
    ASSERT (SELECT COUNT(*) FROM information_schema.tables
            WHERE table_name = 'fraud_sessions') = 1, 'fraud_sessions table missing';
    ASSERT (SELECT COUNT(*) FROM information_schema.tables
            WHERE table_name = 'device_trust') = 1, 'device_trust table missing';
    ASSERT (SELECT COUNT(*) FROM information_schema.tables
            WHERE table_name = 'ip_reputation') = 1, 'ip_reputation table missing';
    ASSERT (SELECT COUNT(*) FROM information_schema.tables
            WHERE table_name = 'user_feature_baseline') = 1, 'user_feature_baseline table missing';
    ASSERT (SELECT COUNT(*) FROM information_schema.tables
            WHERE table_name = 'service_deviation_config') = 1, 'service_deviation_config table missing';

    ASSERT (
        SELECT is_nullable FROM information_schema.columns
        WHERE table_name = 'fraud_decisions' AND column_name = 'policy_action'
    ) = 'YES', 'policy_action must be nullable (action resolution disabled)';

    RAISE NOTICE 'Full schema created and verified OK — 10 tables, no action-engine constraints.';
END $$;

COMMIT;