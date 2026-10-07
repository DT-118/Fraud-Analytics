-- BEGIN;

-- -- gen_random_uuid() needs pgcrypto on some PG builds; harmless if already core.
-- CREATE EXTENSION IF NOT EXISTS pgcrypto;


-- -- =============================================================================
-- -- users  — frontend login only, unrelated to the fraud engine itself
-- -- =============================================================================
-- CREATE TABLE IF NOT EXISTS users (
--     id          UUID                        NOT NULL DEFAULT gen_random_uuid(),
--     name        VARCHAR(100)                NOT NULL,
--     mobile      VARCHAR(15)                 NOT NULL,
--     username    VARCHAR(50)                 NOT NULL,
--     password    VARCHAR(255)                NOT NULL,
--     role        VARCHAR(20)                 NOT NULL DEFAULT 'SERVICE_PROVIDER',
--     is_active   BOOLEAN                     NOT NULL DEFAULT TRUE,
--     created_at  TIMESTAMPTZ                 NOT NULL DEFAULT NOW(),

--     CONSTRAINT users_pkey PRIMARY KEY (id),
--     CONSTRAINT users_mobile_key UNIQUE (mobile),
--     CONSTRAINT users_username_key UNIQUE (username),
--     CONSTRAINT users_role_check CHECK (role IN ('ADMIN', 'SERVICE_PROVIDER'))
-- );

-- CREATE INDEX IF NOT EXISTS idx_users_mobile   ON users (mobile);
-- CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);


-- -- =============================================================================
-- -- fraud_events  — raw incoming event log (append-only)
-- -- =============================================================================
-- CREATE TABLE IF NOT EXISTS fraud_events (
--     id                  UUID                        NOT NULL DEFAULT gen_random_uuid(),
--     schema_version      TEXT                        NOT NULL DEFAULT '2.0',
--     event_type          TEXT                        NOT NULL,
--     action              TEXT                        NOT NULL,   -- action_taxonomy: auth|login|consent|wallet
--     event_id            UUID                        NOT NULL,
--     correlation_id      TEXT                        NOT NULL,
--     transaction_id      TEXT,
--     session_id          TEXT,
--     request_id          TEXT,
--     subject_id          TEXT                        NOT NULL,
--     emirates_id_hash    TEXT,
--     role                TEXT,
--     exception_code      TEXT,
--     actor_type          TEXT,
--     actor_id            TEXT,
--     event_time          TIMESTAMPTZ                 NOT NULL,
--     environment         TEXT                        NOT NULL,
--     service_name        TEXT                        NOT NULL,
--     security_payload    JSONB,
--     biometric_payload   JSONB,
--     document_payload    JSONB,
--     consent_payload     JSONB,
--     wallet_payload      JSONB,
--     source              TEXT                        NOT NULL,
--     created_at          TIMESTAMPTZ                 NOT NULL DEFAULT NOW(),

--     CONSTRAINT fraud_events_pkey PRIMARY KEY (id),
--     CONSTRAINT idx_fraud_events_event_id UNIQUE (event_id),   -- required by ON CONFLICT (event_id)
--     CONSTRAINT fraud_events_schema_version_check CHECK (schema_version = '2.0')
-- );

-- CREATE INDEX IF NOT EXISTS idx_fraud_events_created_at     ON fraud_events (created_at DESC);
-- CREATE INDEX IF NOT EXISTS idx_fraud_events_event_time     ON fraud_events (event_time DESC);
-- CREATE INDEX IF NOT EXISTS idx_fraud_events_event_type     ON fraud_events (event_type);
-- CREATE INDEX IF NOT EXISTS idx_fraud_events_source         ON fraud_events (source);
-- CREATE INDEX IF NOT EXISTS idx_fraud_events_subject_id     ON fraud_events (subject_id);
-- CREATE INDEX IF NOT EXISTS idx_fraud_events_role           ON fraud_events (role) WHERE role IS NOT NULL;
-- CREATE INDEX IF NOT EXISTS idx_fraud_events_emirates_hash  ON fraud_events (emirates_id_hash) WHERE emirates_id_hash IS NOT NULL;


-- -- =============================================================================
-- -- fraud_decisions  — scored outcome per event (append-only, immutable record)
-- -- =============================================================================
-- -- policy_action is NULLABLE — the engine no longer resolves/suggests an
-- -- enforcement action, so this column will always be written as NULL.
-- --
-- -- exception_score and session_amplifier are the two intermediate scoring
-- -- values that were being computed on every event but never persisted —
-- -- only the final capped score made it to disk. Without them, a decision
-- -- log entry could show e.g. score=100 with no way to reconstruct whether
-- -- that came from rule weights alone, an exception-code bump, a session
-- -- amplifier, or some combination — the drill-down API needs the full
-- -- breakdown, not just the end result. Both are nullable because rows
-- -- written before this column existed will not have a value.
-- --   exception_score   — flat points added for the event's exception_code
-- --                       (scoring/engine.py _get_exception_scoring()),
-- --                       applied BEFORE the 0-100 cap.
-- --   session_amplifier — multiplier applied AFTER the cap, based on the
-- --                       session's accumulated risk state
-- --                       (scoring/engine.py apply_session_amplifier()).
-- -- =============================================================================
-- CREATE TABLE IF NOT EXISTS fraud_decisions (
--     id                          UUID                NOT NULL DEFAULT gen_random_uuid(),
--     event_id                    UUID                NOT NULL,
--     fraud_type                  TEXT                NOT NULL,
--     subject_id                  TEXT                NOT NULL,
--     emirates_id_hash            TEXT,
--     role                        TEXT,
--     exception_code              TEXT,
--     score                       INTEGER             NOT NULL,
--     risk_level                  TEXT                NOT NULL,
--     policy_action                TEXT,                                   -- nullable: action resolution disabled
--     triggered_rules              TEXT[]              NOT NULL,
--     rule_weights                  JSONB               NOT NULL DEFAULT '{}',
--     features                    JSONB               NOT NULL,
--     active_liveness_suggestion  JSONB,
--     exception_score              NUMERIC(5,2),                           -- nullable: not recorded before this column existed
--     session_amplifier            NUMERIC(4,3),                           -- nullable: not recorded before this column existed
--     source                      TEXT                NOT NULL,
--     config_version               TEXT                NOT NULL,
--     created_at                   TIMESTAMPTZ         NOT NULL DEFAULT NOW(),

--     CONSTRAINT fraud_decisions_pkey PRIMARY KEY (id),
--     CONSTRAINT fraud_decisions_event_id_key UNIQUE (event_id),  -- required by ON CONFLICT (event_id)
--     CONSTRAINT fraud_decisions_score_check CHECK (score >= 0 AND score <= 100)
-- );

-- CREATE INDEX IF NOT EXISTS idx_fraud_decisions_action          ON fraud_decisions (policy_action, created_at DESC);
-- CREATE INDEX IF NOT EXISTS idx_fraud_decisions_created_at      ON fraud_decisions (created_at DESC);
-- CREATE INDEX IF NOT EXISTS idx_fraud_decisions_fraud_type      ON fraud_decisions (fraud_type);
-- CREATE INDEX IF NOT EXISTS idx_fraud_decisions_risk_level      ON fraud_decisions (risk_level);
-- CREATE INDEX IF NOT EXISTS idx_fraud_decisions_source          ON fraud_decisions (source);
-- CREATE INDEX IF NOT EXISTS idx_fraud_decisions_subject_id      ON fraud_decisions (subject_id);
-- CREATE INDEX IF NOT EXISTS idx_fraud_decisions_emirates_hash   ON fraud_decisions (emirates_id_hash) WHERE emirates_id_hash IS NOT NULL;


-- -- =============================================================================
-- -- fraud_action_outcomes  — action actually applied by the originating service
-- -- =============================================================================
-- -- Written by storage/action_storing_repo.py via
-- -- POST /fraud-analytics-backend/v2/actions.
-- --
-- -- subject_id is stored redundantly (also present on fraud_events, reachable
-- -- via the event_id FK) so per-subject action queries don't require a join.
-- -- =============================================================================
-- CREATE TABLE IF NOT EXISTS fraud_action_outcomes (
--     id          UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
--     event_id    UUID            NOT NULL,
--     subject_id  VARCHAR(128)    NOT NULL,
--     service     VARCHAR(32)     NOT NULL,
--     action      VARCHAR(64)     NOT NULL,
--     created_at  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

--     CONSTRAINT fk_fraud_action_event
--         FOREIGN KEY (event_id)
--         REFERENCES fraud_events(event_id),
--     -- storage/action_storing_repo.py does INSERT ... ON CONFLICT (event_id)
--     -- DO UPDATE, which requires event_id to be unique.
--     CONSTRAINT uq_fraud_action_outcomes_event_id UNIQUE (event_id)
-- );

-- -- Supports "all actions for this subject" queries (fetch_user_action_outcomes)
-- -- without a join back through fraud_events.
-- CREATE INDEX IF NOT EXISTS idx_fraud_action_outcomes_subject_id
--     ON fraud_action_outcomes(subject_id);




-- -- =============================================================================
-- -- user_service_risk_profile — per-service rolling risk score
-- -- =============================================================================
-- -- escalation_score / escalation_updated_at hold the independent, additive
-- -- per-service escalation penalty — see storage/profile_repo.py
-- -- upsert_service_profile().
-- -- last_action_taken is nullable by design — always written as NULL now.
-- -- =============================================================================
-- CREATE TABLE IF NOT EXISTS user_service_risk_profile (
--     id                      SERIAL                  PRIMARY KEY,
--     subject_id              VARCHAR(128)            NOT NULL,
--     service                 VARCHAR(20)             NOT NULL,
--     rolling_score           NUMERIC(5,2)            NOT NULL DEFAULT 0,
--     last_blended_score      NUMERIC(5,2),                       -- burst+rolling blend at last write, for exact GET reconstruction
--     event_count             INTEGER                 NOT NULL DEFAULT 0,
--     last_event_id           UUID,
--     last_event_time         TIMESTAMPTZ,
--     last_risk_level         VARCHAR(20),
--     escalation_score        NUMERIC(5,2)            NOT NULL DEFAULT 0,
--     escalation_updated_at   TIMESTAMPTZ,
--     updated_at              TIMESTAMPTZ             NOT NULL DEFAULT NOW(),

--     CONSTRAINT uq_service_profile UNIQUE (subject_id, service),
--     CONSTRAINT chk_service CHECK (service IN ('AUTH','LOGIN','CONSENT','WALLET')),
--     CONSTRAINT chk_rolling_score CHECK (rolling_score BETWEEN 0 AND 100),
--     CONSTRAINT chk_escalation_score_range CHECK (escalation_score >= 0 AND escalation_score <= 100)
-- );

-- CREATE INDEX IF NOT EXISTS idx_srp_subject ON user_service_risk_profile (subject_id);
-- CREATE INDEX IF NOT EXISTS idx_srp_updated ON user_service_risk_profile (updated_at DESC);


-- -- =============================================================================
-- -- user_identity_risk_profile — composite identity score across all services
-- -- =============================================================================
-- -- previous_composite_score / risk_trend / effective_events / confidence /
-- -- profile_status are read and written by storage/profile_repo.py's
-- -- upsert_identity_profile() and fetch_identity_profile().
-- -- contributing_factors holds a ranked per-service breakdown of what drove
-- -- the current composite_score.
-- -- =============================================================================
-- CREATE TABLE IF NOT EXISTS user_identity_risk_profile (
--     id                          SERIAL              PRIMARY KEY,
--     subject_id                  VARCHAR(128)        NOT NULL UNIQUE,
--     composite_score              NUMERIC(5,2)        NOT NULL DEFAULT 0,
--     previous_composite_score     NUMERIC(5,2),
--     risk_trend                   VARCHAR(20),                    -- RISING | STABLE | FALLING | NEW
--     auth_score                   NUMERIC(5,2)        NOT NULL DEFAULT 0,
--     login_score                  NUMERIC(5,2)        NOT NULL DEFAULT 0,
--     consent_score                NUMERIC(5,2)        NOT NULL DEFAULT 0,
--     wallet_score                 NUMERIC(5,2)        NOT NULL DEFAULT 0,
--     cross_service_flag           BOOLEAN             NOT NULL DEFAULT FALSE,
--     cross_service_flag_reason    VARCHAR(255),
--     cross_service_flag_at        TIMESTAMPTZ,
--     effective_events             NUMERIC(8,3)        NOT NULL DEFAULT 0,   -- decayed event count (N_eff)
--     confidence                   NUMERIC(4,3)        NOT NULL DEFAULT 0,   -- 0.000 - 1.000
--     profile_status                VARCHAR(20),                    -- PROVISIONAL | ESTABLISHED | UNDER_REVIEW
--     contributing_factors          JSONB,                           -- ranked per-service breakdown
--     total_events                  INTEGER             NOT NULL DEFAULT 0,
--     highest_risk_level            VARCHAR(20),
--     last_event_time              TIMESTAMPTZ,
--     updated_at                    TIMESTAMPTZ         NOT NULL DEFAULT NOW(),

--     CONSTRAINT chk_composite CHECK (composite_score BETWEEN 0 AND 100),
--     CONSTRAINT chk_previous_composite CHECK (previous_composite_score IS NULL
--         OR previous_composite_score BETWEEN 0 AND 100),
--     CONSTRAINT chk_risk_trend CHECK (risk_trend IS NULL
--         OR risk_trend IN ('RISING', 'STABLE', 'FALLING', 'NEW')),
--     CONSTRAINT chk_confidence CHECK (confidence BETWEEN 0 AND 1),
--     CONSTRAINT chk_profile_status CHECK (profile_status IS NULL
--         OR profile_status IN ('PROVISIONAL', 'ESTABLISHED', 'UNDER_REVIEW'))
-- );

-- CREATE INDEX IF NOT EXISTS idx_irp_composite   ON user_identity_risk_profile (composite_score DESC);
-- CREATE INDEX IF NOT EXISTS idx_irp_cross_flag  ON user_identity_risk_profile (cross_service_flag) WHERE cross_service_flag = TRUE;


-- -- =============================================================================
-- -- fraud_sessions — durable audit copy of Redis session state
-- -- =============================================================================
-- CREATE TABLE IF NOT EXISTS fraud_sessions (
--     id                  SERIAL                      PRIMARY KEY,
--     session_id          VARCHAR(128)                NOT NULL UNIQUE,
--     subject_id          VARCHAR(128)                NOT NULL,
--     event_count         INTEGER                     NOT NULL DEFAULT 0,
--     high_event_count    INTEGER                     NOT NULL DEFAULT 0,
--     has_critical        BOOLEAN                     NOT NULL DEFAULT FALSE,
--     max_score           INTEGER                     NOT NULL DEFAULT 0,
--     session_risk_level  VARCHAR(20),
--     first_event_at      TIMESTAMPTZ,
--     last_event_at       TIMESTAMPTZ,
--     updated_at          TIMESTAMPTZ                 NOT NULL DEFAULT NOW()
-- );

-- CREATE INDEX IF NOT EXISTS idx_fs_subject ON fraud_sessions (subject_id);
-- CREATE INDEX IF NOT EXISTS idx_fs_updated ON fraud_sessions (updated_at DESC);


-- -- =============================================================================
-- -- device_trust — reserved for future use; no code currently reads/writes this
-- -- (device_features.py tracks device trust in Redis only, not this table)
-- -- =============================================================================
-- CREATE TABLE IF NOT EXISTS device_trust (
--     id              SERIAL                          PRIMARY KEY,
--     device_id       VARCHAR(256)                    NOT NULL UNIQUE,
--     subject_count   INTEGER                         NOT NULL DEFAULT 1,
--     is_flagged      BOOLEAN                         NOT NULL DEFAULT FALSE,
--     flag_reason     VARCHAR(100),
--     first_seen_at   TIMESTAMPTZ                     NOT NULL DEFAULT NOW(),
--     last_seen_at    TIMESTAMPTZ                     NOT NULL DEFAULT NOW(),
--     updated_at      TIMESTAMPTZ                     NOT NULL DEFAULT NOW()
-- );

-- CREATE INDEX IF NOT EXISTS idx_dt_flagged ON device_trust (is_flagged) WHERE is_flagged = TRUE;


-- -- =============================================================================
-- -- ip_reputation — manually managed blocklist, mirrored into Redis at startup
-- -- =============================================================================
-- CREATE TABLE IF NOT EXISTS ip_reputation (
--     id          SERIAL                              PRIMARY KEY,
--     src_ip      VARCHAR(45)                          NOT NULL UNIQUE,  -- IPv4 + IPv6
--     flag_reason VARCHAR(100)                         NOT NULL,
--     flagged_at  TIMESTAMPTZ                          NOT NULL DEFAULT NOW(),
--     flagged_by  VARCHAR(128),
--     is_active   BOOLEAN                              NOT NULL DEFAULT TRUE
-- );

-- CREATE INDEX IF NOT EXISTS idx_ir_active ON ip_reputation (src_ip) WHERE is_active = TRUE;


-- -- =============================================================================
-- -- user_feature_baseline — Welford's online mean/variance per user/feature
-- -- =============================================================================
-- CREATE TABLE IF NOT EXISTS user_feature_baseline (
--     id              SERIAL                          PRIMARY KEY,
--     subject_id      VARCHAR(128)                    NOT NULL,
--     service         VARCHAR(20)                     NOT NULL,  -- AUTH|LOGIN|WALLET|CONSENT
--     feature_name    VARCHAR(100)                    NOT NULL,
--     mean            DOUBLE PRECISION                NOT NULL DEFAULT 0.0,
--     m2              DOUBLE PRECISION                NOT NULL DEFAULT 0.0,
--     sample_count    INTEGER                         NOT NULL DEFAULT 0,
--     updated_at      TIMESTAMPTZ                     NOT NULL DEFAULT NOW(),

--     CONSTRAINT uq_ufb UNIQUE (subject_id, service, feature_name)
-- );

-- CREATE INDEX IF NOT EXISTS idx_ufb_subject_service ON user_feature_baseline (subject_id, service);


-- -- =============================================================================
-- -- service_deviation_config — per-service z-score tolerance for baselines
-- -- =============================================================================
-- CREATE TABLE IF NOT EXISTS service_deviation_config (
--     id              SERIAL                          PRIMARY KEY,
--     service         VARCHAR(20)                     NOT NULL,
--     feature_name    VARCHAR(100)                    NOT NULL DEFAULT '*',
--     tolerance_sigma DOUBLE PRECISION                NOT NULL DEFAULT 2.5,
--     enabled         BOOLEAN                         NOT NULL DEFAULT TRUE,
--     updated_at      TIMESTAMPTZ                     NOT NULL DEFAULT NOW(),

--     CONSTRAINT uq_sdc UNIQUE (service, feature_name)
-- );

-- INSERT INTO service_deviation_config (service, feature_name, tolerance_sigma) VALUES
--     ('AUTH',    '*', 2.5),
--     ('LOGIN',   '*', 2.0),
--     ('WALLET',  '*', 2.0),
--     ('CONSENT', '*', 2.5)
-- ON CONFLICT (service, feature_name) DO NOTHING;


-- -- =============================================================================
-- -- Verification
-- -- =============================================================================
-- DO $$
-- BEGIN
--     ASSERT (SELECT COUNT(*) FROM information_schema.tables
--             WHERE table_name = 'users') = 1, 'users table missing';
--     ASSERT (SELECT COUNT(*) FROM information_schema.tables
--             WHERE table_name = 'fraud_events') = 1, 'fraud_events table missing';
--     ASSERT (SELECT COUNT(*) FROM information_schema.tables
--             WHERE table_name = 'fraud_decisions') = 1, 'fraud_decisions table missing';
--     ASSERT (SELECT COUNT(*) FROM information_schema.tables
--             WHERE table_name = 'fraud_action_outcomes') = 1, 'fraud_action_outcomes table missing';
--     ASSERT (SELECT COUNT(*) FROM information_schema.tables
--             WHERE table_name = 'user_service_risk_profile') = 1, 'user_service_risk_profile table missing';
--     ASSERT (SELECT COUNT(*) FROM information_schema.tables
--             WHERE table_name = 'user_identity_risk_profile') = 1, 'user_identity_risk_profile table missing';
--     ASSERT (SELECT COUNT(*) FROM information_schema.tables
--             WHERE table_name = 'fraud_sessions') = 1, 'fraud_sessions table missing';
--     ASSERT (SELECT COUNT(*) FROM information_schema.tables
--             WHERE table_name = 'device_trust') = 1, 'device_trust table missing';
--     ASSERT (SELECT COUNT(*) FROM information_schema.tables
--             WHERE table_name = 'ip_reputation') = 1, 'ip_reputation table missing';
--     ASSERT (SELECT COUNT(*) FROM information_schema.tables
--             WHERE table_name = 'user_feature_baseline') = 1, 'user_feature_baseline table missing';
--     ASSERT (SELECT COUNT(*) FROM information_schema.tables
--             WHERE table_name = 'service_deviation_config') = 1, 'service_deviation_config table missing';

--     ASSERT (
--         SELECT is_nullable FROM information_schema.columns
--         WHERE table_name = 'fraud_decisions' AND column_name = 'policy_action'
--     ) = 'YES', 'policy_action must be nullable (action resolution disabled)';

--     ASSERT (SELECT COUNT(*) FROM information_schema.columns
--             WHERE table_name = 'fraud_decisions'
--               AND column_name IN ('exception_score','session_amplifier')
--            ) = 2, 'exception_score/session_amplifier columns missing on fraud_decisions';

--     ASSERT (SELECT COUNT(*) FROM information_schema.columns
--             WHERE table_name = 'user_service_risk_profile'
--               AND column_name IN ('escalation_score','escalation_updated_at')
--            ) = 2, 'escalation columns missing on user_service_risk_profile';

--     ASSERT (SELECT COUNT(*) FROM information_schema.columns
--             WHERE table_name = 'user_identity_risk_profile'
--               AND column_name IN ('previous_composite_score','risk_trend',
--                                    'effective_events','confidence',
--                                    'profile_status','contributing_factors')
--            ) = 6, 'trend/confidence/contributing_factors columns missing on user_identity_risk_profile';

--     ASSERT (SELECT COUNT(*) FROM information_schema.columns
--             WHERE table_name = 'fraud_action_outcomes'
--               AND column_name = 'subject_id'
--            ) = 1, 'subject_id column missing on fraud_action_outcomes';

--     RAISE NOTICE 'Full schema created and verified OK — 11 tables.';
-- END $$;

-- COMMIT;










BEGIN;

-- gen_random_uuid() needs pgcrypto on some PG builds; harmless if already core.
CREATE EXTENSION IF NOT EXISTS pgcrypto;


-- =============================================================================
-- users  — frontend login only, unrelated to the fraud engine itself
-- =============================================================================
CREATE TABLE IF NOT EXISTS users (
    id          UUID                        NOT NULL DEFAULT gen_random_uuid(),
    name        VARCHAR(100)                NOT NULL,
    mobile      VARCHAR(15)                 NOT NULL,
    email       VARCHAR(255)                NOT NULL,
    username    VARCHAR(50)                 NOT NULL,
    password    VARCHAR(255)                NOT NULL,
    role        VARCHAR(20)                 NOT NULL DEFAULT 'SERVICE_PROVIDER',
    is_active   BOOLEAN                     NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ                 NOT NULL DEFAULT NOW(),

    CONSTRAINT users_pkey PRIMARY KEY (id),
    CONSTRAINT users_mobile_key UNIQUE (mobile),
    CONSTRAINT users_username_key UNIQUE (username),
    CONSTRAINT users_email_key UNIQUE (email),
    CONSTRAINT users_role_check CHECK (role IN ('ADMIN', 'SERVICE_PROVIDER'))
);

CREATE INDEX IF NOT EXISTS idx_users_mobile   ON users (mobile);
CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);


-- =============================================================================
-- password_reset_tokens — short-lived password reset tokens
-- =============================================================================
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id          UUID                NOT NULL DEFAULT gen_random_uuid(),
    user_id     UUID                NOT NULL,
    token_hash  VARCHAR(64)         NOT NULL,
    created_at  TIMESTAMPTZ         NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ         NOT NULL DEFAULT (NOW() + INTERVAL '5 minutes'),
    consumed_at TIMESTAMPTZ,

    CONSTRAINT password_reset_tokens_pkey PRIMARY KEY (id),
    CONSTRAINT password_reset_tokens_token_hash_key UNIQUE (token_hash),
    CONSTRAINT password_reset_expiry_check CHECK (expires_at > created_at),
    CONSTRAINT password_reset_tokens_user_id_fkey
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_prt_expires_at
    ON password_reset_tokens (expires_at);
CREATE INDEX IF NOT EXISTS idx_prt_user_id
    ON password_reset_tokens (user_id);


-- =============================================================================
-- fraud_events  — raw incoming event log (append-only)
-- =============================================================================
CREATE TABLE IF NOT EXISTS fraud_events (
    id                  UUID                        NOT NULL DEFAULT gen_random_uuid(),
    schema_version      TEXT                        NOT NULL DEFAULT '2.0',
    event_type          TEXT                        NOT NULL,
    action_taxonomy     TEXT                        NOT NULL,   -- action_taxonomy: auth|login|consent|wallet
    action_taxonomy_sub_method TEXT,                            -- e.g. pin|wallet (auth only), NULL if not sent
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
    biometric_method    BOOLEAN                     NOT NULL DEFAULT FALSE,
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
--
-- exception_score and session_amplifier are the two intermediate scoring
-- values that were being computed on every event but never persisted —
-- only the final capped score made it to disk. Without them, a decision
-- log entry could show e.g. score=100 with no way to reconstruct whether
-- that came from rule weights alone, an exception-code bump, a session
-- amplifier, or some combination — the drill-down API needs the full
-- breakdown, not just the end result. Both are nullable because rows
-- written before this column existed will not have a value.
--   exception_score   — flat points added for the event's exception_code
--                       (scoring/engine.py _get_exception_scoring()),
--                       applied BEFORE the 0-100 cap.
--   session_amplifier — multiplier applied AFTER the cap, based on the
--                       session's accumulated risk state
--                       (scoring/engine.py apply_session_amplifier()).
-- =============================================================================
CREATE TABLE IF NOT EXISTS fraud_decisions (
    id                          UUID                NOT NULL DEFAULT gen_random_uuid(),
    event_id                    UUID                NOT NULL,
    fraud_type                  TEXT                NOT NULL,
    subject_id                  TEXT                NOT NULL,
    emirates_id_hash            TEXT,
    role                        TEXT,
    exception_code              TEXT,
    score                       INTEGER             NOT NULL,
    risk_level                  TEXT                NOT NULL,
    policy_action                TEXT,                                   -- nullable: action resolution disabled
    triggered_rules              TEXT[]              NOT NULL,
    rule_weights                  JSONB               NOT NULL DEFAULT '{}',
    features                    JSONB               NOT NULL,
    active_liveness_suggestion  JSONB,
    exception_score              NUMERIC(5,2),                           -- nullable: not recorded before this column existed
    session_amplifier            NUMERIC(4,3),                           -- nullable: not recorded before this column existed
    pre_profile_score            INTEGER,                                -- nullable: rows before this change
    profile_amplifier            NUMERIC(4,3),
    source                      TEXT                NOT NULL,
    config_version               TEXT                NOT NULL,
    created_at                   TIMESTAMPTZ         NOT NULL DEFAULT NOW(),

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
-- fraud_action_outcomes  — action actually applied by the originating service
-- =============================================================================
-- Written by storage/action_storing_repo.py via
-- POST /fraud-analytics-backend/v2/actions.
--
-- subject_id is stored redundantly (also present on fraud_events, reachable
-- via the event_id FK) so per-subject action queries don't require a join.
-- =============================================================================
CREATE TABLE IF NOT EXISTS fraud_action_outcomes (
    id          UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id    UUID            NOT NULL,
    subject_id  VARCHAR(128)    NOT NULL,
    service     VARCHAR(32)     NOT NULL,
    action      VARCHAR(64)     NOT NULL,
    created_at  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_fraud_action_event
        FOREIGN KEY (event_id)
        REFERENCES fraud_events(event_id),
    -- storage/action_storing_repo.py does INSERT ... ON CONFLICT (event_id)
    -- DO UPDATE, which requires event_id to be unique.
    CONSTRAINT uq_fraud_action_outcomes_event_id UNIQUE (event_id)
);

-- Supports "all actions for this subject" queries (fetch_user_action_outcomes)
-- without a join back through fraud_events.
CREATE INDEX IF NOT EXISTS idx_fraud_action_outcomes_subject_id
    ON fraud_action_outcomes(subject_id);




-- =============================================================================
-- user_service_risk_profile — per-service rolling risk score
-- =============================================================================
-- escalation_score / escalation_updated_at hold the independent, additive
-- per-service escalation penalty — see storage/profile_repo.py
-- upsert_service_profile().
-- last_action_taken is nullable by design — always written as NULL now.
-- =============================================================================
CREATE TABLE IF NOT EXISTS user_service_risk_profile (
    id                      SERIAL                  PRIMARY KEY,
    subject_id              VARCHAR(128)            NOT NULL,
    service                 VARCHAR(20)             NOT NULL,
    rolling_score           NUMERIC(5,2)            NOT NULL DEFAULT 0,
    last_blended_score      NUMERIC(5,2),                       -- burst+rolling blend at last write, for exact GET reconstruction
    event_count             INTEGER                 NOT NULL DEFAULT 0,
    last_event_id           UUID,
    last_event_time         TIMESTAMPTZ,
    last_risk_level         VARCHAR(20),
    escalation_score        NUMERIC(5,2)            NOT NULL DEFAULT 0,
    escalation_updated_at   TIMESTAMPTZ,
    updated_at              TIMESTAMPTZ             NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_service_profile UNIQUE (subject_id, service),
    CONSTRAINT chk_service CHECK (service IN ('AUTH','LOGIN','CONSENT','WALLET')),
    CONSTRAINT chk_rolling_score CHECK (rolling_score BETWEEN 0 AND 100),
    CONSTRAINT chk_escalation_score_range CHECK (escalation_score >= 0 AND escalation_score <= 100)
);

CREATE INDEX IF NOT EXISTS idx_srp_subject ON user_service_risk_profile (subject_id);
CREATE INDEX IF NOT EXISTS idx_srp_updated ON user_service_risk_profile (updated_at DESC);


-- =============================================================================
-- user_identity_risk_profile — composite identity score across all services
-- =============================================================================
-- previous_composite_score / risk_trend / effective_events / confidence /
-- profile_status are read and written by storage/profile_repo.py's
-- upsert_identity_profile() and fetch_identity_profile().
-- contributing_factors holds a ranked per-service breakdown of what drove
-- the current composite_score.
-- =============================================================================
CREATE TABLE IF NOT EXISTS user_identity_risk_profile (
    id                          SERIAL              PRIMARY KEY,
    subject_id                  VARCHAR(128)        NOT NULL UNIQUE,
    composite_score              NUMERIC(5,2)        NOT NULL DEFAULT 0,
    previous_composite_score     NUMERIC(5,2),
    risk_trend                   VARCHAR(20),                    -- RISING | STABLE | FALLING | NEW
    auth_score                   NUMERIC(5,2)        NOT NULL DEFAULT 0,
    login_score                  NUMERIC(5,2)        NOT NULL DEFAULT 0,
    consent_score                NUMERIC(5,2)        NOT NULL DEFAULT 0,
    wallet_score                 NUMERIC(5,2)        NOT NULL DEFAULT 0,
    cross_service_flag           BOOLEAN             NOT NULL DEFAULT FALSE,
    cross_service_flag_reason    VARCHAR(255),
    cross_service_flag_at        TIMESTAMPTZ,
    effective_events             NUMERIC(8,3)        NOT NULL DEFAULT 0,   -- decayed event count (N_eff)
    confidence                   NUMERIC(4,3)        NOT NULL DEFAULT 0,   -- 0.000 - 1.000
    profile_status                VARCHAR(20),                    -- PROVISIONAL | ESTABLISHED | UNDER_REVIEW
    contributing_factors          JSONB,                           -- ranked per-service breakdown
    total_events                  INTEGER             NOT NULL DEFAULT 0,
    highest_risk_level            VARCHAR(20),
    last_event_time              TIMESTAMPTZ,
    updated_at                    TIMESTAMPTZ         NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_composite CHECK (composite_score BETWEEN 0 AND 100),
    CONSTRAINT chk_previous_composite CHECK (previous_composite_score IS NULL
        OR previous_composite_score BETWEEN 0 AND 100),
    CONSTRAINT chk_risk_trend CHECK (risk_trend IS NULL
        OR risk_trend IN ('RISING', 'STABLE', 'FALLING', 'NEW')),
    CONSTRAINT chk_confidence CHECK (confidence BETWEEN 0 AND 1),
    CONSTRAINT chk_profile_status CHECK (profile_status IS NULL
        OR profile_status IN ('PROVISIONAL', 'ESTABLISHED', 'UNDER_REVIEW'))
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
    service         VARCHAR(20)                     NOT NULL,  -- AUTH|LOGIN|WALLET|CONSENT
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
    ('LOGIN',   '*', 2.0),
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
            WHERE table_name = 'password_reset_tokens') = 1, 'password_reset_tokens table missing';
    ASSERT (SELECT COUNT(*) FROM information_schema.tables
            WHERE table_name = 'fraud_events') = 1, 'fraud_events table missing';
    ASSERT (SELECT COUNT(*) FROM information_schema.tables
            WHERE table_name = 'fraud_decisions') = 1, 'fraud_decisions table missing';
    ASSERT (SELECT COUNT(*) FROM information_schema.tables
            WHERE table_name = 'fraud_action_outcomes') = 1, 'fraud_action_outcomes table missing';
    ASSERT (SELECT COUNT(*) FROM information_schema.tables
            WHERE table_name = 'user_service_risk_profile') = 1, 'user_service_risk_profile table missing';
    ASSERT (SELECT COUNT(*) FROM information_schema.tables
            WHERE table_name = 'user_identity_risk_profile') = 1, 'user_identity_risk_profile table missing';
    ASSERT (SELECT COUNT(*) FROM information_schema.tables
            WHERE table_name = 'fraud_sessions') = 1, 'fraud_sessions table missing';
    ASSERT (SELECT COUNT(*) FROM information_schema.tables
            WHERE table_name = 'ip_reputation') = 1, 'ip_reputation table missing';
    ASSERT (SELECT COUNT(*) FROM information_schema.tables
            WHERE table_name = 'user_feature_baseline') = 1, 'user_feature_baseline table missing';
    ASSERT (SELECT COUNT(*) FROM information_schema.tables
            WHERE table_name = 'service_deviation_config') = 1, 'service_deviation_config table missing';
    ASSERT (SELECT COUNT(*) FROM information_schema.columns
               WHERE table_name = 'fraud_events'
                 AND column_name = 'biometric_method'
              ) = 1, 'biometric_method column missing on fraud_events';
    ASSERT (
        SELECT is_nullable FROM information_schema.columns
        WHERE table_name = 'fraud_decisions' AND column_name = 'policy_action'
    ) = 'YES', 'policy_action must be nullable (action resolution disabled)';

    ASSERT (SELECT COUNT(*) FROM information_schema.columns
            WHERE table_name = 'fraud_decisions'
              AND column_name IN ('exception_score','session_amplifier')
           ) = 2, 'exception_score/session_amplifier columns missing on fraud_decisions';

    ASSERT (SELECT COUNT(*) FROM information_schema.columns
            WHERE table_name = 'user_service_risk_profile'
              AND column_name IN ('escalation_score','escalation_updated_at')
           ) = 2, 'escalation columns missing on user_service_risk_profile';

    ASSERT (SELECT COUNT(*) FROM information_schema.columns
            WHERE table_name = 'user_identity_risk_profile'
              AND column_name IN ('previous_composite_score','risk_trend',
                                   'effective_events','confidence',
                                   'profile_status','contributing_factors')
           ) = 6, 'trend/confidence/contributing_factors columns missing on user_identity_risk_profile';

    ASSERT (SELECT COUNT(*) FROM information_schema.columns
            WHERE table_name = 'fraud_action_outcomes'
              AND column_name = 'subject_id'
           ) = 1, 'subject_id column missing on fraud_action_outcomes';
    
    ASSERT (SELECT COUNT(*) FROM information_schema.columns
            WHERE table_name = 'fraud_action_outcomes'
              AND column_name = 'updated_at'
           ) = 1, 'updated_at column missing on fraud_action_outcomes';

    ASSERT (SELECT COUNT(*) FROM information_schema.columns
        WHERE table_name = 'fraud_decisions'
          AND column_name IN ('pre_profile_score','profile_amplifier')
       ) = 2, 'pre_profile_score/profile_amplifier columns missing on fraud_decisions';

    ASSERT (SELECT COUNT(*) FROM information_schema.columns
            WHERE table_name = 'fraud_events'
                AND column_name = 'action_taxonomy_sub_method'
            ) = 1, 'action_taxonomy_sub_method column missing on fraud_events';

    RAISE NOTICE 'Full schema created and verified OK — 11 tables.';
END $$;

COMMIT;