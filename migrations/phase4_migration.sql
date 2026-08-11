-- =============================================================================
-- Phase 4 Migration: Decision Intelligence
-- =============================================================================
-- Applies on top of phase3_migration.sql.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Session-level fraud tracking
-- One row per session_id. Updated after every event scored within the session.
-- Redis holds the live state; this table is the durable audit copy.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud_sessions (
    id                  SERIAL PRIMARY KEY,
    session_id          VARCHAR(128)    NOT NULL UNIQUE,
    subject_id          VARCHAR(128)    NOT NULL,
    event_count         INTEGER         NOT NULL DEFAULT 0,
    high_event_count    INTEGER         NOT NULL DEFAULT 0,
    has_critical        BOOLEAN         NOT NULL DEFAULT FALSE,
    max_score           INTEGER         NOT NULL DEFAULT 0,
    session_risk_level  VARCHAR(20),
    first_event_at      TIMESTAMPTZ,
    last_event_at       TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fs_subject
    ON fraud_sessions (subject_id);

CREATE INDEX IF NOT EXISTS idx_fs_updated
    ON fraud_sessions (updated_at DESC);

-- ---------------------------------------------------------------------------
-- Device trust — cross-subject device usage tracking
-- Tracks how many distinct subjects have used each device_id.
-- High subject-count devices are shared fraud devices.
-- Redis holds the live count; this table holds the permanent record.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS device_trust (
    id              SERIAL PRIMARY KEY,
    device_id       VARCHAR(256)    NOT NULL UNIQUE,
    subject_count   INTEGER         NOT NULL DEFAULT 1,
    is_flagged      BOOLEAN         NOT NULL DEFAULT FALSE,
    flag_reason     VARCHAR(100),
    first_seen_at   TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dt_flagged
    ON device_trust (is_flagged)
    WHERE is_flagged = TRUE;

-- ---------------------------------------------------------------------------
-- IP reputation — manually managed blocklist
-- IPs are added here by the fraud operations team.
-- Redis mirrors this list for sub-millisecond lookup during scoring.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ip_reputation (
    id          SERIAL PRIMARY KEY,
    src_ip      VARCHAR(45)     NOT NULL UNIQUE,  -- supports IPv4 and IPv6
    flag_reason VARCHAR(100)    NOT NULL,          -- TOR_EXIT|DATACENTER|KNOWN_BAD|VPN
    flagged_at  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    flagged_by  VARCHAR(128),                      -- analyst ID who added it
    is_active   BOOLEAN         NOT NULL DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_ir_active
    ON ip_reputation (src_ip)
    WHERE is_active = TRUE;

-- ---------------------------------------------------------------------------
-- Verification
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    ASSERT (SELECT COUNT(*) FROM information_schema.tables
            WHERE table_name = 'fraud_sessions') = 1,
        'fraud_sessions table missing';
    ASSERT (SELECT COUNT(*) FROM information_schema.tables
            WHERE table_name = 'device_trust') = 1,
        'device_trust table missing';
    ASSERT (SELECT COUNT(*) FROM information_schema.tables
            WHERE table_name = 'ip_reputation') = 1,
        'ip_reputation table missing';
    RAISE NOTICE 'Phase 4 migration verified OK';
END $$;
