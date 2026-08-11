-- =============================================================
-- PHASE 1 MIGRATION
-- Fraud Scoring Platform — Foundation Changes
-- Run once against fraud_management database
-- Safe to run: all changes are additive (no existing data loss)
-- =============================================================

BEGIN;

-- -------------------------------------------------------------
-- fraud_events: add identity extension columns
-- -------------------------------------------------------------
ALTER TABLE fraud_events
    ADD COLUMN IF NOT EXISTS emirates_id_hash TEXT,
    ADD COLUMN IF NOT EXISTS role             TEXT,
    ADD COLUMN IF NOT EXISTS exception_code  TEXT;

-- Index: look up all events for a given Emirates ID hash
CREATE INDEX IF NOT EXISTS idx_fraud_events_emirates_hash
    ON fraud_events (emirates_id_hash)
    WHERE emirates_id_hash IS NOT NULL;

-- Index: filter events by role (agent vs citizen analytics)
CREATE INDEX IF NOT EXISTS idx_fraud_events_role
    ON fraud_events (role)
    WHERE role IS NOT NULL;

-- Bump schema version on existing rows
UPDATE fraud_events SET schema_version = '2.0' WHERE schema_version = '1.0';


-- -------------------------------------------------------------
-- fraud_decisions: add identity fields + rule_weights + fix action
-- -------------------------------------------------------------
ALTER TABLE fraud_decisions
    ADD COLUMN IF NOT EXISTS emirates_id_hash TEXT,
    ADD COLUMN IF NOT EXISTS role             TEXT,
    ADD COLUMN IF NOT EXISTS exception_code  TEXT,
    ADD COLUMN IF NOT EXISTS rule_weights    JSONB DEFAULT '{}';

-- Rename policy_action values: replace legacy "no" with "ALLOW"
-- (rows inserted before Phase 1 had hardcoded "no")
UPDATE fraud_decisions
    SET policy_action = 'ALLOW'
    WHERE policy_action = 'no';

-- Index: look up decisions by Emirates ID hash
CREATE INDEX IF NOT EXISTS idx_fraud_decisions_emirates_hash
    ON fraud_decisions (emirates_id_hash)
    WHERE emirates_id_hash IS NOT NULL;

-- Index: filter by action taken (ALLOW/MONITOR/STEP_UP/BLOCK)
CREATE INDEX IF NOT EXISTS idx_fraud_decisions_action
    ON fraud_decisions (policy_action, created_at DESC);


-- -------------------------------------------------------------
-- Immutability: revoke UPDATE and DELETE from app user
-- Fraud decisions are an append-only compliance record.
-- Replace 'fraud_app_user' with the actual application DB user.
-- -------------------------------------------------------------
-- REVOKE UPDATE, DELETE ON fraud_decisions FROM fraud_app_user;
-- REVOKE UPDATE, DELETE ON fraud_events    FROM fraud_app_user;


-- -------------------------------------------------------------
-- Verify
-- -------------------------------------------------------------
DO $$
BEGIN
    ASSERT (
        SELECT COUNT(*) FROM information_schema.columns
        WHERE table_name = 'fraud_events'
          AND column_name IN ('emirates_id_hash', 'role', 'exception_code')
    ) = 3,
    'fraud_events: expected 3 new columns';

    ASSERT (
        SELECT COUNT(*) FROM information_schema.columns
        WHERE table_name = 'fraud_decisions'
          AND column_name IN ('emirates_id_hash', 'role', 'exception_code', 'rule_weights')
    ) = 4,
    'fraud_decisions: expected 4 new columns';

    RAISE NOTICE 'Phase 1 migration verified successfully.';
END $$;

COMMIT;
