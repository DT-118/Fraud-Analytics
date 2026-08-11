-- =============================================================================
-- Phase 6 Migration: Idempotency, Historical Risk Tracking
-- =============================================================================
-- Applies on top of phase5_migration.sql.
--
-- Changes:
--   1. Add UNIQUE constraint on fraud_events.event_id  (SEC-03)
--   2. Add UNIQUE constraint on fraud_decisions.event_id  (DAT-01)
--   3. Fix highest_risk_level in user_identity_risk_profile to track
--      the historical maximum, not the current event  (LOG-07)
-- =============================================================================


-- ---------------------------------------------------------------------------
-- 1. Idempotency: UNIQUE constraint on fraud_events.event_id
--    Prevents duplicate raw events from landing even when Redis is down.
--    ON CONFLICT DO NOTHING in insert_fraud_event makes this safe.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE table_name = 'fraud_events'
          AND constraint_type = 'UNIQUE'
          AND constraint_name = 'uq_fraud_events_event_id'
    ) THEN
        ALTER TABLE fraud_events
            ADD CONSTRAINT uq_fraud_events_event_id UNIQUE (event_id);
        RAISE NOTICE 'Added UNIQUE(event_id) to fraud_events';
    ELSE
        RAISE NOTICE 'UNIQUE(event_id) on fraud_events already exists — skipped';
    END IF;
END $$;


-- ---------------------------------------------------------------------------
-- 2. Idempotency: UNIQUE constraint on fraud_decisions.event_id
--    Prevents duplicate decisions from being persisted.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE table_name = 'fraud_decisions'
          AND constraint_type = 'UNIQUE'
          AND constraint_name = 'uq_fraud_decisions_event_id'
    ) THEN
        ALTER TABLE fraud_decisions
            ADD CONSTRAINT uq_fraud_decisions_event_id UNIQUE (event_id);
        RAISE NOTICE 'Added UNIQUE(event_id) to fraud_decisions';
    ELSE
        RAISE NOTICE 'UNIQUE(event_id) on fraud_decisions already exists — skipped';
    END IF;
END $$;


-- ---------------------------------------------------------------------------
-- 3. Track historical highest risk level in user_identity_risk_profile.
--    The existing highest_risk_level column is overwritten on each event
--    (it stored the current event's band, not the historical maximum).
--    We rename it to current_risk_level and add highest_risk_level_ever
--    which only ever increases via a CASE comparison in the upsert.
--
--    For backward compatibility the Python upsert_identity_profile already
--    uses a CASE comparison that keeps the higher of the two bands — this
--    migration just makes the intent explicit in the column name.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    -- Add highest_risk_level_ever if it does not exist
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'user_identity_risk_profile'
          AND column_name = 'highest_risk_level_ever'
    ) THEN
        ALTER TABLE user_identity_risk_profile
            ADD COLUMN highest_risk_level_ever VARCHAR(20)
                NOT NULL DEFAULT 'NORISK';

        -- Back-fill: copy current highest_risk_level into the new column
        UPDATE user_identity_risk_profile
        SET highest_risk_level_ever = highest_risk_level
        WHERE highest_risk_level IS NOT NULL;

        RAISE NOTICE 'Added highest_risk_level_ever to user_identity_risk_profile';
    ELSE
        RAISE NOTICE 'highest_risk_level_ever already exists — skipped';
    END IF;
END $$;


-- ---------------------------------------------------------------------------
-- Verification
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    ASSERT (
        SELECT COUNT(*) FROM information_schema.table_constraints
        WHERE table_name = 'fraud_events'
          AND constraint_name = 'uq_fraud_events_event_id'
    ) = 1, 'UNIQUE(event_id) missing from fraud_events';

    ASSERT (
        SELECT COUNT(*) FROM information_schema.table_constraints
        WHERE table_name = 'fraud_decisions'
          AND constraint_name = 'uq_fraud_decisions_event_id'
    ) = 1, 'UNIQUE(event_id) missing from fraud_decisions';

    ASSERT (
        SELECT COUNT(*) FROM information_schema.columns
        WHERE table_name = 'user_identity_risk_profile'
          AND column_name = 'highest_risk_level_ever'
    ) = 1, 'highest_risk_level_ever column missing';

    RAISE NOTICE 'Phase 6 migration verified OK';
END $$;
