CREATE TABLE fraud_action_outcomes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL,
    service VARCHAR(32) NOT NULL,
    action VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_fraud_action_event
        FOREIGN KEY (event_id)
        REFERENCES fraud_events(event_id)
);

CREATE INDEX idx_fraud_action_outcomes_event_id
    ON fraud_action_outcomes(event_id);