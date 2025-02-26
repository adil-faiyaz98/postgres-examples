\c db_dev;

-- 1) Create table to store AI-governed PostgreSQL security policies
CREATE TABLE IF NOT EXISTS autonomous_security.ai_governed_policies (
    policy_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_name TEXT NOT NULL,
    enforced_by_ai BOOLEAN DEFAULT TRUE,
    last_updated TIMESTAMPTZ DEFAULT NOW()
);

-- 2) Create table to track policy change history
CREATE TABLE IF NOT EXISTS autonomous_security.ai_policy_history (
    history_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_id UUID NOT NULL REFERENCES autonomous_security.ai_governed_policies(policy_id),
    previous_value BOOLEAN,
    updated_value BOOLEAN,
    changed_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3) Function to allow AI to dynamically adjust PostgreSQL security policies
CREATE OR REPLACE FUNCTION autonomous_security.update_ai_governance_policies()
RETURNS VOID AS $$
BEGIN
    -- Strengthen policies for frequently flagged security risks
    UPDATE autonomous_security.ai_governed_policies
    SET enforced_by_ai = TRUE
    WHERE policy_name IN (
        SELECT DISTINCT event_type
        FROM ml.anomaly_predictions
        WHERE detected_anomaly = TRUE
    )
    RETURNING policy_id, FALSE, TRUE INTO policy_id, previous_value, updated_value;

    -- Log AI security policy updates
    INSERT INTO autonomous_security.ai_policy_history (policy_id, previous_value, updated_value)
    VALUES (policy_id, previous_value, updated_value);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
