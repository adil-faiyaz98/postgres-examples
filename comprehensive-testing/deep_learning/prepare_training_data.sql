\c db_dev;

-- 1) Create table to store training data for deep learning models
CREATE TABLE IF NOT EXISTS deep_learning.security_training_data (
    training_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type TEXT NOT NULL,  -- (e.g., 'SQL Injection Attempt', 'Suspicious Login')
    user_id UUID,
    ip_address TEXT,
    query_execution_time NUMERIC,
    role_changes INT,
    failed_logins INT,
    detected_anomaly BOOLEAN DEFAULT FALSE,
    detected_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2) Populate training dataset from AI anomaly logs
INSERT INTO deep_learning.security_training_data (event_type, user_id, ip_address, query_execution_time, role_changes, failed_logins, detected_anomaly)
SELECT
    event_type,
    details->>'user_id'::UUID,
    details->>'ip_address',
    details->>'execution_time'::NUMERIC,
    details->>'role_changes'::INT,
    details->>'failed_logins'::INT,
    detected_anomaly
FROM ml.anomaly_predictions
WHERE detected_at >= NOW() - INTERVAL '6 months';
