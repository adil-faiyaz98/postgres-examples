\c db_dev;

-- 1) Enable PL/Python (if not already enabled)
CREATE EXTENSION IF NOT EXISTS plpython3u;

-- 2) Create a table to store AI anomaly detection results
CREATE TABLE IF NOT EXISTS ml.anomaly_predictions (
    prediction_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type TEXT NOT NULL,
    user_id UUID,
    detected_anomaly BOOLEAN DEFAULT FALSE,
    anomaly_score NUMERIC(10,5),
    detected_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3) Create a Python function to detect anomalies using ML
CREATE OR REPLACE FUNCTION ml.detect_anomalies(
    event_data JSONB
) RETURNS BOOLEAN AS $$
import json
import numpy as np
from sklearn.ensemble import IsolationForest

# Extract relevant data
event_list = json.loads(event_data)
X = np.array([list(event.values()) for event in event_list])

# Train Isolation Forest model for anomaly detection
model = IsolationForest(n_estimators=100, contamination=0.05)
model.fit(X)

# Predict anomalies
predictions = model.predict(X)
return any(p == -1 for p in predictions)
$$ LANGUAGE plpython3u;

-- 4) Create a function to store detected anomalies in PostgreSQL
CREATE OR REPLACE FUNCTION ml.store_anomaly_detection_result()
RETURNS TRIGGER AS $$
DECLARE anomaly_detected BOOLEAN;
BEGIN
    -- Run AI anomaly detection
    anomaly_detected := ml.detect_anomalies(NEW.details);

    -- Insert detected anomalies into table
    INSERT INTO ml.anomaly_predictions (event_type, user_id, detected_anomaly, anomaly_score)
    VALUES (NEW.event_type, NEW.details->>'user_id'::UUID, anomaly_detected, NEW.details->>'anomaly_score'::NUMERIC);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 5) Attach trigger to analyze logs using AI model
CREATE TRIGGER ai_anomaly_detection_trigger
AFTER INSERT
ON logs.notification_log
FOR EACH ROW
WHEN (NEW.event_type IN ('Suspicious Login', 'SQL Injection Attempt', 'Privilege Escalation Attempt'))
EXECUTE FUNCTION ml.store_anomaly_detection_result();
