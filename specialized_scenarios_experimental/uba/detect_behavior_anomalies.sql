\c db_dev;

-- 1) Create function to detect AI-predicted anomalies in user behavior
CREATE OR REPLACE FUNCTION uba.detect_behavior_anomalies()
RETURNS TRIGGER AS $$
DECLARE anomaly_detected BOOLEAN;
BEGIN
    -- Run ML model to detect anomalies
    anomaly_detected := ml.detect_anomalies(NEW.event_details);

    -- If an anomaly is detected, store it in AI anomaly table
    IF anomaly_detected THEN
        INSERT INTO ml.anomaly_predictions (event_type, user_id, detected_anomaly, anomaly_score)
        VALUES (NEW.event_type, NEW.user_id, TRUE, NEW.event_details->>'anomaly_score'::NUMERIC);
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Attach trigger to analyze user behavior using AI model
CREATE TRIGGER ai_behavior_anomaly_trigger
AFTER INSERT
ON uba.user_activity_logs
FOR EACH ROW
EXECUTE FUNCTION uba.detect_behavior_anomalies();
