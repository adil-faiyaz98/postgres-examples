\c db_dev;

-- 1) Create function to send logs to ELK ML API for analysis
CREATE OR REPLACE FUNCTION ml.send_logs_to_elastic_ml()
RETURNS TRIGGER AS $$
DECLARE elk_ml_api_url TEXT := 'http://elasticsearch-server:9200/_ml/anomaly_detect';
DECLARE log_payload TEXT;
BEGIN
    log_payload := json_build_object(
        'event_type', NEW.event_type,
        'event_source', NEW.event_source,
        'details', NEW.details,
        'logged_by', NEW.logged_by,
        'logged_at', NEW.logged_at
    )::TEXT;

    -- Send log data to Elastic ML API
    PERFORM http_post(elk_ml_api_url, 'application/json', log_payload);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Attach trigger to send anomaly logs to Elastic ML
CREATE TRIGGER elastic_ml_anomaly_trigger
AFTER INSERT
ON logs.notification_log
FOR EACH ROW
WHEN (NEW.event_type IN ('SQL Injection Attempt', 'Suspicious Login', 'Account Locked'))
EXECUTE FUNCTION ml.send_logs_to_elastic_ml();
