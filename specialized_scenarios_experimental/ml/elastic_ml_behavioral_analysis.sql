\c db_dev;

-- 1) Create function to send PostgreSQL logs to Elastic ML for analysis
CREATE OR REPLACE FUNCTION ml.send_logs_to_elastic_ml()
RETURNS TRIGGER AS $$
DECLARE elastic_ml_url TEXT := 'http://elasticsearch-server:9200/_ml/anomaly_detect';
DECLARE log_payload TEXT;
BEGIN
    log_payload := json_build_object(
        'event_type', NEW.event_type,
        'event_source', NEW.event_source,
        'details', NEW.details,
        'logged_by', NEW.logged_by,
        'logged_at', NEW.logged_at
    )::TEXT;

    -- Send log data to Elastic ML for machine learning analysis
    PERFORM http_post(elastic_ml_url, 'application/json', log_payload);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Attach trigger to send anomaly logs to Elastic ML
CREATE TRIGGER elastic_ml_behavior_trigger
AFTER INSERT
ON logs.notification_log
FOR EACH ROW
WHEN (NEW.event_type IN ('Suspicious Login', 'SQL Injection Attempt', 'Abnormal Query Pattern'))
EXECUTE FUNCTION ml.send_logs_to_elastic_ml();
