\c db_dev;

-- 1) Create function to send security logs to Elastic ML forecasting
CREATE OR REPLACE FUNCTION ml.send_logs_to_elastic_forecast()
RETURNS TRIGGER AS $$
DECLARE elastic_ml_url TEXT := 'http://elasticsearch-server:9200/_ml/forecast';
DECLARE log_payload TEXT;
BEGIN
    log_payload := json_build_object(
        'event_type', NEW.event_type,
        'user_id', NEW.details->>'user_id',
        'timestamp', NEW.logged_at
    )::TEXT;

    -- Send log data to Elastic ML for AI-based forecasting
    PERFORM http_post(elastic_ml_url, 'application/json', log_payload);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Attach trigger to send security logs to Elastic ML for forecasting
CREATE TRIGGER elastic_ml_forecast_trigger
AFTER INSERT
ON logs.notification_log
FOR EACH ROW
WHEN (NEW.event_type IN ('Suspicious Login', 'SQL Injection Attempt', 'Privilege Escalation Attempt'))
EXECUTE FUNCTION ml.send_logs_to_elastic_forecast();
