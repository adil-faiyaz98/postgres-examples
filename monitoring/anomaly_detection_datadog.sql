\c db_dev;

-- 1) Create function to send anomaly logs to Datadog
CREATE OR REPLACE FUNCTION monitoring.send_anomaly_logs_to_datadog()
RETURNS TRIGGER AS $$
DECLARE datadog_api_url TEXT := 'https://api.datadoghq.com/api/v1/events';
DECLARE datadog_api_key TEXT := 'your-datadog-api-key';
DECLARE log_payload TEXT;
BEGIN
    log_payload := json_build_object(
        'title', 'PostgreSQL Anomaly Detected!',
        'text', json_build_object(
            'event_type', NEW.event_type,
            'event_source', NEW.event_source,
            'details', NEW.details,
            'logged_by', NEW.logged_by,
            'logged_at', NEW.logged_at
        ),
        'alert_type', 'error'
    )::TEXT;

    -- Send log data to Datadog AI anomaly detection
    PERFORM http_post(datadog_api_url || '?api_key=' || datadog_api_key, 'application/json', log_payload);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Attach trigger to send anomaly logs to Datadog
CREATE TRIGGER datadog_anomaly_trigger
AFTER INSERT
ON logs.notification_log
FOR EACH ROW
WHEN (NEW.event_type = 'SQL Injection Attempt' OR NEW.event_type = 'Suspicious Login')
EXECUTE FUNCTION monitoring.send_anomaly_logs
