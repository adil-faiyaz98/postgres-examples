\c db_dev;

-- Function to send anomaly logs to Datadog
CREATE OR REPLACE FUNCTION monitoring.send_anomaly_logs_to_datadog()
RETURNS TRIGGER AS $$
DECLARE
    datadog_api_url TEXT := 'https://http-intake.logs.datadoghq.com/v1/input';
    datadog_api_key TEXT := current_setting('custom.datadog_api_key', TRUE);
    log_payload TEXT;
BEGIN
    log_payload := json_build_object(
        'ddsource', 'postgresql',
        'service', 'db-security',
        'event_type', NEW.event_type,
        'event_source', NEW.event_source,
        'details', NEW.details,
        'logged_by', NEW.logged_by,
        'logged_at', NEW.logged_at
    )::TEXT;

    PERFORM http_post(datadog_api_url || '?api_key=' || datadog_api_key, 'application/json', log_payload);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER;

-- Attach trigger to send anomaly logs to Datadog
CREATE TRIGGER datadog_anomaly_trigger
AFTER INSERT
ON logs.notification_log
FOR EACH ROW
WHEN (NEW.event_type IN ('SQL Injection Attempt', 'Suspicious Login'))
EXECUTE FUNCTION monitoring.send_anomaly_logs_to_datadog();
