\c db_dev;

-- 1) Function to send logging to Datadog
CREATE OR REPLACE FUNCTION logs.export_logs_to_datadog()
RETURNS TRIGGER AS $$
DECLARE datadog_api_url TEXT := 'https://http-intake.logging.datadoghq.com/v1/input';
DECLARE datadog_api_key TEXT := 'your-datadog-api-key';
DECLARE log_payload TEXT;
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

    -- Send log data to Datadog
    PERFORM http_post(datadog_api_url || '?api_key=' || datadog_api_key, 'application/json', log_payload);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Attach trigger to send logging to Datadog
CREATE TRIGGER send_logs_to_datadog
AFTER INSERT
ON logs.notification_log
FOR EACH ROW
EXECUTE FUNCTION logs.export_logs_to_datadog();
