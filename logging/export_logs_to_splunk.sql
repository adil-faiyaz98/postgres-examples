\c db_dev;

-- 1) Function to send logging to ELK via Logstash
CREATE OR REPLACE FUNCTION logs.export_logs_to_elk()
RETURNS TRIGGER AS $$
DECLARE elk_http_endpoint TEXT := 'http://logstash-server:5044'; -- Replace with your Logstash URL
DECLARE log_payload TEXT;
BEGIN
    log_payload := json_build_object(
        'log_id', NEW.log_id,
        'event_type', NEW.event_type,
        'event_source', NEW.event_source,
        'details', NEW.details,
        'logged_by', NEW.logged_by,
        'logged_at', NEW.logged_at
    )::TEXT;

    -- Send log data to Logstash
    PERFORM http_post(elk_http_endpoint, 'application/json', log_payload);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Attach trigger to automatically export logging
CREATE TRIGGER send_logs_to_elk
AFTER INSERT
ON logs.notification_log
FOR EACH ROW
EXECUTE FUNCTION logs.export_logs_to_elk();
