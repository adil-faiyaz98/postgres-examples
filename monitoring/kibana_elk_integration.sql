\c db_dev;

-- 1) Create function to send logs to ELK (via Logstash HTTP endpoint)
CREATE OR REPLACE FUNCTION monitoring.send_logs_to_elk()
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

-- 2) Attach trigger to send logs to ELK
CREATE TRIGGER elk_log_trigger
AFTER INSERT
ON logs.notification_log
FOR EACH ROW
EXECUTE FUNCTION monitoring.send_logs_to_elk();
