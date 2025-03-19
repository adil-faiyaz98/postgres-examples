\c db_dev;

-- 1) Create function to send security logs to Datadog AI anomaly detection
CREATE OR REPLACE FUNCTION ml.send_logs_to_datadog_ai()
RETURNS TRIGGER AS $$
DECLARE datadog_ai_url TEXT := 'https://api.datadoghq.com/api/v1/events';
DECLARE datadog_api_key TEXT := 'your-datadog-api-key';
DECLARE log_payload TEXT;
BEGIN
    log_payload := json_build_object(
        'title', 'AI Security Alert: Abnormal PostgreSQL Activity Detected!',
        'text', json_build_object(
            'event_type', NEW.event_type,
            'event_source', NEW.event_source,
            'details', NEW.details,
            'logged_by', NEW.logged_by,
            'logged_at', NEW.logged_at
        ),
        'alert_type', 'warning'
    )::TEXT;

    -- Send log data to Datadog AI
    PERFORM http_post(datadog_ai_url || '?api_key=' || datadog_api_key, 'application/json', log_payload);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Attach trigger to send AI-analyzed logs to Datadog
CREATE TRIGGER datadog_ai_behavior_trigger
AFTER INSERT
ON logs.notification_log
FOR EACH ROW
WHEN (NEW.event_type IN ('Suspicious Login', 'Privilege Escalation Attempt', 'Abnormal Query Pattern'))
EXECUTE FUNCTION ml.send_logs_to_datadog_ai();
