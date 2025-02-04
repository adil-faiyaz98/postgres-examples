\c db_dev;

-- 1) Create function to send security logs to AWS Security Hub
CREATE OR REPLACE FUNCTION monitoring.send_logs_to_aws_security_hub()
RETURNS TRIGGER AS $$
DECLARE security_hub_api_url TEXT := 'https://securityhub.amazonaws.com/v1/security-events';
DECLARE log_payload TEXT;
BEGIN
    log_payload := json_build_object(
        'Title', 'PostgreSQL Security Alert',
        'Description', json_build_object(
            'event_type', NEW.event_type,
            'event_source', NEW.event_source,
            'details', NEW.details,
            'logged_by', NEW.logged_by,
            'logged_at', NEW.logged_at
        ),
        'Severity', 'HIGH',
        'ResourceType', 'PostgreSQL Database'
    )::TEXT;

    -- Send log data to AWS Security Hub
    PERFORM http_post(security_hub_api_url, 'application/json', log_payload);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Attach trigger to send security alerts to AWS Security Hub
CREATE TRIGGER aws_security_hub_alert_trigger
AFTER INSERT
ON logs.notification_log
FOR EACH ROW
WHEN (NEW.event_type IN ('SQL Injection Attempt', 'Suspicious Login', 'Privilege Escalation Attempt', 'User Suspended'))
EXECUTE FUNCTION monitoring.send_logs_to_aws_security_hub();
