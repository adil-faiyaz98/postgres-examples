\c db_dev;

-- 1) Create function to send security logs to SIEM tools (Splunk, Datadog, ELK)
CREATE OR REPLACE FUNCTION monitoring.send_logs_to_siem()
RETURNS TRIGGER AS $$
DECLARE siem_api_url TEXT := 'https://siem-server/api/security-alerts';
DECLARE siem_payload TEXT;
BEGIN
    siem_payload := json_build_object(
        'event_type', NEW.event_type,
        'event_source', NEW.event_source,
        'details', NEW.details,
        'logged_by', NEW.logged_by,
        'logged_at', NEW.logged_at
    )::TEXT;

    -- Send security alert to SIEM system
    PERFORM http_post(siem_api_url, 'application/json', siem_payload);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Attach trigger to escalate security incidents to SIEM
CREATE TRIGGER siem_security_alert_trigger
AFTER INSERT
ON logs.notification_log
FOR EACH ROW
WHEN (NEW.event_type IN ('SQL Injection Attempt', 'Suspicious Login', 'Privilege Escalation Attempt', 'User Suspended'))
EXECUTE FUNCTION monitoring.send_logs_to_siem();
