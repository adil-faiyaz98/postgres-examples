\c db_dev;

-- 1) Create function to send AI-detected PostgreSQL security incidents to SOAR
CREATE OR REPLACE FUNCTION soar.trigger_soar_security_playbook()
RETURNS TRIGGER AS $$
DECLARE soar_api_url TEXT := 'https://soar-platform/api/execute-playbook';
DECLARE soar_payload TEXT;
BEGIN
    soar_payload := json_build_object(
        'incident_id', NEW.log_id,
        'event_type', NEW.event_type,
        'event_source', NEW.event_source,
        'details', NEW.details,
        'logged_by', NEW.logged_by,
        'logged_at', NEW.logged_at
    )::TEXT;

    -- Send security alert to SOAR platform
    PERFORM http_post(soar_api_url, 'application/json', soar_payload);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Attach trigger to escalate AI-detected threats to SOAR
CREATE TRIGGER soar_ai_security_trigger
AFTER INSERT
ON logs.notification_log
FOR EACH ROW
WHEN (NEW.event_type IN ('SQL Injection Attempt', 'Suspicious Login', 'Privilege Escalation Attempt', 'AI-Predicted Insider Threat'))
EXECUTE FUNCTION soar.trigger_soar_security_playbook();
