\c db_dev;

-- 1) Create function to send AI-predicted security incidents to SIEM playbooks
CREATE OR REPLACE FUNCTION security.escalate_ai_security_incident_to_siem()
RETURNS TRIGGER AS $$
DECLARE siem_api_url TEXT := 'https://siem-server/api/execute-playbook';
DECLARE playbook_payload TEXT;
BEGIN
    playbook_payload := json_build_object(
        'event_type', NEW.event_type,
        'user_id', NEW.details->>'user_id',
        'ip_address', NEW.details->>'ip_address',
        'action', 'execute-security-response',
        'timestamp', NOW()
    )::TEXT;

    -- Send security alert to SIEM playbook execution
    PERFORM http_post(siem_api_url, 'application/json', playbook_payload);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Attach trigger to escalate AI-detected threats to SIEM for response handling
CREATE TRIGGER siem_ai_security_escalation_trigger
AFTER INSERT
ON ml.anomaly_predictions
FOR EACH ROW
WHEN (NEW.detected_anomaly = TRUE)
EXECUTE FUNCTION security.escalate_ai_security_incident_to_siem();
