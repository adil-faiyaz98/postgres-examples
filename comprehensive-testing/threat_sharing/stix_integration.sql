\c db_dev;

-- 1) Create table to store PostgreSQL security incidents formatted as STIX objects
CREATE TABLE IF NOT EXISTS threat_sharing.stix_security_incidents (
    stix_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    type TEXT NOT NULL DEFAULT 'indicator', -- STIX Indicator Type
    created TIMESTAMPTZ DEFAULT NOW(),
    modified TIMESTAMPTZ DEFAULT NOW(),
    labels TEXT[],  -- Labels like "Malware", "Phishing"
    pattern TEXT,   -- STIX Pattern for matching threats
    confidence INTEGER DEFAULT 50,  -- Confidence score (0-100)
    external_references JSONB  -- Reference to external threat reports
);

-- 2) Function to format PostgreSQL security incidents as STIX indicators
CREATE OR REPLACE FUNCTION threat_sharing.format_stix_security_incident()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO threat_sharing.stix_security_incidents (labels, pattern, confidence, external_references)
    SELECT
        ARRAY['SQL Injection', 'Privilege Escalation'],
        format("[network-traffic:src_ref = '%s' AND user-account:user_id = '%s']", NEW.details->>'ip_address', NEW.details->>'user_id'),
        75,
        jsonb_build_object('source', 'PostgreSQL AI', 'description', 'AI-detected database security event')
    FROM logs.notification_log
    WHERE event_type IN ('SQL Injection Attempt', 'Suspicious Login', 'Privilege Escalation Attempt');

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 3) Attach trigger to format PostgreSQL security logs into STIX objects
CREATE TRIGGER stix_format_security_incident_trigger
AFTER INSERT
ON logs.notification_log
FOR EACH ROW
WHEN (NEW.event_type IN ('SQL Injection Attempt', 'Suspicious Login', 'Privilege Escalation Attempt'))
EXECUTE FUNCTION threat_sharing.format_s
