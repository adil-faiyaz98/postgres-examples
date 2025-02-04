\c db_dev;

-- 1) Create table to correlate PostgreSQL security incidents with SOAR and threat intelligence feeds
CREATE TABLE IF NOT EXISTS irp.security_incident_correlation (
    correlation_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_type TEXT NOT NULL,
    related_user_id UUID,
    related_ip TEXT,
    threat_intelligence_source TEXT,
    correlation_timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- 2) Function to correlate PostgreSQL security incidents with threat intelligence data
CREATE OR REPLACE FUNCTION irp.correlate_security_incidents()
RETURNS VOID AS $$
BEGIN
    -- Correlate PostgreSQL incidents with SOAR security responses
    INSERT INTO irp.security_incident_correlation (incident_type, related_user_id, related_ip, threat_intelligence_source)
    SELECT
        sl.action_type,
        sl.user_id,
        sl.details->>'ip_address',
        'SOAR Security Response'
    FROM soar.soar_action_logs sl
    WHERE sl.action_timestamp >= NOW() - INTERVAL '30 days';

    -- Correlate PostgreSQL incidents with AWS GuardDuty threat intelligence
    INSERT INTO irp.security_incident_correlation (incident_type, related_user_id, related_ip, threat_intelligence_source)
    SELECT
        finding_id,
        user_id,
        ip_address,
        'AWS GuardDuty'
    FROM threat_intelligence.aws_guardduty_findings
    WHERE finding_timestamp >= NOW() - INTERVAL '30 days';

    -- Correlate PostgreSQL incidents with Google Chronicle threat intelligence
    INSERT INTO irp.security_incident_correlation (incident_type, related_user_id, related_ip, threat_intelligence_source)
    SELECT
        correlated_threat,
        user_id,
        ip_address,
        'Google Chronicle'
    FROM threat_intelligence.google_chronicle_threats
    WHERE detection_timestamp >= NOW() - INTERVAL '30 days';

    -- Log security correlation results
    INSERT INTO logs.notification_log (event_type, event_source, details, logged_by, logged_at)
    VALUES ('Security Incident Correlation', 'irp.correlate_security_incidents', json_build_object('timestamp', NOW()), 'system', NOW());
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 3) Automate PostgreSQL security incident correlation every 24 hours
SELECT cron.schedule('0 0 * * *', 'SELECT irp.correlate_security_incidents();');
