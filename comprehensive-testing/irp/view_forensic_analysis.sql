\c db_dev;

-- View forensic evidence collected on PostgreSQL security incidents
SELECT * FROM irp.forensic_evidence
ORDER BY captured_at DESC
LIMIT 50;

-- View PostgreSQL security incidents correlated with SOAR security response
SELECT * FROM irp.security_incident_correlation
ORDER BY correlation_timestamp DESC
LIMIT 50;

-- View PostgreSQL users disabled due to security incidents
SELECT * FROM soar.soar_action_logs
WHERE action_type = 'Disable User Account'
ORDER BY action_timestamp DESC;

-- View high-risk IPs blocked due to PostgreSQL security findings
SELECT * FROM threat_intelligence.otx_threat_indicators
WHERE confidence_score > 0.9
ORDER BY last_seen DESC;
