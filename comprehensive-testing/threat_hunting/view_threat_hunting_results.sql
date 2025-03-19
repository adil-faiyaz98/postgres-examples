\c db_dev;

-- View recent adversary tactics detected in PostgreSQL logs
SELECT * FROM threat_hunting.mitre_caldera_detections
ORDER BY detection_timestamp DESC
LIMIT 50;

-- View AWS Detective findings related to PostgreSQL users
SELECT * FROM threat_hunting.aws_detective_findings
ORDER BY finding_timestamp DESC
LIMIT 50;

-- View Google Chronicle-correlated PostgreSQL security threats
SELECT * FROM threat_hunting.google_chronicle_threats
ORDER BY detection_timestamp DESC
LIMIT 50;

-- View PostgreSQL accounts disabled due to threat hunting findings
SELECT * FROM soar.soar_action_logs
WHERE action_type = 'Disable User Account'
ORDER BY action_timestamp DESC;
