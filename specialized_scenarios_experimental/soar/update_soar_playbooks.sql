\c db_dev;

-- 1) Create function to update SOAR security playbooks based on AI threat analysis
CREATE OR REPLACE FUNCTION soar.update_soar_playbooks()
RETURNS VOID AS $$
BEGIN
    -- Identify new threats from MITRE ATT&CK and AWS GuardDuty
    INSERT INTO soar.soar_playbook_updates (playbook_id, threat_intelligence_source, action_type, severity_level, last_updated)
    SELECT
        attack_id,
        'MITRE ATT&CK',
        'Adjust Privilege Escalation Handling',
        'HIGH',
        NOW()
    FROM threat_intelligence.mitre_attack_mapping
    WHERE last_updated >= NOW() - INTERVAL '30 days';

    INSERT INTO soar.soar_playbook_updates (playbook_id, threat_intelligence_source, action_type, severity_level, last_updated)
    SELECT
        finding_id,
        'AWS GuardDuty',
        'Automate Blocking of Malicious IPs',
        'CRITICAL',
        NOW()
    FROM threat_intelligence.aws_guardduty_findings
    WHERE timestamp >= NOW() - INTERVAL '30 days';

    -- Log playbook updates
    INSERT INTO logs.notification_log (event_type, event_source, details, logged_by, logged_at)
    VALUES ('SOAR Playbook Update', 'soar.update_soar_playbooks', json_build_object('timestamp', NOW()), 'system', NOW());
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Automate AI-driven SOAR playbook updates every 12 hours
SELECT cron.schedule('0 */12 * * *', 'SELECT soar.update_soar_playbooks();');
