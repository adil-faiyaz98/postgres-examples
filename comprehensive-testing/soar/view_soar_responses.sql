\c db_dev;

-- View SOAR-triggered security responses in the last 7 days
SELECT * FROM soar.soar_action_logs
WHERE action_timestamp >= NOW() - INTERVAL '7 days'
ORDER BY action_timestamp DESC;

-- View all PostgreSQL users disabled by SOAR automation
SELECT * FROM soar.soar_action_logs
WHERE action_type = 'Disable User Account'
ORDER BY action_timestamp DESC;

-- View AI-flagged high-risk IPs blocked by SOAR
SELECT details->>'ip_address', action_timestamp
FROM soar.soar_action_logs
WHERE action_type = 'Block High-Risk IP'
ORDER BY action_timestamp DESC;
