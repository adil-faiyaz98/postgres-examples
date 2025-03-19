\c db_dev;

-- View AI-detected security anomalies that were validated by SOAR
SELECT ap.*, sr.action_type, sr.executed_by
FROM ml.anomaly_predictions ap
JOIN feedback_loop.soar_security_responses sr
ON ap.user_id = sr.user_id
WHERE ap.detected_anomaly = TRUE
ORDER BY ap.detected_at DESC
LIMIT 50;

-- Identify users who triggered multiple SOAR security actions
SELECT user_id, COUNT(*) AS security_actions
FROM feedback_loop.soar_security_responses
GROUP BY user_id
HAVING COUNT(*) > 3
ORDER BY security_actions DESC;

-- Detect IP addresses that were blocked multiple times
SELECT ip_address, COUNT(*) AS blocks
FROM feedback_loop.soar_security_responses
WHERE action_type = 'Block IP'
GROUP BY ip_address
HAVING COUNT(*) > 3
ORDER BY blocks DESC;

-- Analyze how security policies changed over time due to AI findings
SELECT logged_at, event_type, details
FROM logs.notification_log
WHERE event_type = 'AI Security Policy Update'
ORDER BY logged_at DESC;
