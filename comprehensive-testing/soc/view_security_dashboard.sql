\c db_dev;

-- View the last 50 AI-detected PostgreSQL security events
SELECT * FROM logs.notification_log
WHERE event_type IN ('SQL Injection Attempt', 'Suspicious Login', 'Privilege Escalation Attempt', 'AI-Predicted Insider Threat')
ORDER BY logged_at DESC
LIMIT 50;

-- Identify top users with failed login attempts flagged by AI
SELECT user_id, COUNT(*) AS failed_logins
FROM logs.notification_log
WHERE event_type = 'Suspicious Login'
AND logged_at >= NOW() - INTERVAL '7 days'
GROUP BY user_id
HAVING COUNT(*) > 5
ORDER BY failed_logins DESC;

-- Analyze AI-predicted SQL injection attempts
SELECT event_type, user_id, details->>'query', detected_anomaly
FROM ml.anomaly_predictions
WHERE event_type = 'SQL Injection Attempt'
ORDER BY detected_at DESC;

-- Forecast AI-driven threat trends over time
SELECT date_trunc('day', detected_at) AS day, COUNT(*) AS detected_anomalies
FROM ml.anomaly_predictions
WHERE detected_anomaly = TRUE
GROUP BY date_trunc('day', detected_at)
ORDER BY day DESC;
