\c db_dev;

-- Retrieve the most recent AI-detected security anomalies
SELECT * FROM logs.notification_log
WHERE event_type IN ('SQL Injection Attempt', 'Suspicious Login', 'Account Locked')
ORDER BY logged_at DESC
LIMIT 50;

-- Identify login anomalies (e.g., failed login attempts per user)
SELECT logged_by, COUNT(*) AS login_attempts
FROM logs.notification_log
WHERE event_type = 'Suspicious Login'
AND logged_at >= NOW() - INTERVAL '7 days'
GROUP BY logged_by
HAVING COUNT(*) > 5
ORDER BY login_attempts DESC;

-- Detect abnormal query execution times
SELECT event_type, details->>'query', details->>'execution_time'
FROM logs.notification_log
WHERE event_type = 'Slow Query Detected'
AND details->>'execution_time'::NUMERIC > 5000
ORDER BY logged_at DESC;

-- Analyze privilege escalation attempts
SELECT * FROM logs.notification_log
WHERE event_type = 'Privilege Escalation Attempt'
AND logged_at >= NOW() - INTERVAL '30 days';
