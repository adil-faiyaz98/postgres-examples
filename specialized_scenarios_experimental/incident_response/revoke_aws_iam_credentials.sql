\c db_dev;

-- Retrieve the last 50 AI-detected security threats
SELECT * FROM logs.notification_log
WHERE event_type IN ('SQL Injection Attempt', 'Suspicious Login', 'Privilege Escalation Attempt')
ORDER BY logged_at DESC
LIMIT 50;

-- Identify the top users with failed login attempts
SELECT logged_by, COUNT(*) AS failed_logins
FROM logs.notification_log
WHERE event_type = 'Suspicious Login'
AND logged_at >= NOW() - INTERVAL '7 days'
GROUP BY logged_by
HAVING COUNT(*) > 5
ORDER BY failed_logins DESC;

-- Detect unusual query execution patterns
SELECT event_type, details->>'query', details->>'execution_time'
FROM logs.notification_log
WHERE event_type = 'Abnormal Query Pattern'
AND details->>'execution_time'::NUMERIC > 5000
ORDER BY logged_at DESC;

-- Analyze privilege escalation attempts over time
SELECT logged_at::DATE, COUNT(*) AS escalation_attempts
FROM logs.notification_log
WHERE event_type = 'Privilege Escalation Attempt'
AND logged_at >= NOW() - INTERVAL '30 days'
GROUP BY logged_at::DATE
ORDER BY logged_at DESC;
