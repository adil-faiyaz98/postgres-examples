\c db_dev;

-- View the last 50 security incidents
SELECT * FROM logs.notification_log
WHERE event_type IN ('SQL Injection Attempt', 'Suspicious Login', 'Account Locked')
ORDER BY logged_at DESC
LIMIT 50;

-- Count the number of SQL injection attempts in the last 24 hours
SELECT COUNT(*) AS sql_injection_attempts
FROM logs.notification_log
WHERE event_type = 'SQL Injection Attempt'
AND logged_at >= NOW() - INTERVAL '24 hours';

-- Retrieve all security alerts related to specific users
SELECT * FROM logs.notification_log
WHERE event_type IN ('SQL Injection Attempt', 'Suspicious Login', 'Account Locked')
AND details->>'user_id' = '123e4567-e89b-12d3-a456-426614174000';

-- Retrieve all critical security incidents in the last 7 days
SELECT * FROM logs.notification_log
WHERE event_type IN ('SQL Injection Attempt', 'Suspicious Login', 'Account Locked')
AND logged_at >= NOW() - INTERVAL '7 days';
