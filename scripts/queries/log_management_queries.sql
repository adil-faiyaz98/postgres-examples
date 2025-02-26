\c db_dev;

-- View the last 50 security logs
SELECT * FROM logs.notification_log
ORDER BY logged_at DESC
LIMIT 50;

-- Count logs by event type
SELECT event_type, COUNT(*)
FROM logs.notification_log
GROUP BY event_type
ORDER BY COUNT(*) DESC;

-- Safely rotate PostgreSQL logs instead of deleting manually
SELECT pg_logfile_rotate();
