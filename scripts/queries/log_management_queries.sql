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

-- Manually delete old logs (if needed)
DELETE FROM logs.notification_log WHERE logged_at < NOW() - INTERVAL '6 months';

-- Check PostgreSQL log directory for large log files
SELECT pg_ls_dir('/var/log/postgresql');

-- Manually delete a specific old log file
EXECUTE format('rm -f /var/log/postgresql/postgresql-2023-01-01.log');
