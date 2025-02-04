\c db_dev;

-- 1) Enable detailed logging for important security events
ALTER SYSTEM SET log_statement = 'mod'; -- Logs all INSERT, UPDATE, DELETE
ALTER SYSTEM SET log_min_duration_statement = 500; -- Logs queries taking longer than 500ms
ALTER SYSTEM SET log_checkpoints = on;
ALTER SYSTEM SET log_connections = on;
ALTER SYSTEM SET log_disconnections = on;
ALTER SYSTEM SET log_duration = on;
ALTER SYSTEM SET log_error_verbosity = 'default';
ALTER SYSTEM SET log_lock_waits = on;

-- 2) Set up log rotation settings
ALTER SYSTEM SET logging_collector = on;
ALTER SYSTEM SET log_directory = '/var/log/postgresql';
ALTER SYSTEM SET log_filename = 'postgresql-%Y-%m-%d.log';
ALTER SYSTEM SET log_rotation_age = '1d'; -- Rotate logging daily
ALTER SYSTEM SET log_rotation_size = '100MB'; -- Rotate if log exceeds 100MB
ALTER SYSTEM SET log_truncate_on_rotation = on;

-- 3) Reload configuration to apply changes
SELECT pg_reload_conf();
