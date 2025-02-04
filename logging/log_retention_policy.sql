\c db_dev;

-- 1) Create function to delete old logging
CREATE OR REPLACE FUNCTION logs.cleanup_old_logs()
RETURNS VOID AS $$
BEGIN
    PERFORM pg_notify('log_cleanup', 'Deleting logging older than 30 days');

    -- Delete logging older than 30 days
    EXECUTE format('find /var/log/postgresql -name ''postgresql-*.log'' -mtime +30 -delete');
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Schedule automatic log cleanup using pg_cron (Runs daily at midnight)
SELECT cron.schedule('0 0 * * *', 'SELECT logging.cleanup_old_logs();');
