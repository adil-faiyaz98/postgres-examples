\c db_dev;

-- Function to delete old logs
CREATE OR REPLACE FUNCTION logs.cleanup_old_logs()
RETURNS VOID AS $$
BEGIN
    DELETE FROM logs.notification_log WHERE logged_at < NOW() - INTERVAL current_setting('custom.log_retention_days', TRUE) || ' days';
    PERFORM pg_notify('log_cleanup', 'Deleted logs older than ' || current_setting('custom.log_retention_days', TRUE) || ' days');
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Schedule automatic log cleanup using pg_cron
SELECT cron.schedule('0 0 * * *', 'SELECT logs.cleanup_old_logs();');
