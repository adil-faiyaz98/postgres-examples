\c db_dev;

-- 1) Create function to remove old notification logging
CREATE OR REPLACE FUNCTION logs.cleanup_old_notification_logs()
RETURNS VOID AS $$
BEGIN
    DELETE FROM logs.notification_log WHERE logged_at < NOW() - INTERVAL '90 days';
    PERFORM pg_notify('log_cleanup', 'Deleted notification logging older than 90 days');
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Schedule automatic log table cleanup (Runs every Sunday at 1 AM)
SELECT cron.schedule('0 1 * * 0', 'SELECT logging.cleanup_old_notification_logs();');
