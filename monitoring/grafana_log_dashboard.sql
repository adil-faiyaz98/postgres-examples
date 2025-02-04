\c db_dev;

-- 1) Install pg_prometheus extension (if not installed)
CREATE EXTENSION IF NOT EXISTS pg_prometheus;

-- ) Create a function to send logs to Prometheus for Grafana
CREATE OR REPLACE FUNCTION monitoring.send_logs_to_prometheus()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO prometheus.logs (
        log_id, event_type, event_source, details, logged_by, logged_at
    )
    VALUES (
        NEW.log_id, NEW.event_type, NEW.event_source, NEW.details, NEW.logged_by, NEW.logged_at
    );

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 3) Attach trigger to send logs to Prometheus
CREATE TRIGGER grafana_log_trigger
AFTER INSERT
ON logs.notification_log
FOR EACH ROW
EXECUTE FUNCTION monitoring.send_logs_to_prometheus();
