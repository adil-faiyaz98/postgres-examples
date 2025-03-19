\c db_dev;

-- 1) Install Prometheus PostgreSQL extension (if not installed)
CREATE EXTENSION IF NOT EXISTS pg_prometheus;

-- 2) Create function to send AI-detected security logs to Prometheus for Grafana monitoring
CREATE OR REPLACE FUNCTION soc.send_logs_to_prometheus()
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

-- 3) Attach trigger to send PostgreSQL security logs to Prometheus
CREATE TRIGGER grafana_soc_log_trigger
AFTER INSERT
ON logs.notification_log
FOR EACH ROW
WHEN (NEW.event_type IN ('SQL Injection Attempt', 'Suspicious Login', 'Privilege Escalation Attempt', 'AI-Predicted Insider Threat'))
EXECUTE FUNCTION soc.send_logs_to_prometheus();
