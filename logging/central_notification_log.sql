\c db_dev;

-- Create a centralized logging table
CREATE TABLE IF NOT EXISTS logs.notification_log (
    log_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type TEXT NOT NULL,
    event_source TEXT NOT NULL,
    details JSONB NOT NULL,
    logged_by TEXT DEFAULT current_user,
    logged_at TIMESTAMPTZ DEFAULT NOW()
);

-- Ensure only specific roles can write to logs
GRANT INSERT ON logs.notification_log TO app_user;
GRANT SELECT ON logs.notification_log TO readonly_user;

-- Function to log events into the table
CREATE OR REPLACE FUNCTION logs.store_notification_log(
    p_event_type TEXT,
    p_event_source TEXT,
    p_details JSONB
)
RETURNS VOID AS $$
BEGIN
    INSERT INTO logs.notification_log (event_type, event_source, details)
    VALUES (p_event_type, p_event_source, p_details);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
