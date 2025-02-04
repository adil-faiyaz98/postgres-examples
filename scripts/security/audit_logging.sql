\c db_dev;

-- 1) Create a table for logging database audit events
CREATE TABLE IF NOT EXISTS logging.audit_log (
    log_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type TEXT NOT NULL CHECK (event_type IN ('INSERT', 'UPDATE', 'DELETE', 'FAILED_LOGIN', 'UNAUTHORIZED_ACCESS')),
    table_name TEXT NOT NULL,
    query TEXT NOT NULL,
    user TEXT NOT NULL DEFAULT current_user,
    event_timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- 2) Function to log all data modifications
CREATE OR REPLACE FUNCTION logging.record_table_changes()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO logging.audit_log (event_type, table_name, query, user)
    VALUES (
        TG_OP,
        TG_TABLE_NAME,
        current_query(),
        current_user
    );
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 3) Attach auditing triggers to critical tables
CREATE TRIGGER audit_customers_changes
AFTER INSERT OR UPDATE OR DELETE
ON inventory.customers
FOR EACH ROW
EXECUTE FUNCTION logging.record_table_changes();

CREATE TRIGGER audit_orders_changes
AFTER INSERT OR UPDATE OR DELETE
ON inventory.orders
FOR EACH ROW
EXECUTE FUNCTION logging.record_table_changes();

-- 4) Function to log failed login attempts
CREATE OR REPLACE FUNCTION logging.log_failed_logins()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO logging.audit_log (event_type, table_name, query, user)
    VALUES ('FAILED_LOGIN', 'auth.failed_logins', current_query(), current_user);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 5) Attach trigger to log failed logins
CREATE TRIGGER failed_login_audit
BEFORE INSERT
ON auth.failed_logins
FOR EACH ROW
EXECUTE FUNCTION logging.log_failed_logins();
