\c db_dev;

-- 1) Create an audit log table for all table modifications
CREATE TABLE IF NOT EXISTS logs.table_audit_log (
    log_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    table_name TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('INSERT', 'UPDATE', 'DELETE')),
    row_data JSONB,
    changed_by TEXT NOT NULL DEFAULT current_user,
    ip_address TEXT DEFAULT NULL,
    changed_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2) Generic logging function for tracking data changes
CREATE OR REPLACE FUNCTION logs.record_table_changes()
RETURNS TRIGGER AS $$
DECLARE user_ip TEXT;
BEGIN
    -- Capture user IP from pg_stat_activity
    SELECT client_addr INTO user_ip
    FROM pg_stat_activity
    WHERE pid = pg_backend_pid();

    INSERT INTO logs.table_audit_log (table_name, action, row_data, changed_by, ip_address)
    VALUES (
        TG_TABLE_NAME,
        TG_OP,
        jsonb_build_object('id', OLD.customer_id, 'changes', row_to_json(NEW) - row_to_json(OLD)),
        current_user,
        COALESCE(user_ip, 'unknown')
    );

    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 3) Attach trigger to inventory.customers (logs updates and deletions)
CREATE TRIGGER audit_customers_changes
AFTER INSERT OR UPDATE OR DELETE
ON inventory.customers
FOR EACH ROW
WHEN (OLD IS DISTINCT FROM NEW)
EXECUTE FUNCTION logs.record_table_changes();

-- 4) Attach trigger to inventory.orders (logs updates and deletions)
CREATE TRIGGER audit_orders_changes
AFTER INSERT OR UPDATE OR DELETE
ON inventory.orders
FOR EACH ROW
WHEN (OLD IS DISTINCT FROM NEW)
EXECUTE FUNCTION logs.record_table_changes();
