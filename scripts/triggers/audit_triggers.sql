\c db_dev;

-- 1) Create an audit log table for all table modifications
CREATE TABLE IF NOT EXISTS logs.table_audit_log (
    log_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    table_name TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('INSERT', 'UPDATE', 'DELETE')),
    row_data JSONB,
    changed_by TEXT NOT NULL DEFAULT current_user,
    changed_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2) Generic logging function for tracking data changes
CREATE OR REPLACE FUNCTION logs.record_table_changes()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO logs.table_audit_log (table_name, action, row_data, changed_by)
    VALUES (
        TG_TABLE_NAME,
        TG_OP,
        CASE WHEN TG_OP = 'DELETE' THEN row_to_json(OLD) ELSE row_to_json(NEW) END,
        current_user
    );
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 3) Attach trigger to inventory.customers (logs updates and deletions)
CREATE TRIGGER audit_customers_changes
AFTER INSERT OR UPDATE OR DELETE
ON inventory.customers
FOR EACH ROW
EXECUTE FUNCTION logs.record_table_changes();

-- 4) Attach trigger to inventory.orders (logs updates and deletions)
CREATE TRIGGER audit_orders_changes
AFTER INSERT OR UPDATE OR DELETE
ON inventory.orders
FOR EACH ROW
EXECUTE FUNCTION logs.record_table_changes();
