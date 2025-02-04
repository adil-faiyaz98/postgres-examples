\c db_dev;

-- 1) Create an audit log table for order modifications
CREATE TABLE IF NOT EXISTS inventory.orders_log (
    log_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    order_id UUID NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('INSERT', 'UPDATE', 'DELETE')),
    changed_by TEXT NOT NULL DEFAULT current_user,
    changed_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2) Create function to log changes to the orders table
CREATE OR REPLACE FUNCTION inventory.log_order_changes()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO inventory.orders_log (order_id, action, changed_by)
    VALUES (COALESCE(NEW.order_id, OLD.order_id), TG_OP, current_user);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = inventory;

-- 3) Create trigger to log changes on order modifications (updates or deletions)
CREATE TRIGGER orders_audit
AFTER INSERT OR UPDATE OR DELETE
ON inventory.orders
FOR EACH ROW
EXECUTE FUNCTION inventory.log_order_changes();

-- 4) Prevent unauthorized order modifications
CREATE OR REPLACE FUNCTION inventory.prevent_order_modifications()
RETURNS TRIGGER AS $$
BEGIN
    IF current_user NOT IN ('app_user', 'admin_user') THEN
        RAISE EXCEPTION 'Unauthorized user % cannot modify orders.', current_user;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = inventory;

-- 5) Attach trigger to prevent unauthorized changes to orders
CREATE TRIGGER prevent_order_changes
BEFORE UPDATE OR DELETE
ON inventory.orders
FOR EACH ROW
EXECUTE FUNCTION inventory.prevent_order_modifications();

-- 6) Prevent unauthorized deletions in key tables
CREATE OR REPLACE FUNCTION inventory.prevent_critical_data_deletion()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Deleting critical data is not allowed in production!';
    RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = inventory;

-- 7) Attach trigger to prevent deletions in critical tables
CREATE TRIGGER prevent_customer_deletions
BEFORE DELETE
ON inventory.customers
FOR EACH ROW
EXECUTE FUNCTION inventory.prevent_critical_data_deletion();

CREATE TRIGGER prevent_product_deletions
BEFORE DELETE
ON inventory.products
FOR EACH ROW
EXECUTE FUNCTION inventory.prevent_critical_data_deletion();
