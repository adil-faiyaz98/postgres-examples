\c db_dev;

-- 1) Function to prevent unauthorized changes to critical tables
CREATE OR REPLACE FUNCTION security.prevent_unauthorized_changes()
RETURNS TRIGGER AS $$
BEGIN
    IF current_user NOT IN ('app_user', 'admin_user') THEN
        -- Log unauthorized modification attempt
        INSERT INTO logging.central_notification_log (event_type, event_source, event_details, logged_by)
        VALUES ('Unauthorized Change Attempt', TG_TABLE_NAME, jsonb_build_object('user', current_user, 'action', TG_OP), current_user);

        RAISE EXCEPTION 'Unauthorized user % cannot modify %.', current_user, TG_TABLE_NAME;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ✅ 2) Attach trigger to prevent unauthorized changes to sensitive tables
CREATE TRIGGER prevent_unauthorized_customers_changes
BEFORE INSERT OR UPDATE OR DELETE
ON inventory.customers
FOR EACH ROW
EXECUTE FUNCTION security.prevent_unauthorized_changes();

CREATE TRIGGER prevent_unauthorized_orders_changes
BEFORE INSERT OR UPDATE OR DELETE
ON inventory.orders
FOR EACH ROW
EXECUTE FUNCTION security.prevent_unauthorized_changes();

-- 3) Function to log failed login attempts
CREATE OR REPLACE FUNCTION security.log_failed_logins()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO logging.central_notification_log (event_type, event_source, event_details, logged_by)
    VALUES ('Failed Login Attempt', 'auth.user_sessions', jsonb_build_object('user_id', NEW.user_id, 'ip_address', NEW.ip_address), NEW.user_email);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 4) Attach trigger to log failed login attempts
CREATE TRIGGER log_failed_logins
BEFORE INSERT
ON auth.failed_logins
FOR EACH ROW
EXECUTE FUNCTION security.log_failed_logins();
