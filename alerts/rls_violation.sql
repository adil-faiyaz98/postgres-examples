\c db_dev;

-- 1) Create a function to send alerts via NOTIFY
CREATE OR REPLACE FUNCTION auth.notify_rls_violation()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM pg_notify('rls_violation', json_build_object(
        'user', current_user,
        'table', TG_TABLE_NAME,
        'operation', TG_OP,
        'attempted_access_time', NOW()
    )::TEXT);

    RAISE EXCEPTION 'Unauthorized access detected on table: % by user: %', TG_TABLE_NAME, current_user;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Apply RLS alert trigger to sensitive tables
CREATE TRIGGER customers_rls_violation
BEFORE SELECT OR UPDATE OR DELETE
ON inventory.customers
FOR EACH ROW
EXECUTE FUNCTION auth.notify_rls_violation();

CREATE TRIGGER orders_rls_violation
BEFORE SELECT OR UPDATE OR DELETE
ON inventory.orders
FOR EACH ROW
EXECUTE FUNCTION auth.notify_rls_violation();
