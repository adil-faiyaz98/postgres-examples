\c db_dev;

CREATE OR REPLACE FUNCTION auth.notify_rls_violation()
RETURNS TRIGGER AS $$
BEGIN
    -- Notify security logs
    PERFORM pg_notify('rls_violation', json_build_object(
        'user', current_user,
        'table', TG_TABLE_NAME,
        'operation', TG_OP,
        'attempted_access_time', NOW()
    )::TEXT);

    IF TG_OP IN ('UPDATE', 'DELETE') THEN
        RAISE EXCEPTION 'Unauthorized access detected on table: % by user: %', TG_TABLE_NAME, current_user;
    END IF;

    RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER customers_rls_violation
BEFORE UPDATE OR DELETE
ON inventory.customers
FOR EACH ROW
EXECUTE FUNCTION auth.notify_rls_violation();

CREATE TRIGGER orders_rls_violation
BEFORE UPDATE OR DELETE
ON inventory.orders
FOR EACH ROW
EXECUTE FUNCTION auth.notify_rls_violation();

