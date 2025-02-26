\c db_dev;

-- 1)Create a function to send alerts when business rules are violated
CREATE OR REPLACE FUNCTION inventory.alert_business_rule_violation()
RETURNS TRIGGER AS $$
BEGIN
    -- Notify about invalid business rule
    PERFORM pg_notify('business_rule_violation', json_build_object(
        'user', current_user,
        'table', TG_TABLE_NAME,
        'action', TG_OP,
        'violated_rule', 'Negative total amount',
        'timestamp', NOW()
    )::TEXT);

    RAISE EXCEPTION 'Order total cannot be negative!';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;


-- 2) Attach trigger to inventory.orders
CREATE TRIGGER prevent_negative_orders
BEFORE INSERT OR UPDATE
ON inventory.orders
FOR EACH ROW
WHEN (NEW.total_amount < 0)
EXECUTE FUNCTION inventory.alert_business_rule_violation();
