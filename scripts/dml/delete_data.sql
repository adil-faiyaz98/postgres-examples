\c db_dev;
BEGIN;

-- Log customer deletion before removing
INSERT INTO logging.audit_log (event_type, table_name, query, user)
SELECT 'DELETE', 'inventory.customers', json_build_object('customer_id', customer_id, 'email', email)::TEXT, current_user
FROM inventory.customers
WHERE email = 'alice.smith@securemail.com';

-- Delete Customer with Cascade (Ensures ON DELETE CASCADE)
DELETE FROM inventory.customers
WHERE email = 'alice.smith@securemail.com'
RETURNING *;

-- Log order deletion
INSERT INTO logging.audit_log (event_type, table_name, query, user)
SELECT 'DELETE', 'inventory.orders', json_build_object('order_id', order_id, 'total_amount', total_amount)::TEXT, current_user
FROM inventory.orders
WHERE customer_id NOT IN (SELECT customer_id FROM inventory.customers);

-- Delete Orphaned Orders
DELETE FROM inventory.orders
WHERE customer_id NOT IN (SELECT customer_id FROM inventory.customers)
RETURNING *;

-- Delete Old Transactions (Ensuring Partitions are Used)
DELETE FROM accounting.transactions
WHERE txn_date < NOW() - INTERVAL '2 years'
RETURNING *;

-- Rollback on error
EXCEPTION WHEN OTHERS THEN
    ROLLBACK;
    RAISE NOTICE 'Error in deletion process. Rolled back changes.';

COMMIT;
