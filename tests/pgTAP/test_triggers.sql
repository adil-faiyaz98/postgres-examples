\c db_dev;
BEGIN;
SELECT plan(5); -- Number of tests

-- 1) Test `audit_triggers.sql` (Ensure table changes are logged)
INSERT INTO inventory.customers (customer_id, first_name, last_name, email, created_at)
VALUES (uuid_generate_v4(), 'John', 'Doe', 'john.doe@example.com', NOW());

UPDATE inventory.customers SET last_name = 'Smith' WHERE email = 'john.doe@example.com';

DELETE FROM inventory.customers WHERE email = 'john.doe@example.com';

SELECT is(
    (SELECT COUNT(*) FROM logs.table_audit_log WHERE table_name = 'inventory.customers' AND action = 'INSERT'),
    1, 'Audit trigger logs INSERT operations'
);

SELECT is(
    (SELECT COUNT(*) FROM logs.table_audit_log WHERE table_name = 'inventory.customers' AND action = 'UPDATE'),
    1, 'Audit trigger logs UPDATE operations'
);

SELECT is(
    (SELECT COUNT(*) FROM logs.table_audit_log WHERE table_name = 'inventory.customers' AND action = 'DELETE'),
    1, 'Audit trigger logs DELETE operations'
);

-- 2) Test partition triggers (Ensure partitions are created)
SELECT lives_ok(
    $$SELECT accounting.create_next_month_partition()$$,
    'Partition creation trigger executes successfully'
);

-- 3) Ensure security triggers prevent unauthorized access
SET SESSION AUTHORIZATION 'readonly_user';
SELECT throws_ok(
    $$UPDATE inventory.orders SET total_amount = 200.00 WHERE order_id = (SELECT order_id FROM inventory.orders LIMIT 1)$$,
    'Unauthorized user readonly_user cannot modify orders.',
    'Security trigger prevents unauthorized updates'
);

ROLLBACK;
