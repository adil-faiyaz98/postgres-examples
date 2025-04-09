\c db_dev;
BEGIN;
SELECT plan(4);

-- 1) Check if unauthorized users can modify data
SET SESSION AUTHORIZATION 'readonly_user';
SELECT throws_ok(
    $$UPDATE inventory.orders SET total_amount = 500.00 WHERE order_id = (SELECT order_id FROM inventory.orders LIMIT 1)$$,
    'Unauthorized user readonly_user cannot modify orders.',
    'Security policy prevents unauthorized updates'
);

-- 2) Check if unauthorized users can delete records
SELECT throws_ok(
    $$DELETE FROM inventory.customers WHERE email = 'alice.smith@example.com'$$,
    'Deleting critical data is not allowed in production!',
    'Security policy prevents unauthorized deletions'
);

-- 3) Check if Row-Level Security (RLS) is applied
SET SESSION AUTHORIZATION 'app_user';
SELECT throws_ok(
    $$SELECT * FROM inventory.customers WHERE email = 'admin@example.com'$$,
    'RLS policy prevents unauthorized access',
    'Row-Level Security (RLS) prevents data leaks'
);

ROLLBACK;
