\c db_dev;
BEGIN;
SELECT plan(4);

-- 1) Check that users can only access their own data
SET SESSION app.current_user_id = '123e4567-e89b-12d3-a456-426614174000';

SELECT throws_ok(
    $$SELECT * FROM inventory.customers WHERE customer_id != current_setting('app.current_user_id')::uuid$$,
    'permission denied for relation customers',
    'RLS prevents unauthorized SELECT queries'
);

-- 2) Check that users cannot update another user’s record
SELECT throws_ok(
    $$UPDATE inventory.customers SET last_name = 'Hacker' WHERE customer_id != current_setting('app.current_user_id')::uuid$$,
    'permission denied for relation customers',
    'RLS prevents unauthorized UPDATE queries'
);

-- 3) Check that users cannot delete another user’s record
SELECT throws_ok(
    $$DELETE FROM inventory.customers WHERE customer_id != current_setting('app.current_user_id')::uuid$$,
    'permission denied for relation customers',
    'RLS prevents unauthorized DELETE queries'
);

-- 4) Ensure users can update their own records
SELECT lives_ok(
    $$UPDATE inventory.customers SET last_name = 'Updated' WHERE customer_id = current_setting('app.current_user_id')::uuid$$,
    'Users can update their own records'
);

ROLLBACK;
