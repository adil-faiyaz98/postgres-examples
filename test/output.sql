\c db_dev;
BEGIN;
SELECT plan(3); -- Number of tests

-- 1) Verify PostgreSQL version
SELECT like(pg_catalog.version(), '%PostgreSQL%', 'PostgreSQL is running');

-- 2) Check if required schemas exist
SELECT has_schema('inventory'), 'Schema inventory exists';
SELECT has_schema('accounting'), 'Schema accounting exists';

-- 3) Verify if necessary extensions are installed
SELECT has_extension('uuid-ossp'), 'uuid-ossp extension is installed';
SELECT has_extension('pgcrypto'), 'pgcrypto extension is installed';

ROLLBACK;
\c db_dev;
BEGIN;
SELECT plan(4);

-- 1) Test UUID function for generating IDs
SELECT is(uuid_generate_v4()::TEXT ~ '^[a-f0-9-]+$', true, 'UUID function generates valid UUIDs');

-- 2) Test transaction partitioning function
SELECT is(
    (SELECT accounting.create_next_month_partition() IS NOT NULL),
    true,
    'Partition creation function executes successfully'
);

-- 3) Test user session management function
SELECT lives_ok(
    $$SELECT auth.start_user_session(uuid_generate_v4(), 'test@example.com', '30 minutes')$$,
    'User session starts successfully'
);

-- 4) Test partition cleanup function
SELECT lives_ok(
    $$SELECT accounting.cleanup_old_partitions()$$,
    'Partition cleanup function executes successfully'
);

ROLLBACK;
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
\c db_dev;
BEGIN;
SELECT plan(3);

-- 1) Test partition creation
SELECT lives_ok(
    $$SELECT accounting.create_next_month_partition()$$,
    'Partition creation function executes successfully'
);

-- 2) Ensure partition exists
SELECT results_eq(
    $$SELECT EXISTS(SELECT 1 FROM pg_tables WHERE tablename = 'transactions_' || to_char(NOW() + INTERVAL '1 month', 'YYYY_MM'))$$,
    $$SELECT true$$,
    'Next month’s partition is created successfully'
);

-- 3) Test partition cleanup
SELECT lives_ok(
    $$SELECT accounting.cleanup_old_partitions()$$,
    'Old partitions are removed successfully'
);

ROLLBACK;
\c db_dev;
BEGIN;
SELECT plan(3);

-- 1) Prevent negative total amounts in orders
SELECT throws_ok(
    $$INSERT INTO inventory.orders (order_id, customer_id, order_date, total_amount)
      SELECT uuid_generate_v4(), customer_id, NOW(), -50.00 FROM inventory.customers LIMIT 1$$,
    'new row for relation "orders" violates check constraint "chk_positive_amount"',
    'Constraint prevents negative order amounts'
);

-- 2) Prevent duplicate customer emails
SELECT throws_ok(
    $$INSERT INTO inventory.customers (customer_id, first_name, last_name, email, created_at)
      VALUES (uuid_generate_v4(), 'Duplicate', 'User', 'alice.smith@example.com', NOW())$$,
    'duplicate key value violates unique constraint "unique_customer_email"',
    'Constraint prevents duplicate emails'
);

-- 3) Ensure payments cannot be negative
SELECT throws_ok(
    $$INSERT INTO accounting.payments (payment_id, order_id, amount, paid_at)
      SELECT uuid_generate_v4(), order_id, -10.00, NOW() FROM inventory.orders LIMIT 1$$,
    'new row for relation "payments" violates check constraint "chk_non_negative_payment"',
    'Constraint prevents negative payments'
);

ROLLBACK;
\c db_dev;

-- Install pgTAP if not already installed
CREATE EXTENSION IF NOT EXISTS pgtap;

-- Create a test schema to isolate test objects
CREATE SCHEMA IF NOT EXISTS test AUTHORIZATION postgres;

-- Grant required privileges for testing
GRANT USAGE ON SCHEMA test TO app_user, readonly_user;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA test TO app_user;
\c db_dev;
BEGIN;
SELECT plan(6);

-- 1) Ensure `chk_positive_amount` prevents negative order amounts
SELECT throws_ok(
    $$INSERT INTO inventory.orders (order_id, customer_id, order_date, total_amount)
      SELECT uuid_generate_v4(), customer_id, NOW(), -100.00 FROM inventory.customers LIMIT 1$$,
    'new row for relation "orders" violates check constraint "chk_positive_amount"',
    'Constraint prevents negative order amounts'
);

-- 2) Ensure `chk_valid_email` prevents invalid email format
SELECT throws_ok(
    $$INSERT INTO inventory.customers (customer_id, first_name, last_name, email, created_at)
      VALUES (uuid_generate_v4(), 'Invalid', 'Email', 'invalid-email', NOW())$$,
    'new row for relation "customers" violates check constraint "chk_valid_email"',
    'Constraint prevents invalid email format'
);

-- 3) Prevent duplicate email constraint
SELECT throws_ok(
    $$INSERT INTO inventory.customers (customer_id, first_name, last_name, email, created_at)
      VALUES (uuid_generate_v4(), 'Duplicate', 'User', 'alice.smith@example.com', NOW())$$,
    'duplicate key value violates unique constraint',
    'Unique constraint prevents duplicate emails'
);

-- 4) Ensure `chk_non_negative_payment` prevents negative payments
SELECT throws_ok(
    $$INSERT INTO accounting.payments (payment_id, order_id, amount, paid_at)
      SELECT uuid_generate_v4(), order_id, -10.00, NOW() FROM inventory.orders LIMIT 1$$,
    'new row for relation "payments" violates check constraint "chk_non_negative_payment"',
    'Constraint prevents negative payment amounts'
);

-- 5) Ensure foreign key constraint prevents orphaned orders
SELECT throws_ok(
    $$INSERT INTO inventory.orders (order_id, customer_id, order_date, total_amount)
      VALUES (uuid_generate_v4(), uuid_generate_v4(), NOW(), 99.99)$$,
    'insert or update on table "orders" violates foreign key constraint',
    'Foreign key constraint prevents orders without valid customers'
);

-- 6) Ensure valid partition assignment for transactions
SELECT is(
    (SELECT txn_date FROM accounting.transactions ORDER BY txn_date DESC LIMIT 1) IS NOT NULL,
    true,
    'Transaction partitions are correctly assigned'
);

ROLLBACK;
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
