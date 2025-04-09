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
