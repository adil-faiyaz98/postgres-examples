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
