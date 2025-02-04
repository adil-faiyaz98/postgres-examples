\c db_dev;

-- 1) Insert sample customers
INSERT INTO inventory.customers (customer_id, first_name, last_name, email, created_at)
VALUES
    (uuid_generate_v4(), 'Alice', 'Smith', 'alice.smith@example.com', NOW()),
    (uuid_generate_v4(), 'Bob', 'Johnson', 'bob.johnson@example.com', NOW()),
    (uuid_generate_v4(), 'Charlie', 'Brown', 'charlie.brown@example.com', NOW());

-- 2) Insert sample products
INSERT INTO inventory.products (product_id, name, categories, metadata, created_at)
VALUES
    (uuid_generate_v4(), 'Laptop', ARRAY['Electronics'], '{"brand": "Dell", "warranty": "2 years"}'::jsonb, NOW()),
    (uuid_generate_v4(), 'Smartphone', ARRAY['Electronics'], '{"brand": "Apple", "storage": "128GB"}'::jsonb, NOW()),
    (uuid_generate_v4(), 'Office Chair', ARRAY['Furniture'], '{"color": "Black", "adjustable": true}'::jsonb, NOW());

-- 3) Insert test orders linked to real customers
INSERT INTO inventory.orders (order_id, customer_id, order_date, total_amount)
SELECT uuid_generate_v4(), customer_id, NOW(), 199.99
FROM inventory.customers WHERE email = 'alice.smith@example.com';

-- 4) Insert sample payments linked to orders
INSERT INTO accounting.payments (payment_id, order_id, amount, paid_at)
SELECT uuid_generate_v4(), order_id, 199.99, NOW()
FROM inventory.orders WHERE total_amount = 199.99;

-- 5) Insert test transactions for partitioning verification
INSERT INTO accounting.transactions (transaction_id, txn_date, amount)
VALUES
    (uuid_generate_v4(), '2024-01-01', 500.00),
    (uuid_generate_v4(), '2024-02-01', 750.00),
    (uuid_generate_v4(), CURRENT_DATE - INTERVAL '1 day', 320.75), -- Recent transaction
    (uuid_generate_v4(), CURRENT_DATE, 100.00); -- Today's transaction

-- 6) Ensure transactions are spread across partitions
SELECT accounting.create_next_month_partition();
