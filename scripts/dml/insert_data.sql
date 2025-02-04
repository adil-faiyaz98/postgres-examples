\c db_dev;
BEGIN;

-- Insert Customers
INSERT INTO inventory.customers (customer_id, first_name, last_name, email, created_at)
VALUES
    (uuid_generate_v4(), 'Alice', 'Smith', 'alice.smith@example.com', NOW()),
    (uuid_generate_v4(), 'Bob', 'Johnson', 'bob.johnson@example.com', NOW()),
    (uuid_generate_v4(), 'Charlie', 'Brown', 'charlie.brown@example.com', NOW());

-- Insert Products
INSERT INTO inventory.products (product_id, name, categories, metadata, created_at)
VALUES
    (uuid_generate_v4(), 'Laptop', ARRAY['Electronics'], '{"brand": "Dell"}'::jsonb, NOW()),
    (uuid_generate_v4(), 'Phone', ARRAY['Electronics'], '{"brand": "Apple"}'::jsonb, NOW());

-- Insert Orders (Linked to Customers)
INSERT INTO inventory.orders (order_id, customer_id, order_date, total_amount)
SELECT uuid_generate_v4(), customer_id, NOW(), 199.99
FROM inventory.customers WHERE email = 'alice.smith@example.com';

-- Insert Transactions (for partitioning validation)
INSERT INTO accounting.transactions (transaction_id, txn_date, amount)
VALUES
    (uuid_generate_v4(), '2024-01-01', 500.00),
    (uuid_generate_v4(), '2024-02-01', 750.00),
    (uuid_generate_v4(), CURRENT_DATE - INTERVAL '1 day', 320.75),
    (uuid_generate_v4(), CURRENT_DATE, 100.00);

COMMIT;
