\c db_dev;

-- Enable detailed execution timing (temporarily for this session)
SET client_min_messages TO WARNING; -- Reduce noise in output
SET enable_seqscan = OFF; -- Force index usage for monitoring tuning

-- Checking query plan for customer lookup by email (Uses GIN Index)
EXPLAIN ANALYZE
SELECT customer_id, first_name, last_name
FROM inventory.customers
WHERE email = 'alice.smith@example.com';

-- Checking index usage for range-based order queries (Uses BRIN Index)
EXPLAIN ANALYZE
SELECT order_id, customer_id, total_amount
FROM inventory.orders
WHERE order_date >= NOW() - INTERVAL '1 month'
ORDER BY order_date DESC;

-- Checking GIN index effectiveness for JSONB search
EXPLAIN ANALYZE
SELECT product_id, name
FROM inventory.products
WHERE metadata @> '{"brand": "TechCorp"}';

-- Checking GiST index effectiveness for range queries on transactions
EXPLAIN ANALYZE
SELECT transaction_id, txn_date, amount
FROM accounting.transactions
WHERE amount <@ numrange(50, 500, '[]');

-- Checking efficiency of covering index for customer orders
EXPLAIN ANALYZE
SELECT customer_id, total_amount
FROM inventory.orders
WHERE customer_id = (SELECT customer_id FROM inventory.customers WHERE email = 'bob.jones@example.com');

-- Checking monitoring of a materialized view query
EXPLAIN ANALYZE
SELECT * FROM analytics.monthly_sales WHERE month >= NOW() - INTERVAL '6 months';

-- Reset session settings
SET enable_seqscan = ON;
