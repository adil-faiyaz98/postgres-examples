\c db_dev;

-- 1) Create a materialized view for recent orders (optimized)
CREATE MATERIALIZED VIEW IF NOT EXISTS analytics.recent_orders
AS
SELECT
    o.order_id,
    c.first_name,
    c.last_name,
    o.total_amount,
    o.order_date
FROM inventory.orders o
JOIN inventory.customers c
    ON o.customer_id = c.customer_id
WHERE o.order_date >= NOW() - INTERVAL '30 days'
WITH NO DATA;

-- Ensure indexes exist on materialized view for refresh performance
CREATE INDEX IF NOT EXISTS idx_recent_orders ON analytics.recent_orders(order_date);

-- Refresh materialized view after creating it
REFRESH MATERIALIZED VIEW analytics.recent_orders;

-- 2) Create a materialized view for top customers
CREATE MATERIALIZED VIEW IF NOT EXISTS analytics.top_customers
AS
SELECT
    c.customer_id,
    c.first_name,
    c.last_name,
    SUM(o.total_amount) AS total_spent
FROM inventory.customers c
JOIN inventory.orders o
    ON c.customer_id = o.customer_id
GROUP BY c.customer_id
ORDER BY total_spent DESC
WITH NO DATA;

-- Ensure index on materialized view for query performance
CREATE INDEX IF NOT EXISTS idx_top_customers ON analytics.top_customers(total_spent DESC);

-- Refresh materialized view
REFRESH MATERIALIZED VIEW analytics.top_customers;
