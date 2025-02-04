\c db_dev;

-- Single-column B-Tree index for fast range queries on order_date
CREATE INDEX IF NOT EXISTS idx_orders_order_date
  ON inventory.orders (order_date DESC);

-- Covering index for customer orders to optimize SELECT monitoring
CREATE INDEX IF NOT EXISTS idx_orders_customer_total
  ON inventory.orders (customer_id) INCLUDE (total_amount);

-- Partial index to optimize queries filtering only active orders
CREATE INDEX IF NOT EXISTS idx_active_orders
  ON inventory.orders (order_date)
  WHERE total_amount > 0;

-- Example query optimized by indexes
SELECT order_id, customer_id, total_amount
FROM inventory.orders
WHERE order_date >= NOW() - INTERVAL '1 month'
ORDER BY order_date DESC;
