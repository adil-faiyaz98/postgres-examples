\c db_dev;

-- Ensure foreign key lookups are optimized
CREATE INDEX IF NOT EXISTS idx_orders_customer_id
  ON inventory.orders (customer_id);

-- Index for fast lookups on email (unique constraint ensures efficiency)
CREATE UNIQUE INDEX IF NOT EXISTS idx_customers_email
  ON inventory.customers (email);

-- Index for filtering orders by date
CREATE INDEX IF NOT EXISTS idx_orders_date
  ON inventory.orders (order_date);

-- Covering index for customer orders to optimize SELECT performance
CREATE INDEX IF NOT EXISTS idx_orders_customer_total
  ON inventory.orders (customer_id) INCLUDE (total_amount);

-- Partial index for filtering active orders only
CREATE INDEX IF NOT EXISTS idx_active_orders
  ON inventory.orders (order_date)
  WHERE total_amount > 0;

-- Example query optimized by indexes
SELECT order_id, customer_id, total_amount
FROM inventory.orders
WHERE order_date >= NOW() - INTERVAL '1 month'
ORDER BY order_date DESC;
