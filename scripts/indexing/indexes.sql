\c db_dev;

-- Index for fast email lookups
CREATE INDEX IF NOT EXISTS idx_customers_email ON inventory.customers (email);

-- Index for filtering orders by date
CREATE INDEX IF NOT EXISTS idx_orders_date ON inventory.orders (order_date);

-- GIN Index for JSONB queries
CREATE INDEX IF NOT EXISTS idx_products_metadata_gin ON inventory.products USING GIN (metadata);

-- BRIN Index for time-series data
CREATE INDEX IF NOT EXISTS idx_transactions_brin ON accounting.transactions USING BRIN (txn_date);
