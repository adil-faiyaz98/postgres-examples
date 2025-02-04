\c db_dev;

-- BRIN index for time-series data in large tables (Orders)
CREATE INDEX IF NOT EXISTS idx_orders_brin
  ON inventory.orders USING BRIN (order_date);

-- BRIN index for large partitioned transaction tables
CREATE INDEX IF NOT EXISTS idx_transactions_brin
  ON accounting.transactions USING BRIN (txn_date);

-- Example query optimized by BRIN index
SELECT transaction_id, txn_date, amount
FROM accounting.transactions
WHERE txn_date >= NOW() - INTERVAL '6 months';
