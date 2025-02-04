\c db_dev;

-- GiST Index for range-based queries on transaction amounts
CREATE INDEX IF NOT EXISTS idx_transactions_amount_gist
  ON accounting.transactions USING GIST (amount);

-- GiST Index for full-text search on web events (if needed)
CREATE INDEX IF NOT EXISTS idx_web_events_search_gist
  ON analytics.web_events USING GIST (event_data);

-- Example queries optimized by GiST
SELECT * FROM accounting.transactions
WHERE amount <@ numrange(50, 500, '[]'); -- Efficient for numeric range filtering

SELECT * FROM analytics.web_events
WHERE event_data @@ to_tsquery('login & success');
