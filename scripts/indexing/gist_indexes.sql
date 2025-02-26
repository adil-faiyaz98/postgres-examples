\c db_dev;

-- Ensure pg_trgm extension is enabled for text search
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- GiST Index for range-based queries on transaction amounts
CREATE INDEX IF NOT EXISTS idx_transactions_amount_gist
  ON accounting.transactions USING GIST (amount);

-- Use GIN instead of GiST for full-text search
CREATE INDEX IF NOT EXISTS idx_web_events_search_gin
  ON analytics.web_events USING GIN (to_tsvector('english', event_data));

-- Example queries optimized by indexes
SELECT * FROM accounting.transactions
WHERE amount <@ numrange(50, 500, '[]'); -- Efficient for numeric range filtering

SELECT * FROM analytics.web_events
WHERE event_data @@ to_tsquery('login & success');
