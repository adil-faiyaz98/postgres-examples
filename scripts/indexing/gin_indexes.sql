\c db_dev;

-- Enable GIN for efficient JSONB querying
CREATE INDEX IF NOT EXISTS idx_products_metadata_gin
  ON inventory.products
  USING GIN (metadata);

-- Enable GIN index on array categories for efficient searching
CREATE INDEX IF NOT EXISTS idx_products_categories_gin
  ON inventory.products
  USING GIN (categories);

-- Prevent index bloat with VACUUM ANALYZE
VACUUM ANALYZE inventory.products;

-- Example query optimized by GIN index (Exact Match JSONB Search)
SELECT product_id, name
FROM inventory.products
WHERE metadata @> '{"brand": "TechCorp"}';

-- Example query optimized by GIN index (Array Search)
SELECT product_id, name
FROM inventory.products
WHERE categories @> ARRAY['Electronics'];
