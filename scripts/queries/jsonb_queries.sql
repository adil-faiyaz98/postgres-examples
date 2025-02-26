\c db_dev;

-- Query products by JSONB key
SELECT product_id, name, metadata
FROM inventory.products
WHERE metadata ->> 'brand' = 'TechCorp';

-- Check if metadata contains a certain key-value pair (use @>)
SELECT product_id, name, metadata
FROM inventory.products
WHERE metadata @> '{"brand": "GamerPro"}';

-- Update JSONB data safely
UPDATE inventory.products
SET metadata = jsonb_set(metadata, '{color}', '"black"', true)
WHERE name = 'Desk Chair'
AND metadata->>'color' IS DISTINCT FROM 'black';

-- Insert or Update Products (Fixing MERGE issue)
INSERT INTO inventory.products (name, categories, metadata)
VALUES
    ('Gaming Laptop', ARRAY['Electronics','Gaming'], '{"brand": "GamerPro", "warranty": "3 years"}'),
    ('Ergonomic Chair', ARRAY['Furniture','Office'], '{"color": "blue", "ergonomic": true}')
ON CONFLICT (name)
DO UPDATE
SET metadata = EXCLUDED.metadata || inventory.products.metadata;
