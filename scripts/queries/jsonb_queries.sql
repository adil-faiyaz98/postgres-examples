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

-- Merge new products or update existing
MERGE INTO inventory.products AS p
USING (VALUES
    ('Gaming Laptop', ARRAY['Electronics','Gaming'], '{"brand": "GamerPro", "warranty": "3 years"}'),
    ('Ergonomic Chair', ARRAY['Furniture','Office'], '{"color": "blue", "ergonomic": true}')
) AS new_data(name, categories, metadata)
    ON p.name = new_data.name
WHEN MATCHED THEN
    UPDATE SET metadata = p.metadata || new_data.metadata  -- Concatenating JSONB
WHEN NOT MATCHED THEN
    INSERT (name, categories, metadata)
    VALUES (new_data.name, new_data.categories, new_data.metadata);
