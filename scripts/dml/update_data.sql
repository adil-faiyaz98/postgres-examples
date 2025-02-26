\c db_dev;
BEGIN;

-- Validate Email Format Before Updating
UPDATE inventory.customers
SET email = 'alice.smith@securemail.com'
WHERE email = 'alice.smith@example.com'
AND email ~ '^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$'
RETURNING *;

-- Log email change into audit log
INSERT INTO logging.audit_log (event_type, table_name, query, user)
VALUES ('UPDATE', 'inventory.customers', 'Updated email for Alice Smith', current_user);

-- Update Product Price in Metadata JSONB (Ensure Field Exists)
UPDATE inventory.products
SET metadata = jsonb_set(metadata, '{price}', '1499.99'::jsonb, true)
WHERE name = 'Laptop'
AND metadata ? 'price'  -- Ensures key exists in JSONB
RETURNING *;

-- Log product update
INSERT INTO logging.audit_log (event_type, table_name, query, user)
VALUES ('UPDATE', 'inventory.products', 'Updated price for Laptop', current_user);

-- Update Order Amount (Ensuring Integrity)
UPDATE inventory.orders
SET total_amount = 249.99
WHERE order_id = (
    SELECT order_id
    FROM inventory.orders
    WHERE customer_id = (SELECT customer_id FROM inventory.customers WHERE email = 'alice.smith@securemail.com')
    ORDER BY order_date DESC
    LIMIT 1
)
RETURNING *;

COMMIT;
