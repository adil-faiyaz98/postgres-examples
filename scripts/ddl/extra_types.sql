\c db_dev;

-- Create a domain for enforcing email format consistency
CREATE DOMAIN email_address AS TEXT
CHECK (
    VALUE ~* '^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$'
);

-- Apply domain constraint to customers table
ALTER TABLE inventory.customers
    ALTER COLUMN email TYPE email_address;
