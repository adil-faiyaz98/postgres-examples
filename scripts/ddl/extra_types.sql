\c db_dev;

-- Create a domain for enforcing email format consistency (case insensitive)
CREATE DOMAIN email_address AS TEXT
CHECK (
    LOWER(VALUE) ~ '^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$'
);

-- Apply domain constraint to customers table
ALTER TABLE inventory.customers
    ALTER COLUMN email TYPE email_address;

-- Ensure emails are unique
ALTER TABLE inventory.customers
    ADD CONSTRAINT unique_email UNIQUE (email);
