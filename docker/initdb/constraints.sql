\c db_dev;

-- Enforce unique emails
ALTER TABLE inventory.customers ADD CONSTRAINT unique_customer_email UNIQUE (email);

-- Prevent negative order amounts
ALTER TABLE inventory.orders ADD CONSTRAINT chk_positive_amount CHECK (total_amount > 0);

-- Ensure payments are non-negative
ALTER TABLE accounting.payments ADD CONSTRAINT chk_non_negative_payment CHECK (amount >= 0);
