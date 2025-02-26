\c db_dev;

ALTER TABLE inventory.customers ADD CONSTRAINT unique_customer_email UNIQUE (email) DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE inventory.orders ADD CONSTRAINT chk_positive_amount CHECK (total_amount > 0) DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE accounting.payments ADD CONSTRAINT chk_non_negative_payment CHECK (amount >= 0) DEFERRABLE INITIALLY IMMEDIATE;

