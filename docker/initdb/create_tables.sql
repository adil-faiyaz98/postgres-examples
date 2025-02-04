\c db_dev;

-- Customers Table
CREATE TABLE IF NOT EXISTS inventory.customers (
    customer_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Orders Table
CREATE TABLE IF NOT EXISTS inventory.orders (
    order_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    customer_id UUID NOT NULL,
    order_date TIMESTAMPTZ DEFAULT NOW(),
    total_amount DECIMAL(10,2) CHECK (total_amount >= 0),
    CONSTRAINT fk_customer FOREIGN KEY (customer_id) REFERENCES inventory.customers (customer_id)
);

-- Payments Table
CREATE TABLE IF NOT EXISTS accounting.payments (
    payment_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    order_id UUID NOT NULL,
    amount DECIMAL(10,2) CHECK (amount >= 0),
    paid_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_order FOREIGN KEY (order_id) REFERENCES inventory.orders (order_id)
);
