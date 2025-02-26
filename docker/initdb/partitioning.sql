\c db_dev;

-- Transactions Table (Partitioned by Date)
CREATE TABLE IF NOT EXISTS accounting.transactions (
    transaction_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    txn_date DATE NOT NULL,
    amount NUMERIC(10,2),
    PRIMARY KEY (transaction_id, txn_date)
) PARTITION BY RANGE (txn_date);

-- Automatically creates new partitions each month
CREATE OR REPLACE FUNCTION accounting.create_next_month_partition()
RETURNS VOID AS $$
DECLARE next_month TEXT;
BEGIN
    next_month := to_char(NOW() + INTERVAL '1 month', 'YYYY_MM');
    IF NOT EXISTS (SELECT FROM pg_tables WHERE tablename = 'transactions_' || next_month) THEN
        EXECUTE format(
            'CREATE TABLE accounting.transactions_%s PARTITION OF accounting.transactions
             FOR VALUES FROM (%L) TO (%L);',
            next_month,
            date_trunc('month', NOW() + INTERVAL '1 month'),
            date_trunc('month', NOW() + INTERVAL '2 months')
        );
    END IF;
END;
$$ LANGUAGE plpgsql;

