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
DECLARE next_month DATE := date_trunc('month', NOW()) + INTERVAL '1 month';
BEGIN
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS accounting.transactions_%s
         PARTITION OF accounting.transactions
         FOR VALUES FROM (%L) TO (%L);',
        to_char(next_month, 'YYYY_MM'),
        next_month, next_month + INTERVAL '1 month'
    );
END;
$$ LANGUAGE plpgsql;

-- Automate partition creation
SELECT cron.schedule('0 0 1 * *', 'SELECT accounting.create_next_month_partition();');
