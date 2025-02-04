\c db_dev;

-- 1) Notify when new partitions are created
CREATE OR REPLACE FUNCTION accounting.notify_partition_creation()
RETURNS VOID AS $$
DECLARE
    next_partition TEXT;
BEGIN
    next_partition := 'transactions_' || to_char(NOW() + INTERVAL '1 month', 'YYYY_MM');

    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS accounting.%I
         PARTITION OF accounting.transactions
         FOR VALUES FROM (%L) TO (%L);',
        next_partition,
        date_trunc('month', NOW() + INTERVAL '1 month'),
        date_trunc('month', NOW() + INTERVAL '2 months')
    );

    PERFORM pg_notify('partition_management', json_build_object(
        'action', 'Partition Created',
        'partition_name', next_partition,
        'timestamp', NOW()
    )::TEXT);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Automate partition creation
SELECT cron.schedule('0 0 1 * *', 'SELECT accounting.notify_partition_creation();');
