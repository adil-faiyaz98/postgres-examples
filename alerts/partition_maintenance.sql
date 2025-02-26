\c db_dev;

CREATE OR REPLACE FUNCTION accounting.notify_partition_creation()
RETURNS VOID AS $$
DECLARE
    next_partition TEXT;
BEGIN
    next_partition := 'transactions_' || to_char(NOW() + INTERVAL '1 month', 'YYYY_MM');

    SET search_path TO accounting;

    -- Create partition only if it does not exist
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name = next_partition
    ) THEN
        EXECUTE format(
            'CREATE TABLE accounting.%I PARTITION OF accounting.transactions
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
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Automate partition creation with safe scheduling
SELECT cron.schedule(
    'monthly_partitioning',  -- Unique job name
    '0 0 1 * *',  -- Runs on the 1st of every month at 00:00 UTC
    $$SELECT accounting.notify_partition_creation();$$
);
