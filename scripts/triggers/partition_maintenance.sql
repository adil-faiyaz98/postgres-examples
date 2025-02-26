\c db_dev;

-- 1) Function to create next month's partition automatically
CREATE OR REPLACE FUNCTION accounting.create_next_month_partition()
RETURNS VOID AS $$
DECLARE
    next_month TEXT := to_char(NOW() + INTERVAL '1 month', 'YYYY_MM');
    partition_name TEXT := format('transactions_%s', next_month);
BEGIN
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS accounting.%I
         PARTITION OF accounting.transactions
         FOR VALUES FROM (%L) TO (%L);',
        partition_name,
        date_trunc('month', NOW() + INTERVAL '1 month'),
        date_trunc('month', NOW() + INTERVAL '2 months')
    );

    -- Log partition creation
    INSERT INTO logging.central_notification_log (event_type, event_source, event_details, logged_by)
    VALUES ('Partition Created', 'accounting.transactions', jsonb_build_object('partition_name', partition_name), 'system');
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Function to delete old partitions (older than 2 years)
CREATE OR REPLACE FUNCTION accounting.cleanup_old_partitions()
RETURNS VOID AS $$
DECLARE part_name TEXT;
BEGIN
    FOR part_name IN
        SELECT inhrelid::regclass::TEXT
        FROM pg_inherits
        WHERE inhparent = 'accounting.transactions'::regclass
        AND inhrelid::regclass::TEXT < 'transactions_' || to_char(NOW() - INTERVAL '2 years', 'YYYY_MM')
    LOOP
        IF EXISTS (SELECT 1 FROM pg_tables WHERE tablename = part_name) THEN
            EXECUTE format('DROP TABLE IF EXISTS %I CASCADE;', part_name);

            -- Log partition cleanup
            INSERT INTO logging.central_notification_log (event_type, event_source, event_details, logged_by)
            VALUES ('Partition Deleted', 'accounting.transactions', jsonb_build_object('partition_name', part_name), 'system');
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 3) Automate partition maintenance with pg_cron
SELECT cron.schedule('0 0 1 * *', 'SELECT accounting.create_next_month_partition();');
SELECT cron.schedule('0 0 1 * *', 'SELECT accounting.cleanup_old_partitions();');
