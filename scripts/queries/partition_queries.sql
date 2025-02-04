\c db_dev;

-- Query a specific partition (January 2024)
SELECT * FROM accounting.transactions_2024_01;

-- Query using parent table (automatically routes to correct partition)
SELECT * FROM accounting.transactions
WHERE txn_date BETWEEN '2024-01-01' AND '2024-01-31';

-- Check partition sizes
SELECT
    inhrelid::regclass AS partition_name,
    pg_size_pretty(pg_relation_size(inhrelid::regclass)) AS partition_size
FROM pg_inherits
WHERE inhparent = 'accounting.transactions'::regclass;

-- Delete old partitions (e.g., transactions before 2022)
DO $$
DECLARE part_name TEXT;
BEGIN
    FOR part_name IN
        SELECT inhrelid::regclass::text
        FROM pg_inherits
        WHERE inhparent = 'accounting.transactions'::regclass
        AND inhrelid::regclass::text LIKE 'accounting.transactions_2022%'
    LOOP
        EXECUTE format('DROP TABLE IF EXISTS %I CASCADE;', part_name);
    END LOOP;
END $$;
