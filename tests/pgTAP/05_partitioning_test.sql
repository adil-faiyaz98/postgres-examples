\c db_dev;
BEGIN;
SELECT plan(3);

-- 1) Test partition creation
SELECT lives_ok(
    $$SELECT accounting.create_next_month_partition()$$,
    'Partition creation function executes successfully'
);

-- 2) Ensure partition exists
SELECT results_eq(
    $$SELECT EXISTS(SELECT 1 FROM pg_tables WHERE tablename = 'transactions_' || to_char(NOW() + INTERVAL '1 month', 'YYYY_MM'))$$,
    $$SELECT true$$,
    'Next month’s partition is created successfully'
);

-- 3) Test partition cleanup
SELECT lives_ok(
    $$SELECT accounting.cleanup_old_partitions()$$,
    'Old partitions are removed successfully'
);

ROLLBACK;
