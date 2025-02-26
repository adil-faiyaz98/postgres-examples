\c db_dev;

-- 1) Analyze all tables to update query planner statistics
ANALYZE VERBOSE inventory.orders;
ANALYZE VERBOSE inventory.customers;
ANALYZE VERBOSE accounting.transactions;

-- 2) Perform a standard `VACUUM ANALYZE` to clean up dead tuples and update stats
VACUUM ANALYZE inventory.orders;
VACUUM ANALYZE inventory.customers;
VACUUM ANALYZE accounting.transactions;

-- 3) Check for table bloat before performing `VACUUM FULL`
SELECT
    schemaname, relname, pg_size_pretty(pg_table_size(c.oid)) AS table_size,
    pg_size_pretty(pg_relation_size(c.oid)) AS relation_size,
    (pg_table_size(c.oid) - pg_relation_size(c.oid)) AS wasted_space
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'inventory'
ORDER BY wasted_space DESC
LIMIT 5;

-- Perform `VACUUM FULL` only if wasted space > 50% of table size
DO $$
DECLARE table_name TEXT;
BEGIN
    FOR table_name IN
        SELECT relname
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'inventory'
        AND (pg_table_size(c.oid) - pg_relation_size(c.oid)) > (pg_table_size(c.oid) * 0.5)
    LOOP
        EXECUTE format('VACUUM FULL %I;', table_name);
    END LOOP;
END $$;

-- 4) Rebuild indexes only if they are bloated
SELECT
    indexrelname AS index_name,
    relname AS table_name,
    pg_size_pretty(pg_relation_size(indexrelid)) AS index_size
FROM pg_stat_user_indexes
WHERE idx_scan = 0 -- Unused indexes
ORDER BY pg_relation_size(indexrelid) DESC;

-- Rebuild bloated indexes
DO $$
DECLARE index_name TEXT;
BEGIN
    FOR index_name IN
        SELECT indexrelname
        FROM pg_stat_user_indexes
        WHERE idx_scan = 0
        ORDER BY pg_relation_size(indexrelid) DESC
    LOOP
        EXECUTE format('REINDEX INDEX %I;', index_name);
    END LOOP;
END $$;

-- 5) Automate autovacuum settings dynamically based on table size
DO $$
DECLARE t RECORD;
BEGIN
    FOR t IN
        SELECT rel
