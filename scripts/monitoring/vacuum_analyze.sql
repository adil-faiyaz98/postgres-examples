\c db_dev;

-- 1) Analyze all tables to update query planner statistics
ANALYZE VERBOSE inventory.orders;
ANALYZE VERBOSE inventory.customers;
ANALYZE VERBOSE accounting.transactions;

-- 2) Perform a standard `VACUUM ANALYZE` to clean up dead tuples and update stats
VACUUM ANALYZE inventory.orders;
VACUUM ANALYZE inventory.customers;
VACUUM ANALYZE accounting.transactions;

-- 3) Perform a `VACUUM FULL` (CAUTION: Locks the table, use during maintenance windows only)
VACUUM FULL inventory.products;

-- 4) Rebuild indexes to reclaim space and improve query monitoring
REINDEX TABLE inventory.orders;
REINDEX TABLE inventory.customers;
REINDEX TABLE inventory.products;

-- 5) Automate autovacuum settings for optimal monitoring (Requires Admin Role)
ALTER TABLE inventory.orders SET (
    autovacuum_enabled = true,
    autovacuum_vacuum_threshold = 50,
    autovacuum_vacuum_scale_factor = 0.1,
    autovacuum_analyze_threshold = 50,
    autovacuum_analyze_scale_factor = 0.05
);

ALTER TABLE inventory.customers SET (
    autovacuum_enabled = true,
    autovacuum_vacuum_threshold = 100,
    autovacuum_vacuum_scale_factor = 0.05,
    autovacuum_analyze_threshold = 100,
    autovacuum_analyze_scale_factor = 0.02
);

-- 6) Monitor autovacuum activity (Checks vacuuming efficiency)
SELECT relname, n_live_tup, n_dead_tup, last_autovacuum, last_autoanalyze
FROM pg_stat_all_tables
WHERE schemaname = 'inventory'
ORDER BY last_autovacuum DESC NULLS LAST;

-- 7) Identify unused indexes and index bloat (Optimization Insights)
SELECT
    schemaname,
    relname AS table_name,
    indexrelname AS index_name,
    idx_scan AS scans,
    pg_size_pretty(pg_relation_size(indexrelid)) AS index_size
FROM pg_stat_user_indexes
WHERE idx_scan = 0  -- Unused indexes
ORDER BY pg_relation_size(indexrelid) DESC;

-- 8) Log vacuum activity for reference
SELECT now(), 'VACUUM ANALYZE completed for inventory.orders and customers tables';
