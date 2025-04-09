\c db_dev;
BEGIN;
SELECT plan(4);

-- 1) Test UUID function for generating IDs
SELECT is(uuid_generate_v4()::TEXT ~ '^[a-f0-9-]+$', true, 'UUID function generates valid UUIDs');

-- 2) Test transaction partitioning function
SELECT is(
    (SELECT accounting.create_next_month_partition() IS NOT NULL),
    true,
    'Partition creation function executes successfully'
);

-- 3) Test user session management function
SELECT lives_ok(
    $$SELECT auth.start_user_session(uuid_generate_v4(), 'test@example.com', '30 minutes')$$,
    'User session starts successfully'
);

-- 4) Test partition cleanup function
SELECT lives_ok(
    $$SELECT accounting.cleanup_old_partitions()$$,
    'Partition cleanup function executes successfully'
);

ROLLBACK;
