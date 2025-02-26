ALTER SYSTEM SET custom.db_dev = 'db_dev';
ALTER SYSTEM SET custom.db_test = 'db_test';

DO $$
DECLARE db_name TEXT;
BEGIN
    FOR db_name IN ARRAY [
        current_setting('custom.db_dev', TRUE),
        current_setting('custom.db_test', TRUE),
        current_setting('custom.db_prod', TRUE),
        current_setting('custom.db_analytics', TRUE),
        current_setting('custom.db_staging', TRUE)
    ] LOOP
        IF NOT EXISTS (SELECT FROM pg_database WHERE datname = db_name) THEN
            EXECUTE format('CREATE DATABASE %I ENCODING ''UTF8'' LC_COLLATE ''en_US.utf8'' LC_CTYPE ''en_US.utf8'' TEMPLATE template0;', db_name);
        END IF;
    END LOOP;
END $$;

