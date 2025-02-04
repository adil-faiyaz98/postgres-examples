DO $$
DECLARE db_name TEXT;
BEGIN
    FOR db_name IN ARRAY ['db_dev', 'db_test', 'db_prod', 'db_analytics', 'db_staging'] LOOP
        IF NOT EXISTS (SELECT FROM pg_database WHERE datname = db_name) THEN
            EXECUTE format('CREATE DATABASE %I ENCODING ''UTF8'' LC_COLLATE ''en_US.utf8'' LC_CTYPE ''en_US.utf8'' TEMPLATE template0;', db_name);
        END IF;
    END LOOP;
END $$;
