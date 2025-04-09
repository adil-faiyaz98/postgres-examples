\c db_dev;

-- Install pgTAP if not already installed
CREATE EXTENSION IF NOT EXISTS pgtap;

-- Create a test schema to isolate test objects
CREATE SCHEMA IF NOT EXISTS test AUTHORIZATION postgres;

-- Grant required privileges for testing
GRANT USAGE ON SCHEMA test TO app_user, readonly_user;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA test TO app_user;
