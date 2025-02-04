\c db_dev;

-- Prevent default public schema modification
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- Create structured schemas with secure ownership
CREATE SCHEMA IF NOT EXISTS inventory AUTHORIZATION db_owner;
CREATE SCHEMA IF NOT EXISTS accounting AUTHORIZATION db_owner;
CREATE SCHEMA IF NOT EXISTS auth AUTHORIZATION db_owner;
CREATE SCHEMA IF NOT EXISTS analytics AUTHORIZATION db_owner;

-- Create dedicated roles with proper access control
CREATE ROLE db_owner WITH LOGIN PASSWORD 'owner_password';
CREATE ROLE db_app WITH LOGIN PASSWORD 'app_password';
CREATE ROLE db_readonly WITH LOGIN PASSWORD 'readonly_password';

-- Assign ownership to db_owner
ALTER SCHEMA inventory OWNER TO db_owner;
ALTER SCHEMA accounting OWNER TO db_owner;
ALTER SCHEMA auth OWNER TO db_owner;
ALTER SCHEMA analytics OWNER TO db_owner;

-- Grant database access
GRANT CONNECT ON DATABASE db_dev TO db_app, db_readonly;
GRANT USAGE ON SCHEMA inventory, accounting, auth, analytics TO db_app, db_readonly;

-- Restrict app_user to only modifying app tables
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA inventory TO db_app;
GRANT SELECT ON ALL TABLES IN SCHEMA inventory TO db_readonly;
