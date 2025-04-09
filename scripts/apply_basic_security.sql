-- Basic Security Tier for PostgreSQL 16
-- This script applies basic security settings to a PostgreSQL database

-- 1. Create roles with appropriate privileges
CREATE ROLE app_readonly;
CREATE ROLE app_readwrite;
CREATE ROLE app_admin;

-- Grant appropriate privileges to roles
GRANT CONNECT ON DATABASE postgres TO app_readonly, app_readwrite, app_admin;
GRANT USAGE ON SCHEMA public TO app_readonly, app_readwrite, app_admin;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_readonly, app_readwrite, app_admin;
GRANT INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_readwrite, app_admin;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO app_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO app_readwrite, app_admin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO app_readwrite, app_admin;

-- 2. Create users with appropriate roles
CREATE USER app_user_readonly WITH PASSWORD 'readonly_password';
CREATE USER app_user_readwrite WITH PASSWORD 'readwrite_password';
CREATE USER app_user_admin WITH PASSWORD 'admin_password';

-- Grant roles to users
GRANT app_readonly TO app_user_readonly;
GRANT app_readwrite TO app_user_readwrite;
GRANT app_admin TO app_user_admin;

-- 3. Configure connection restrictions
-- Limit failed login attempts (using pg_hba.conf and auth_delay extension)
CREATE EXTENSION IF NOT EXISTS auth_delay;
ALTER SYSTEM SET auth_delay.milliseconds = '3000';  -- 3 second delay after failed login

-- 4. Configure password policies
ALTER SYSTEM SET password_encryption = 'scram-sha-256';  -- Use strong password hashing

-- 5. Restrict superuser access
-- Create a security_admin role for security-related tasks
CREATE ROLE security_admin WITH CREATEDB CREATEROLE;
CREATE USER security_admin_user WITH PASSWORD 'security_admin_password';
GRANT security_admin TO security_admin_user;

-- 6. Revoke public schema privileges
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE postgres FROM PUBLIC;

-- 7. Set secure session defaults
ALTER SYSTEM SET idle_in_transaction_session_timeout = '60000';  -- 1 minute
ALTER SYSTEM SET statement_timeout = '30000';  -- 30 seconds

-- Apply changes
SELECT pg_reload_conf();
