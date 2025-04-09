-- Apply All Security Tiers for PostgreSQL 16
-- This script applies all security tiers to a PostgreSQL database

-- Create security schema
CREATE SCHEMA IF NOT EXISTS security;

-- Include basic security tier
\i 'apply_basic_security.sql'

-- Include intermediate security tier
\i 'apply_intermediate_security.sql'

-- Include advanced security tier
\i 'apply_advanced_security.sql'

-- Final configurations
-- Set up connection pooling limits
ALTER SYSTEM SET max_connections = '100';
ALTER SYSTEM SET superuser_reserved_connections = '3';

-- Apply changes
SELECT pg_reload_conf();

-- Verify security settings
SELECT name, setting FROM pg_settings WHERE name IN (
    'password_encryption',
    'ssl',
    'log_connections',
    'log_disconnections',
    'statement_timeout',
    'idle_in_transaction_session_timeout'
);

-- List installed extensions
SELECT * FROM pg_extension;

-- List roles and permissions
SELECT r.rolname, r.rolsuper, r.rolinherit, r.rolcreaterole, r.rolcreatedb, r.rolcanlogin
FROM pg_roles r
ORDER BY r.rolname;
