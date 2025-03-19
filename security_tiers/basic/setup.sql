-- PostgreSQL Basic Security Tier Setup
-- This tier focuses on essential security features with minimal performance impact

-- 1. Create pgAudit extension for basic logging
CREATE EXTENSION IF NOT EXISTS pgaudit;

-- 2. Secure basic configuration settings
ALTER SYSTEM SET log_min_duration_statement = '1000';  -- Log slow queries (1 second)
ALTER SYSTEM SET password_encryption = 'scram-sha-256';  -- Use strong password hashing
ALTER SYSTEM SET log_connections = 'on';  -- Log all connection attempts
ALTER SYSTEM SET log_disconnections = 'on';  -- Log all disconnections
ALTER SYSTEM SET log_error_verbosity = 'default';  -- Avoid excessive info in errors
ALTER SYSTEM SET log_statement = 'ddl';  -- Log all schema-changing statements

-- 3. Create basic security roles
CREATE ROLE security_admin WITH LOGIN PASSWORD 'REPLACE_WITH_SECURE_PASSWORD' CREATEDB CREATEROLE;
CREATE ROLE security_auditor WITH LOGIN PASSWORD 'REPLACE_WITH_SECURE_PASSWORD';

-- 4. Create basic security schema
CREATE SCHEMA IF NOT EXISTS security;
GRANT USAGE ON SCHEMA security TO security_admin, security_auditor;

-- 5. Create basic audit log table
CREATE TABLE IF NOT EXISTS security.audit_log (
    audit_id BIGSERIAL PRIMARY KEY,
    audit_time TIMESTAMPTZ DEFAULT NOW(),
    user_name TEXT,
    event_type TEXT,
    object_type TEXT,
    object_name TEXT,
    query TEXT
);

-- 6. Create audit logging function
CREATE OR REPLACE FUNCTION security.log_activity()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO security.audit_log (user_name, event_type, object_type, object_name, query)
    VALUES (current_user, TG_OP, TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME, TG_TABLE_NAME, current_query());
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 7. Configure pgAudit for basic auditing
ALTER SYSTEM SET pgaudit.log = 'write, ddl';
ALTER SYSTEM SET pgaudit.log_catalog = 'off';
ALTER SYSTEM SET pgaudit.log_client = 'on';
ALTER SYSTEM SET pgaudit.log_relation = 'on';

-- 8. Basic connection security
ALTER SYSTEM SET ssl = 'on';
ALTER SYSTEM SET ssl_prefer_server_ciphers = 'on';

-- 9. Reload PostgreSQL configuration
SELECT pg_reload_conf(); 