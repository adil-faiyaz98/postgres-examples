-- PostgreSQL Standard Security Tier Setup
-- This tier builds on Basic, adding comprehensive auditing and monitoring

-- 0. Apply basic tier first (ensure it's already run)
\i ../basic/setup.sql

-- 1. Create additional security extensions
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
CREATE EXTENSION IF NOT EXISTS pgcrypto;  

-- 2. Enhanced security settings
ALTER SYSTEM SET log_min_duration_statement = '500';  -- Log queries taking > 500ms
ALTER SYSTEM SET log_statement = 'mod';  -- Log all data-modifying statements
ALTER SYSTEM SET log_min_error_statement = 'error';  -- Log statements causing errors
ALTER SYSTEM SET log_line_prefix = '%m [%p] %q%u@%d ';  -- Enhanced log prefix with user info
ALTER SYSTEM SET log_checkpoints = 'on';  -- Log all checkpoints
ALTER SYSTEM SET log_lock_waits = 'on';  -- Log lock waits
ALTER SYSTEM SET log_temp_files = '0';  -- Log all temporary file creation

-- 3. Create comprehensive anomaly detection schema
CREATE SCHEMA IF NOT EXISTS security_monitoring;
GRANT USAGE ON SCHEMA security_monitoring TO security_admin, security_auditor;

-- 4. Create tables for anomaly detection
CREATE TABLE IF NOT EXISTS security_monitoring.query_patterns (
    pattern_id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    database_name TEXT NOT NULL,
    query_signature TEXT NOT NULL,
    avg_execution_time NUMERIC NOT NULL,
    std_dev_execution_time NUMERIC NOT NULL,
    sample_size INTEGER NOT NULL,
    last_updated TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS security_monitoring.anomalies (
    anomaly_id BIGSERIAL PRIMARY KEY,
    detection_time TIMESTAMPTZ DEFAULT NOW(),
    username TEXT NOT NULL,
    database_name TEXT NOT NULL,
    query_signature TEXT NOT NULL,
    execution_time NUMERIC NOT NULL,
    expected_execution_time NUMERIC NOT NULL,
    deviation_factor NUMERIC NOT NULL,
    query_text TEXT,
    action_taken TEXT
);

-- 5. Create role-based access control (RBAC) tables
CREATE TABLE IF NOT EXISTS security.roles (
    role_id SERIAL PRIMARY KEY,
    role_name TEXT UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS security.role_permissions (
    permission_id SERIAL PRIMARY KEY,
    role_id INTEGER REFERENCES security.roles(role_id),
    object_type TEXT NOT NULL,
    object_name TEXT NOT NULL,
    permission TEXT NOT NULL,
    granted_at TIMESTAMPTZ DEFAULT NOW()
);

-- 6. Configure pgAudit for comprehensive auditing
ALTER SYSTEM SET pgaudit.log = 'all';
ALTER SYSTEM SET pgaudit.log_catalog = 'on';
ALTER SYSTEM SET pgaudit.log_parameter = 'on';
ALTER SYSTEM SET pgaudit.log_statement_once = 'on';
ALTER SYSTEM SET pgaudit.role = 'security_auditor';

-- 7. Enhanced connection security
ALTER SYSTEM SET ssl = 'on';
ALTER SYSTEM SET ssl_prefer_server_ciphers = 'on';
ALTER SYSTEM SET ssl_min_protocol_version = 'TLSv1.2';

-- 8. Active session monitoring function
CREATE OR REPLACE FUNCTION security_monitoring.check_suspicious_activity()
RETURNS TABLE (
    pid INTEGER,
    username TEXT,
    application_name TEXT,
    client_addr INET,
    backend_start TIMESTAMPTZ,
    query_start TIMESTAMPTZ,
    state TEXT,
    query TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        pg_stat_activity.pid,
        pg_stat_activity.usename::TEXT,
        pg_stat_activity.application_name,
        pg_stat_activity.client_addr,
        pg_stat_activity.backend_start,
        pg_stat_activity.query_start,
        pg_stat_activity.state,
        pg_stat_activity.query
    FROM 
        pg_stat_activity
    WHERE 
        -- Long-running queries (more than 5 minutes)
        (state = 'active' AND NOW() - query_start > INTERVAL '5 minutes')
        -- Unusual application connections
        OR application_name !~ '^(psql|pgAdmin|DBeaver|pg_dump)$'
        -- Multiple connections from same IP
        OR client_addr IN (
            SELECT client_addr 
            FROM pg_stat_activity 
            WHERE client_addr IS NOT NULL 
            GROUP BY client_addr 
            HAVING COUNT(*) > 5
        );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 9. Reload PostgreSQL configuration
SELECT pg_reload_conf(); 