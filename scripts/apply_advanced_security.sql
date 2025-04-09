-- Advanced Security Tier for PostgreSQL 16
-- This script applies advanced security settings to a PostgreSQL database

-- 1. Configure SSL/TLS for data in transit
-- Note: SSL certificate setup requires manual steps outside this script
-- These settings should be applied in postgresql.conf
ALTER SYSTEM SET ssl = 'on';
ALTER SYSTEM SET ssl_ciphers = 'HIGH:!aNULL:!MD5';
ALTER SYSTEM SET ssl_prefer_server_ciphers = 'on';

-- 2. Advanced Authentication
-- Install SCRAM authentication
ALTER SYSTEM SET password_encryption = 'scram-sha-256';

-- Create a function to enforce password complexity
CREATE OR REPLACE FUNCTION check_password_strength(username TEXT, password TEXT, password_type TEXT)
RETURNS BOOLEAN AS $$
DECLARE
    complexity_check BOOLEAN;
BEGIN
    -- Check password complexity (at least 8 chars, with uppercase, lowercase, number, and special char)
    complexity_check := (
        LENGTH(password) >= 8 AND
        password ~ '[A-Z]' AND
        password ~ '[a-z]' AND
        password ~ '[0-9]' AND
        password ~ '[!@#$%^&*()_+]'
    );
    
    IF NOT complexity_check THEN
        RAISE EXCEPTION 'Password does not meet complexity requirements';
    END IF;
    
    -- Check if password contains username
    IF password ILIKE '%' || username || '%' THEN
        RAISE EXCEPTION 'Password cannot contain username';
    END IF;
    
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- 3. Intrusion Detection
-- Create a table to track failed login attempts
CREATE TABLE IF NOT EXISTS security.failed_login_attempts (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    ip_address TEXT,
    attempt_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    successful BOOLEAN DEFAULT FALSE
);

-- Create a function to log failed login attempts
CREATE OR REPLACE FUNCTION log_failed_login() RETURNS event_trigger AS $$
BEGIN
    IF current_query() ~ 'authentication failed for user' THEN
        INSERT INTO security.failed_login_attempts (username, ip_address)
        VALUES (
            substring(current_query() from 'user "([^"]+)"'),
            inet_client_addr()::TEXT
        );
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Create a function to detect brute force attacks
CREATE OR REPLACE FUNCTION detect_brute_force() RETURNS TRIGGER AS $$
DECLARE
    attempt_count INTEGER;
BEGIN
    -- Count failed attempts in the last 5 minutes
    SELECT COUNT(*) INTO attempt_count
    FROM security.failed_login_attempts
    WHERE username = NEW.username
    AND attempt_time > (CURRENT_TIMESTAMP - INTERVAL '5 minutes')
    AND successful = FALSE;
    
    -- If more than 5 failed attempts, log a security event
    IF attempt_count > 5 THEN
        INSERT INTO security.security_events (event_type, description, severity)
        VALUES ('BRUTE_FORCE', 'Possible brute force attack detected for user ' || NEW.username, 'HIGH');
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create a security events table
CREATE TABLE IF NOT EXISTS security.security_events (
    id SERIAL PRIMARY KEY,
    event_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,
    description TEXT,
    severity TEXT CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    resolved BOOLEAN DEFAULT FALSE
);

-- 4. Advanced Monitoring
-- Create a function to monitor suspicious queries
CREATE OR REPLACE FUNCTION monitor_suspicious_queries() RETURNS TRIGGER AS $$
BEGIN
    -- Check for suspicious patterns in queries
    IF NEW.query ~* 'drop|truncate|delete from.*where|update.*where' THEN
        INSERT INTO security.security_events (event_type, description, severity)
        VALUES ('SUSPICIOUS_QUERY', 'Potentially dangerous query detected: ' || NEW.query, 'MEDIUM');
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply trigger to audit log
CREATE TRIGGER monitor_queries_trigger
AFTER INSERT ON audit.logged_actions
FOR EACH ROW EXECUTE FUNCTION monitor_suspicious_queries();

-- 5. Apply additional security settings
ALTER SYSTEM SET log_min_duration_statement = '1000';  -- Log slow queries (over 1 second)
ALTER SYSTEM SET log_checkpoints = 'on';
ALTER SYSTEM SET log_lock_waits = 'on';
ALTER SYSTEM SET log_temp_files = '0';  -- Log all temp file usage

-- Apply changes
SELECT pg_reload_conf();
