-- Enhance Database Security Configuration
-- This script applies additional security settings to address identified weaknesses

-- 1. Strengthen connection security
ALTER SYSTEM SET log_connections = 'on';
ALTER SYSTEM SET log_disconnections = 'on';
ALTER SYSTEM SET log_statement = 'ddl';
ALTER SYSTEM SET log_min_error_statement = 'error';
ALTER SYSTEM SET log_min_duration_statement = '1000';  -- Log queries taking more than 1 second
ALTER SYSTEM SET log_line_prefix = '%m [%p] %q%u@%d ';  -- Include more information in log prefix

-- 2. Enhance SSL/TLS configuration
ALTER SYSTEM SET ssl = 'on';
ALTER SYSTEM SET ssl_prefer_server_ciphers = 'on';
ALTER SYSTEM SET ssl_ciphers = 'HIGH:!aNULL:!MD5';

-- 3. Set stricter statement timeout to prevent long-running attacks
ALTER SYSTEM SET statement_timeout = '30000';  -- 30 seconds
ALTER SYSTEM SET idle_in_transaction_session_timeout = '60000';  -- 1 minute

-- 4. Limit connection attempts to prevent brute force attacks
ALTER SYSTEM SET max_connections = '100';
ALTER SYSTEM SET superuser_reserved_connections = '3';

-- 5. Create a security event trigger to log suspicious activities
CREATE OR REPLACE FUNCTION log_security_event()
RETURNS event_trigger AS $$
BEGIN
    IF current_query() ~ 'DROP|TRUNCATE|DELETE FROM|UPDATE.*WHERE|CREATE ROLE|ALTER ROLE' THEN
        INSERT INTO security.security_events (event_type, description, severity)
        VALUES ('SUSPICIOUS_QUERY', 'Potentially dangerous query detected: ' || current_query(), 'MEDIUM');
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Create event trigger for DDL commands
DROP EVENT TRIGGER IF EXISTS security_event_trigger;
CREATE EVENT TRIGGER security_event_trigger ON ddl_command_end
EXECUTE FUNCTION log_security_event();

-- 6. Create a function to monitor failed login attempts
CREATE OR REPLACE FUNCTION log_failed_login()
RETURNS event_trigger AS $$
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

-- 7. Create a function to detect brute force attacks
CREATE OR REPLACE FUNCTION detect_brute_force()
RETURNS TRIGGER AS $$
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

-- Apply the trigger to the failed_login_attempts table
DROP TRIGGER IF EXISTS detect_brute_force_trigger ON security.failed_login_attempts;
CREATE TRIGGER detect_brute_force_trigger
AFTER INSERT ON security.failed_login_attempts
FOR EACH ROW EXECUTE FUNCTION detect_brute_force();

-- 8. Apply changes
SELECT pg_reload_conf();
