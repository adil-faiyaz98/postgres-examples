-- Comprehensive Fix for Buffer Overflow Warnings
-- This script implements comprehensive protection against buffer overflow vulnerabilities

-- 1. Create a schema for security functions
CREATE SCHEMA IF NOT EXISTS security;

-- 2. Create a function to validate input size with detailed logging
CREATE OR REPLACE FUNCTION security.validate_input_size(
    input text, 
    max_size integer DEFAULT 1000000,
    function_name text DEFAULT NULL,
    parameter_name text DEFAULT NULL
)
RETURNS text AS $$
DECLARE
    input_length integer;
BEGIN
    IF input IS NULL THEN
        RETURN NULL;
    END IF;
    
    input_length := LENGTH(input);
    
    IF input_length > max_size THEN
        -- Log the attempt
        INSERT INTO security.security_events (
            event_type,
            description,
            severity,
            source,
            username,
            database_name,
            client_addr
        ) VALUES (
            'BUFFER_OVERFLOW_ATTEMPT',
            format(
                'Buffer overflow attempt detected: %s bytes for %s.%s (max: %s)',
                input_length,
                COALESCE(function_name, 'unknown_function'),
                COALESCE(parameter_name, 'unknown_parameter'),
                max_size
            ),
            'HIGH',
            'validate_input_size',
            current_user,
            current_database(),
            inet_client_addr()::TEXT
        );
        
        RAISE EXCEPTION 'Input exceeds maximum allowed size of % characters (received % characters)', 
                        max_size, input_length;
    END IF;
    
    RETURN input;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 3. Create a table to store security events if it doesn't exist
CREATE TABLE IF NOT EXISTS security.security_events (
    id SERIAL PRIMARY KEY,
    event_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,
    description TEXT,
    severity TEXT CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    source TEXT,
    username TEXT,
    database_name TEXT,
    client_addr TEXT,
    query TEXT,
    resolved BOOLEAN DEFAULT FALSE,
    resolution_notes TEXT,
    resolution_time TIMESTAMP WITH TIME ZONE
);

-- 4. Create secure wrapper functions for all text-handling functions
-- Digest function
CREATE OR REPLACE FUNCTION security.secure_digest(input text, algorithm text)
RETURNS bytea AS $$
BEGIN
    -- Validate input size
    input := security.validate_input_size(input, 1000000, 'secure_digest', 'input');
    algorithm := security.validate_input_size(algorithm, 100, 'secure_digest', 'algorithm');
    
    -- Call the original function with validated input
    RETURN digest(input, algorithm);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- HMAC function
CREATE OR REPLACE FUNCTION security.secure_hmac(input text, key text, algorithm text)
RETURNS bytea AS $$
BEGIN
    -- Validate input size
    input := security.validate_input_size(input, 1000000, 'secure_hmac', 'input');
    key := security.validate_input_size(key, 10000, 'secure_hmac', 'key');
    algorithm := security.validate_input_size(algorithm, 100, 'secure_hmac', 'algorithm');
    
    -- Call the original function with validated input
    RETURN hmac(input, key, algorithm);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Crypt function
CREATE OR REPLACE FUNCTION security.secure_crypt(input text, salt text)
RETURNS text AS $$
BEGIN
    -- Validate input size
    input := security.validate_input_size(input, 10000, 'secure_crypt', 'input');
    salt := security.validate_input_size(salt, 100, 'secure_crypt', 'salt');
    
    -- Call the original function with validated input
    RETURN crypt(input, salt);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- PGP encryption functions
CREATE OR REPLACE FUNCTION security.secure_pgp_sym_encrypt(input text, key text)
RETURNS bytea AS $$
BEGIN
    -- Validate input size
    input := security.validate_input_size(input, 1000000, 'secure_pgp_sym_encrypt', 'input');
    key := security.validate_input_size(key, 10000, 'secure_pgp_sym_encrypt', 'key');
    
    -- Call the original function with validated input
    RETURN pgp_sym_encrypt(input, key);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION security.secure_pgp_pub_encrypt(input text, key bytea)
RETURNS bytea AS $$
BEGIN
    -- Validate input size
    input := security.validate_input_size(input, 1000000, 'secure_pgp_pub_encrypt', 'input');
    
    -- Call the original function with validated input
    RETURN pgp_pub_encrypt(input, key);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 5. Create a secure version of the test_buffer_overflow function
CREATE OR REPLACE FUNCTION security.test_buffer_overflow_secure(input text)
RETURNS text AS $$
BEGIN
    -- Validate input size
    input := security.validate_input_size(input, 1000, 'test_buffer_overflow_secure', 'input');
    
    -- Process the validated input
    RETURN 'Processed: ' || input;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 6. Create a function to detect and log buffer overflow attempts
CREATE OR REPLACE FUNCTION security.log_buffer_overflow_attempt()
RETURNS TRIGGER AS $$
BEGIN
    -- Send an alert (this could be an email, a notification, etc.)
    RAISE NOTICE 'SECURITY ALERT: Buffer overflow attempt detected from %', NEW.client_addr;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create a trigger on the security events table
DROP TRIGGER IF EXISTS buffer_overflow_alert ON security.security_events;
CREATE TRIGGER buffer_overflow_alert
AFTER INSERT ON security.security_events
FOR EACH ROW
WHEN (NEW.event_type = 'BUFFER_OVERFLOW_ATTEMPT')
EXECUTE FUNCTION security.log_buffer_overflow_attempt();

-- 7. Create a view to monitor buffer overflow attempts
CREATE OR REPLACE VIEW security.buffer_overflow_attempts AS
SELECT
    id,
    event_time,
    description,
    severity,
    username,
    client_addr,
    resolved
FROM
    security.security_events
WHERE
    event_type = 'BUFFER_OVERFLOW_ATTEMPT'
ORDER BY
    event_time DESC;

-- 8. Add comments explaining the security measures
COMMENT ON SCHEMA security IS 'Schema for security functions and tables';
COMMENT ON FUNCTION security.validate_input_size IS 'Validates that input does not exceed the specified maximum size';
COMMENT ON FUNCTION security.secure_digest IS 'Secure wrapper for digest() with input size validation';
COMMENT ON FUNCTION security.secure_hmac IS 'Secure wrapper for hmac() with input size validation';
COMMENT ON FUNCTION security.secure_crypt IS 'Secure wrapper for crypt() with input size validation';
COMMENT ON FUNCTION security.secure_pgp_sym_encrypt IS 'Secure wrapper for pgp_sym_encrypt() with input size validation';
COMMENT ON FUNCTION security.secure_pgp_pub_encrypt IS 'Secure wrapper for pgp_pub_encrypt() with input size validation';
COMMENT ON FUNCTION security.test_buffer_overflow_secure IS 'Secure function with buffer overflow protection';
COMMENT ON FUNCTION security.log_buffer_overflow_attempt IS 'Function to log buffer overflow attempts';
COMMENT ON TABLE security.security_events IS 'Table to store security events';
COMMENT ON VIEW security.buffer_overflow_attempts IS 'View to monitor buffer overflow attempts';

-- 9. Grant appropriate permissions
GRANT USAGE ON SCHEMA security TO app_admin;
GRANT EXECUTE ON FUNCTION security.validate_input_size TO app_admin;
GRANT EXECUTE ON FUNCTION security.secure_digest TO app_admin;
GRANT EXECUTE ON FUNCTION security.secure_hmac TO app_admin;
GRANT EXECUTE ON FUNCTION security.secure_crypt TO app_admin;
GRANT EXECUTE ON FUNCTION security.secure_pgp_sym_encrypt TO app_admin;
GRANT EXECUTE ON FUNCTION security.secure_pgp_pub_encrypt TO app_admin;
GRANT EXECUTE ON FUNCTION security.test_buffer_overflow_secure TO app_admin;
GRANT SELECT ON security.buffer_overflow_attempts TO app_admin;
