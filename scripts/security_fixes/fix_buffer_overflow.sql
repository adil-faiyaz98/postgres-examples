-- Address Buffer Overflow Warnings
-- This script implements input size limits and validation for functions accepting text inputs

-- Create a function to validate input size
CREATE OR REPLACE FUNCTION validate_input_size(input text, max_size integer DEFAULT 1000000)
RETURNS text AS $$
BEGIN
    IF input IS NULL THEN
        RETURN NULL;
    END IF;
    
    IF LENGTH(input) > max_size THEN
        RAISE EXCEPTION 'Input exceeds maximum allowed size of % characters', max_size;
    END IF;
    
    RETURN input;
END;
$$ LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER;

-- Create secure wrapper functions for common text functions
CREATE OR REPLACE FUNCTION secure_digest(input text, algorithm text)
RETURNS bytea AS $$
BEGIN
    -- Validate input size
    input := validate_input_size(input);
    algorithm := validate_input_size(algorithm, 100);
    
    -- Call the original function with validated input
    RETURN digest(input, algorithm);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION secure_hmac(input text, key text, algorithm text)
RETURNS bytea AS $$
BEGIN
    -- Validate input size
    input := validate_input_size(input);
    key := validate_input_size(key);
    algorithm := validate_input_size(algorithm, 100);
    
    -- Call the original function with validated input
    RETURN hmac(input, key, algorithm);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION secure_crypt(input text, salt text)
RETURNS text AS $$
BEGIN
    -- Validate input size
    input := validate_input_size(input);
    salt := validate_input_size(salt, 100);
    
    -- Call the original function with validated input
    RETURN crypt(input, salt);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create a function to test buffer overflow protection
CREATE OR REPLACE FUNCTION test_buffer_overflow_secure(input text)
RETURNS text AS $$
BEGIN
    -- Validate input size
    input := validate_input_size(input, 1000);
    
    -- Process the validated input
    RETURN 'Processed: ' || input;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Add comments explaining the security measures
COMMENT ON FUNCTION validate_input_size(text, integer) IS 
'Validates that input does not exceed the specified maximum size';

COMMENT ON FUNCTION secure_digest(text, text) IS 
'Secure wrapper for digest() with input size validation';

COMMENT ON FUNCTION secure_hmac(text, text, text) IS 
'Secure wrapper for hmac() with input size validation';

COMMENT ON FUNCTION secure_crypt(text, text) IS 
'Secure wrapper for crypt() with input size validation';

COMMENT ON FUNCTION test_buffer_overflow_secure(text) IS 
'Secure function with buffer overflow protection';
