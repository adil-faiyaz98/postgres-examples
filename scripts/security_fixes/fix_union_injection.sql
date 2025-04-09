-- Fix Union-Based SQL Injection Vulnerability
-- This script replaces the vulnerable test_union_injection function with a secure version

-- Drop the vulnerable function
DROP FUNCTION IF EXISTS test_union_injection(text);

-- Create a secure version using parameterized queries and proper input validation
CREATE OR REPLACE FUNCTION test_union_injection_secure(param text)
RETURNS TABLE(item_id int, item_name text) AS $$
DECLARE
    validated_param text;
BEGIN
    -- Input validation
    IF param ~ '[^a-zA-Z0-9]' THEN
        RAISE EXCEPTION 'Invalid input: parameter contains disallowed characters';
    END IF;
    
    validated_param := param;
    
    -- Use parameterized query instead of string concatenation
    RETURN QUERY 
    SELECT t.id AS item_id, t.name AS item_name 
    FROM (VALUES (1, 'test1'), (2, 'test2')) AS t(id, name) 
    WHERE t.id = CASE WHEN validated_param = '1' THEN 1 ELSE 2 END;
    
    RETURN;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Add a comment explaining the security measures
COMMENT ON FUNCTION test_union_injection_secure(text) IS 
'Secure version of test_union_injection with input validation and parameterized queries';

-- Test the secure function
SELECT * FROM test_union_injection_secure('1');
SELECT * FROM test_union_injection_secure('2');

-- This should fail with an error
-- SELECT * FROM test_union_injection_secure('1'' UNION SELECT 1, current_user --');
