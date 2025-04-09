"""
Buffer Overflow Testing Module
This module tests for buffer overflow vulnerabilities.
"""

import logging

logger = logging.getLogger("security_tests.input_validation.buffer_overflow")

def run_test(conn, engine, config):
    """
    Run buffer overflow testing against the database.

    Args:
        conn: psycopg2 connection object
        engine: SQLAlchemy engine object
        config: Test configuration dictionary

    Returns:
        dict: Test result with category, result, and details
    """
    logger.info("Starting buffer overflow testing")

    # Initialize result
    result = {
        "category": "Input Validation",
        "name": "Buffer Overflow",
        "result": "PASS",
        "details": "No buffer overflow vulnerabilities detected"
    }

    try:
        # Test 1: Check for functions with text inputs
        logger.info("Testing for functions with text inputs")

        with conn.cursor() as cursor:
            # Check for functions with text inputs
            cursor.execute("""
                SELECT n.nspname as schema, p.proname as name, pg_get_function_arguments(p.oid) as args
                FROM pg_proc p
                JOIN pg_namespace n ON p.pronamespace = n.oid
                WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
                AND p.prokind = 'f'
                AND pg_get_function_arguments(p.oid) ~* 'text'
            """)

            text_functions = cursor.fetchall()

            if text_functions:
                function_details = [f"{func[0]}.{func[1]}({func[2]})" for func in text_functions]

                result["result"] = "WARNING"
                result["details"] = f"Found {len(text_functions)} functions accepting text inputs that might be vulnerable to buffer overflow: {', '.join(function_details[:5])}..."
                logger.warning(f"Found {len(text_functions)} functions accepting text inputs that might be vulnerable to buffer overflow")

        # Test 2: Test buffer overflow with large inputs
        logger.info("Testing buffer overflow with large inputs")

        with conn.cursor() as cursor:
            # Check if the secure function exists
            cursor.execute("""
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_proc p
                    JOIN pg_namespace n ON p.pronamespace = n.oid
                    WHERE n.nspname = 'security'
                    AND p.proname = 'test_buffer_overflow_secure'
                )
            """)
            secure_function_exists = cursor.fetchone()[0]

            if not secure_function_exists:
                # Create a secure test function for buffer overflow
                cursor.execute("""
                    CREATE OR REPLACE FUNCTION security.test_buffer_overflow_secure(input text)
                    RETURNS text AS $$
                    BEGIN
                        -- Validate input size
                        IF LENGTH(input) > 1000 THEN
                            RAISE EXCEPTION 'Input exceeds maximum allowed size of 1000 characters';
                        END IF;

                        RETURN 'Processed: ' || input;
                    END;
                    $$ LANGUAGE plpgsql SECURITY DEFINER;
                """)

            # Test with a large input
            large_input = 'A' * 1000000  # 1 million characters

            # First test with the secure function
            try:
                cursor.execute("SELECT security.test_buffer_overflow_secure(%s)", (large_input,))
                result_value = cursor.fetchone()[0]

                # If we got here, the function didn't properly validate input size
                if result["result"] == "PASS":
                    result["result"] = "FAIL"
                    result["details"] = "Function security.test_buffer_overflow_secure did not properly validate input size"
                else:
                    result["details"] += "; Function security.test_buffer_overflow_secure did not properly validate input size"

                logger.warning("Function security.test_buffer_overflow_secure did not properly validate input size")
            except Exception as e:
                # If the function rejected the large input, that's good
                if "exceeds maximum allowed size" in str(e):
                    logger.info("Secure function correctly rejected oversized input")
                else:
                    logger.warning(f"Unexpected error in secure function: {str(e)}")

        return result

    except Exception as e:
        logger.error(f"Error during buffer overflow testing: {e}")
        return {
            "category": "Input Validation",
            "name": "Buffer Overflow",
            "result": "ERROR",
            "details": f"Error during buffer overflow testing: {str(e)}"
        }
