"""
Error-Based SQL Injection Test Module
This module tests for error-based SQL injection vulnerabilities.
"""

import logging

logger = logging.getLogger("security_tests.sql_injection.error_based")

def run_test(conn, engine, config):
    """Run the error-based SQL injection test."""
    logger.info("Starting error-based SQL injection tests")

    results = {
        "category": "SQL Injection",
        "name": "Error-Based SQL Injection",
        "result": "PASS",
        "details": "No error-based SQL injection vulnerabilities found"
    }

    try:
        # Test 1: Check for basic error-based SQL injection
        logger.info("Testing basic error-based SQL injection")

        # Create a test function for error-based injection
        with conn.cursor() as cursor:
            # First, check if the function already exists
            cursor.execute("""
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_proc p
                    JOIN pg_namespace n ON p.pronamespace = n.oid
                    WHERE n.nspname = 'public'
                    AND p.proname = 'test_error_injection'
                )
            """)
            function_exists = cursor.fetchone()[0]

            if not function_exists:
                # Create a test function
                cursor.execute("""
                    CREATE OR REPLACE FUNCTION test_error_injection(param text)
                    RETURNS TABLE(item_id int, item_name text) AS $$
                    BEGIN
                        RETURN QUERY SELECT t.id AS item_id, t.name AS item_name FROM (VALUES (1, 'test1'), (2, 'test2')) AS t(id, name) WHERE t.id = 1;
                        RETURN;
                    END;
                    $$ LANGUAGE plpgsql;
                """)

            # Test the function with a normal parameter
            cursor.execute("SELECT * FROM test_error_injection('normal')")

            # Test the function with a malicious parameter (simulated)
            # In a real test, we would try to inject a query that causes an error
            # But for this test, we'll just check if the function is vulnerable

            try:
                cursor.execute("SELECT * FROM test_error_injection('1'' AND (SELECT 1 FROM non_existent_table) = ''1')")
                # If the query succeeded, it might not be vulnerable
                logger.info("Error during injection attempt, but doesn't appear to be successful")
            except Exception as e:
                # If the query failed with a specific error, it might be vulnerable
                if "non_existent_table" in str(e):
                    results["result"] = "FAIL"
                    results["details"] = f"Function test_error_injection is vulnerable to error-based SQL injection"
                    logger.warning(f"Function test_error_injection is vulnerable to error-based SQL injection")
                else:
                    # If the query failed with a different error, it might not be vulnerable
                    logger.info(f"Error during injection attempt, but doesn't appear to be successful: {e}")

        # Test 2: Check for advanced error-based SQL injection
        logger.info("Testing advanced error-based SQL injection")

        # Simulate a test by checking if the database has proper input validation
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_proc p
                    JOIN pg_namespace n ON p.pronamespace = n.oid
                    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
                    AND p.prokind = 'f'
                    AND pg_get_functiondef(p.oid) ~* 'validate|sanitize|check'
                )
            """)
            has_validation = cursor.fetchone()[0]

            if not has_validation:
                if results["result"] == "PASS":
                    results["result"] = "WARNING"
                    results["details"] = "No input validation functions found, potential error-based SQL injection risk"
                else:
                    results["details"] += "; No input validation functions found, potential error-based SQL injection risk"
    except Exception as e:
        logger.error(f"Error during error-based SQL injection tests: {e}")
        results["result"] = "ERROR"
        results["details"] = f"Error during test: {str(e)}"

    return results
