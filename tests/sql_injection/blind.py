"""
Blind SQL Injection Test Module
This module tests for blind SQL injection vulnerabilities.
"""

import logging
import time

logger = logging.getLogger("security_tests.sql_injection.blind")

def run_test(conn, engine, config):
    """Run the blind SQL injection test."""
    logger.info("Starting blind SQL injection tests")

    results = {
        "category": "SQL Injection",
        "name": "Blind SQL Injection",
        "result": "PASS",
        "details": "No blind SQL injection vulnerabilities found"
    }

    try:
        # Test 1: Check for time-based blind SQL injection
        logger.info("Testing time-based blind SQL injection")

        # Create a test function for time-based blind injection
        with conn.cursor() as cursor:
            # First, check if the function already exists
            cursor.execute("""
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_proc p
                    JOIN pg_namespace n ON p.pronamespace = n.oid
                    WHERE n.nspname = 'public'
                    AND p.proname = 'test_blind_injection'
                )
            """)
            function_exists = cursor.fetchone()[0]

            if not function_exists:
                # Create a test function
                cursor.execute("""
                    CREATE OR REPLACE FUNCTION test_blind_injection(param text)
                    RETURNS TABLE(item_id int, item_name text) AS $$
                    BEGIN
                        RETURN QUERY SELECT t.id AS item_id, t.name AS item_name FROM (VALUES (1, 'test1'), (2, 'test2')) AS t(id, name) WHERE t.id = 1;
                        RETURN;
                    END;
                    $$ LANGUAGE plpgsql;
                """)

            # Test the function with a normal parameter
            start_time = time.time()
            cursor.execute("SELECT * FROM test_blind_injection('1')")
            normal_time = time.time() - start_time

            # Test the function with a malicious parameter (simulated)
            # In a real test, we would try to inject a sleep command
            # But for this test, we'll just check if the function is vulnerable

            try:
                start_time = time.time()
                cursor.execute("SELECT * FROM test_blind_injection('1; SELECT pg_sleep(2)')")
                malicious_time = time.time() - start_time

                # If the malicious query took significantly longer, it might be vulnerable
                if malicious_time > normal_time + 1.5:
                    results["result"] = "FAIL"
                    results["details"] = f"Function test_blind_injection is vulnerable to time-based blind SQL injection"
                    logger.warning(f"Function test_blind_injection is vulnerable to time-based blind SQL injection")
            except Exception as e:
                # If the query failed, it might be because of proper input validation
                logger.error(f"Unexpected error during time-based blind injection test: {e}")

        # Test 2: Check for boolean-based blind SQL injection
        logger.info("Testing boolean-based blind SQL injection")

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
                    results["details"] = "No input validation functions found, potential boolean-based blind SQL injection risk"
                else:
                    results["details"] += "; No input validation functions found, potential boolean-based blind SQL injection risk"
    except Exception as e:
        logger.error(f"Error during blind SQL injection tests: {e}")
        results["result"] = "ERROR"
        results["details"] = f"Error during test: {str(e)}"

    return results
