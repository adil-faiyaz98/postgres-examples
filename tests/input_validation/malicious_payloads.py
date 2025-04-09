"""
Malicious Payloads Testing Module
This module tests for malicious payload vulnerabilities.
"""

import logging

logger = logging.getLogger("security_tests.input_validation.malicious_payloads")

def run_test(conn, engine, config):
    """
    Run malicious payloads testing against the database.
    
    Args:
        conn: psycopg2 connection object
        engine: SQLAlchemy engine object
        config: Test configuration dictionary
    
    Returns:
        dict: Test result with category, result, and details
    """
    logger.info("Starting malicious payloads testing")
    
    # Initialize result
    result = {
        "category": "Input Validation",
        "name": "Malicious Payloads",
        "result": "PASS",
        "details": "No malicious payload vulnerabilities detected"
    }
    
    try:
        # Test 1: Check for input validation in functions
        logger.info("Testing for input validation in functions")
        
        with conn.cursor() as cursor:
            # Check for functions with input validation
            cursor.execute("""
                SELECT n.nspname as schema, p.proname as name
                FROM pg_proc p
                JOIN pg_namespace n ON p.pronamespace = n.oid
                WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
                AND p.prokind = 'f'
                AND pg_get_functiondef(p.oid) ~* 'validate|sanitize|check'
            """)
            
            validation_functions = cursor.fetchall()
            
            if not validation_functions:
                result["result"] = "WARNING"
                result["details"] = "No functions found with explicit input validation"
                logger.warning("No functions found with explicit input validation")
        
        # Test 2: Test for SQL injection in dynamic SQL
        logger.info("Testing for SQL injection in dynamic SQL")
        
        with conn.cursor() as cursor:
            # Check for functions using dynamic SQL
            cursor.execute("""
                SELECT n.nspname as schema, p.proname as name
                FROM pg_proc p
                JOIN pg_namespace n ON p.pronamespace = n.oid
                WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
                AND p.prokind = 'f'
                AND pg_get_functiondef(p.oid) ~* 'EXECUTE'
            """)
            
            dynamic_sql_functions = cursor.fetchall()
            
            if dynamic_sql_functions:
                function_details = [f"{func[0]}.{func[1]}" for func in dynamic_sql_functions]
                
                if result["result"] == "PASS":
                    result["result"] = "WARNING"
                    result["details"] = f"Found {len(dynamic_sql_functions)} functions using dynamic SQL, potential SQL injection risk: {', '.join(function_details[:5])}..."
                else:
                    result["details"] += f"; Found {len(dynamic_sql_functions)} functions using dynamic SQL, potential SQL injection risk: {', '.join(function_details[:5])}..."
                
                logger.warning(f"Found {len(dynamic_sql_functions)} functions using dynamic SQL, potential SQL injection risk")
        
        # Test 3: Test for command injection
        logger.info("Testing for command injection")
        
        with conn.cursor() as cursor:
            # Check for functions using external commands
            cursor.execute("""
                SELECT n.nspname as schema, p.proname as name
                FROM pg_proc p
                JOIN pg_namespace n ON p.pronamespace = n.oid
                WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
                AND p.prokind = 'f'
                AND pg_get_functiondef(p.oid) ~* 'COPY|pg_read_file|pg_write_file'
            """)
            
            command_functions = cursor.fetchall()
            
            if command_functions:
                function_details = [f"{func[0]}.{func[1]}" for func in command_functions]
                
                if result["result"] == "PASS":
                    result["result"] = "WARNING"
                    result["details"] = f"Found {len(command_functions)} functions using external commands, potential command injection risk: {', '.join(function_details[:5])}..."
                else:
                    result["details"] += f"; Found {len(command_functions)} functions using external commands, potential command injection risk: {', '.join(function_details[:5])}..."
                
                logger.warning(f"Found {len(command_functions)} functions using external commands, potential command injection risk")
        
        return result
        
    except Exception as e:
        logger.error(f"Error during malicious payloads testing: {e}")
        return {
            "category": "Input Validation",
            "name": "Malicious Payloads",
            "result": "ERROR",
            "details": f"Error during malicious payloads testing: {str(e)}"
        }
