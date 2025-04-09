"""
Advanced SQL Injection Test Module
Tests for advanced SQL injection vulnerabilities in PostgreSQL.
"""

import logging
import re
from security.base_test import BaseSecurityTest

logger = logging.getLogger("security_tests")

class AdvancedSQLInjectionTest(BaseSecurityTest):
    """Test for advanced SQL injection vulnerabilities."""
    
    def run(self):
        """Run the test and return results."""
        logger.info("Running Advanced SQL Injection Test")
        
        # Test 1: Check for proper input validation in functions
        self._test_function_input_validation()
        
        # Test 2: Check for SQL injection in dynamic queries
        self._test_dynamic_queries()
        
        # Test 3: Check for SQL injection in stored procedures
        self._test_stored_procedures()
        
        # Test 4: Check for proper error handling
        self._test_error_handling()
        
        return self.results
    
    def _test_function_input_validation(self):
        """Test for proper input validation in functions."""
        try:
            # Get all functions in the database
            functions = self.execute_query("""
                SELECT n.nspname as schema, p.proname as name, pg_get_function_arguments(p.oid) as args
                FROM pg_proc p
                JOIN pg_namespace n ON p.pronamespace = n.oid
                WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
                AND p.prokind = 'f'
            """)
            
            vulnerable_functions = []
            
            for schema, name, args in functions:
                # Check if function has string parameters
                if 'text' in args or 'varchar' in args or 'character' in args:
                    # Check function body for input validation
                    function_body = self.execute_query(f"""
                        SELECT pg_get_functiondef(p.oid)
                        FROM pg_proc p
                        JOIN pg_namespace n ON p.pronamespace = n.oid
                        WHERE n.nspname = %s AND p.proname = %s
                    """, (schema, name))
                    
                    if function_body:
                        body = function_body[0][0]
                        
                        # Check for common input validation patterns
                        has_validation = (
                            re.search(r'RAISE\s+EXCEPTION', body, re.IGNORECASE) or
                            re.search(r'IF\s+.+\s+THEN', body, re.IGNORECASE) or
                            re.search(r'CASE\s+WHEN', body, re.IGNORECASE) or
                            re.search(r'ASSERT', body, re.IGNORECASE) or
                            re.search(r'VALIDATE', body, re.IGNORECASE) or
                            re.search(r'CHECK', body, re.IGNORECASE)
                        )
                        
                        if not has_validation:
                            vulnerable_functions.append(f"{schema}.{name}")
            
            if vulnerable_functions:
                self.add_result(
                    "Function Input Validation",
                    "WARNING",
                    f"Found {len(vulnerable_functions)} functions without apparent input validation: {', '.join(vulnerable_functions)}"
                )
            else:
                self.add_result(
                    "Function Input Validation",
                    "PASS",
                    "All functions appear to have input validation"
                )
                
        except Exception as e:
            logger.error(f"Error in _test_function_input_validation: {e}")
            self.add_result(
                "Function Input Validation",
                "ERROR",
                f"Error testing function input validation: {str(e)}"
            )
    
    def _test_dynamic_queries(self):
        """Test for SQL injection in dynamic queries."""
        try:
            # Check for functions using dynamic SQL
            dynamic_sql_functions = self.execute_query("""
                SELECT n.nspname as schema, p.proname as name
                FROM pg_proc p
                JOIN pg_namespace n ON p.pronamespace = n.oid
                WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
                AND p.prokind = 'f'
                AND pg_get_functiondef(p.oid) ~* 'EXECUTE'
            """)
            
            vulnerable_functions = []
            
            for schema, name in dynamic_sql_functions:
                # Get function definition
                function_body = self.execute_query(f"""
                    SELECT pg_get_functiondef(p.oid)
                    FROM pg_proc p
                    JOIN pg_namespace n ON p.pronamespace = n.oid
                    WHERE n.nspname = %s AND p.proname = %s
                """, (schema, name))
                
                if function_body:
                    body = function_body[0][0]
                    
                    # Check for unsafe dynamic SQL patterns
                    has_unsafe_pattern = (
                        re.search(r'EXECUTE\s+.*\|\|', body, re.IGNORECASE) or
                        re.search(r'EXECUTE\s+.*\+', body, re.IGNORECASE) or
                        re.search(r'EXECUTE\s+.*\|\|.*\$', body, re.IGNORECASE)
                    )
                    
                    # Check for safe patterns (using parameters)
                    has_safe_pattern = (
                        re.search(r'EXECUTE\s+.*USING', body, re.IGNORECASE) or
                        re.search(r'EXECUTE\s+.*\$1', body, re.IGNORECASE) or
                        re.search(r'PREPARE', body, re.IGNORECASE)
                    )
                    
                    if has_unsafe_pattern and not has_safe_pattern:
                        vulnerable_functions.append(f"{schema}.{name}")
            
            if vulnerable_functions:
                self.add_result(
                    "Dynamic SQL Injection",
                    "FAIL",
                    f"Found {len(vulnerable_functions)} functions with potentially unsafe dynamic SQL: {', '.join(vulnerable_functions)}"
                )
            else:
                self.add_result(
                    "Dynamic SQL Injection",
                    "PASS",
                    "No functions with unsafe dynamic SQL patterns found"
                )
                
        except Exception as e:
            logger.error(f"Error in _test_dynamic_queries: {e}")
            self.add_result(
                "Dynamic SQL Injection",
                "ERROR",
                f"Error testing dynamic queries: {str(e)}"
            )
    
    def _test_stored_procedures(self):
        """Test for SQL injection in stored procedures."""
        try:
            # Check for stored procedures using dynamic SQL
            procedures = self.execute_query("""
                SELECT n.nspname as schema, p.proname as name
                FROM pg_proc p
                JOIN pg_namespace n ON p.pronamespace = n.oid
                WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
                AND p.prokind = 'p'
            """)
            
            if not procedures:
                self.add_result(
                    "Stored Procedure Injection",
                    "PASS",
                    "No stored procedures found"
                )
                return
                
            vulnerable_procedures = []
            
            for schema, name in procedures:
                # Get procedure definition
                procedure_body = self.execute_query(f"""
                    SELECT pg_get_functiondef(p.oid)
                    FROM pg_proc p
                    JOIN pg_namespace n ON p.pronamespace = n.oid
                    WHERE n.nspname = %s AND p.proname = %s
                """, (schema, name))
                
                if procedure_body:
                    body = procedure_body[0][0]
                    
                    # Check for unsafe dynamic SQL patterns
                    has_unsafe_pattern = (
                        re.search(r'EXECUTE\s+.*\|\|', body, re.IGNORECASE) or
                        re.search(r'EXECUTE\s+.*\+', body, re.IGNORECASE) or
                        re.search(r'EXECUTE\s+.*\|\|.*\$', body, re.IGNORECASE)
                    )
                    
                    # Check for safe patterns (using parameters)
                    has_safe_pattern = (
                        re.search(r'EXECUTE\s+.*USING', body, re.IGNORECASE) or
                        re.search(r'EXECUTE\s+.*\$1', body, re.IGNORECASE) or
                        re.search(r'PREPARE', body, re.IGNORECASE)
                    )
                    
                    if has_unsafe_pattern and not has_safe_pattern:
                        vulnerable_procedures.append(f"{schema}.{name}")
            
            if vulnerable_procedures:
                self.add_result(
                    "Stored Procedure Injection",
                    "FAIL",
                    f"Found {len(vulnerable_procedures)} procedures with potentially unsafe dynamic SQL: {', '.join(vulnerable_procedures)}"
                )
            else:
                self.add_result(
                    "Stored Procedure Injection",
                    "PASS",
                    "No procedures with unsafe dynamic SQL patterns found"
                )
                
        except Exception as e:
            logger.error(f"Error in _test_stored_procedures: {e}")
            self.add_result(
                "Stored Procedure Injection",
                "ERROR",
                f"Error testing stored procedures: {str(e)}"
            )
    
    def _test_error_handling(self):
        """Test for proper error handling that could leak information."""
        try:
            # Check if error handling is configured properly
            error_handling = self.execute_query("""
                SELECT name, setting
                FROM pg_settings
                WHERE name IN ('log_error_verbosity', 'client_min_messages')
            """)
            
            error_settings = {row[0]: row[1] for row in error_handling}
            
            issues = []
            
            if error_settings.get('log_error_verbosity') == 'VERBOSE':
                issues.append("log_error_verbosity is set to VERBOSE, which may leak sensitive information")
                
            if error_settings.get('client_min_messages') in ('DEBUG', 'LOG'):
                issues.append(f"client_min_messages is set to {error_settings.get('client_min_messages')}, which may leak sensitive information")
            
            if issues:
                self.add_result(
                    "Error Handling",
                    "WARNING",
                    f"Potential information leakage through error messages: {'; '.join(issues)}"
                )
            else:
                self.add_result(
                    "Error Handling",
                    "PASS",
                    "Error handling configuration appears secure"
                )
                
        except Exception as e:
            logger.error(f"Error in _test_error_handling: {e}")
            self.add_result(
                "Error Handling",
                "ERROR",
                f"Error testing error handling: {str(e)}"
            )
