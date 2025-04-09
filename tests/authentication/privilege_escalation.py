"""
Privilege Escalation Test Module
This module tests for privilege escalation vulnerabilities.
"""

import logging

logger = logging.getLogger("security_tests.authentication.privilege_escalation")

def run_test(conn, engine, config):
    """Run the privilege escalation test."""
    logger.info("Starting privilege escalation tests")
    
    results = {
        "category": "Authentication",
        "name": "Privilege Escalation",
        "result": "PASS",
        "details": "No privilege escalation vulnerabilities found"
    }
    
    try:
        # Test 1: Check for function execution privilege escalation
        logger.info("Testing function execution privilege escalation")
        
        # Create a test function for privilege escalation
        with conn.cursor() as cursor:
            # First, check if the function already exists
            cursor.execute("""
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_proc p
                    JOIN pg_namespace n ON p.pronamespace = n.oid
                    WHERE n.nspname = 'public'
                    AND p.proname = 'test_privilege_escalation'
                )
            """)
            function_exists = cursor.fetchone()[0]
            
            if not function_exists:
                # Create a test function
                cursor.execute("""
                    CREATE OR REPLACE FUNCTION test_privilege_escalation()
                    RETURNS text AS $$
                    BEGIN
                        RETURN 'test';
                    END;
                    $$ LANGUAGE plpgsql;
                """)
            
            # Check if the function is defined with SECURITY DEFINER
            cursor.execute("""
                SELECT p.prosecdef
                FROM pg_proc p
                JOIN pg_namespace n ON p.pronamespace = n.oid
                WHERE n.nspname = 'public'
                AND p.proname = 'test_privilege_escalation'
            """)
            is_security_definer = cursor.fetchone()[0]
            
            if is_security_definer:
                results["result"] = "WARNING"
                results["details"] = "Function test_privilege_escalation is defined with SECURITY DEFINER, potential privilege escalation risk"
                logger.warning("Function test_privilege_escalation is defined with SECURITY DEFINER, potential privilege escalation risk")
        
        # Test 2: Check for excessive role privileges
        logger.info("Testing excessive role privileges")
        
        with conn.cursor() as cursor:
            # Check for roles with excessive privileges
            cursor.execute("""
                SELECT r.rolname, r.rolsuper, r.rolinherit, r.rolcreaterole, 
                       r.rolcreatedb, r.rolcanlogin, r.rolreplication
                FROM pg_roles r
                WHERE r.rolname NOT IN ('postgres', 'pg_signal_backend')
                AND (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication)
            """)
            
            privileged_roles = cursor.fetchall()
            
            if privileged_roles:
                role_details = []
                for role in privileged_roles:
                    privileges = []
                    if role[1]:  # rolsuper
                        privileges.append("superuser")
                    if role[3]:  # rolcreaterole
                        privileges.append("create role")
                    if role[4]:  # rolcreatedb
                        privileges.append("create database")
                    if role[6]:  # rolreplication
                        privileges.append("replication")
                    
                    role_details.append(f"{role[0]} ({', '.join(privileges)})")
                
                if results["result"] == "PASS":
                    results["result"] = "WARNING"
                    results["details"] = f"Found roles with excessive privileges: {', '.join(role_details)}"
                else:
                    results["details"] += f"; Found roles with excessive privileges: {', '.join(role_details)}"
                
                logger.warning(f"Found roles with excessive privileges: {', '.join(role_details)}")
    except Exception as e:
        logger.error(f"Error during privilege escalation tests: {e}")
        results["result"] = "ERROR"
        results["details"] = f"Error during test: {str(e)}"
    
    return results
