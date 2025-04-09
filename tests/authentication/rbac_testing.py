"""
RBAC Testing Module
This module tests for role-based access control vulnerabilities.
"""

import logging

logger = logging.getLogger("security_tests.authentication.rbac_testing")

def run_test(conn, engine, config):
    """
    Run RBAC testing against the database.
    
    Args:
        conn: psycopg2 connection object
        engine: SQLAlchemy engine object
        config: Test configuration dictionary
    
    Returns:
        dict: Test result with category, result, and details
    """
    logger.info("Starting RBAC testing")
    
    # Initialize result
    result = {
        "category": "Authentication",
        "name": "RBAC Testing",
        "result": "PASS",
        "details": "No RBAC vulnerabilities detected"
    }
    
    try:
        # Test 1: Check for proper role separation
        logger.info("Testing role separation")
        
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
                
                result["result"] = "WARNING"
                result["details"] = f"Found roles with excessive privileges: {', '.join(role_details)}"
                logger.warning(f"Found roles with excessive privileges: {', '.join(role_details)}")
        
        # Test 2: Check for proper object ownership
        logger.info("Testing object ownership")
        
        with conn.cursor() as cursor:
            # Check for objects owned by superusers
            cursor.execute("""
                SELECT c.relname, n.nspname, r.rolname
                FROM pg_class c
                JOIN pg_namespace n ON c.relnamespace = n.oid
                JOIN pg_roles r ON c.relowner = r.oid
                WHERE r.rolsuper
                AND n.nspname NOT IN ('pg_catalog', 'information_schema')
                AND c.relkind IN ('r', 'v', 'm', 'S', 'f')
                LIMIT 10
            """)
            
            superuser_objects = cursor.fetchall()
            
            if superuser_objects:
                object_details = [f"{obj[1]}.{obj[0]} (owned by {obj[2]})" for obj in superuser_objects]
                
                if result["result"] == "PASS":
                    result["result"] = "WARNING"
                    result["details"] = f"Found objects owned by superusers: {', '.join(object_details[:5])}..."
                else:
                    result["details"] += f"; Found objects owned by superusers: {', '.join(object_details[:5])}..."
                
                logger.warning(f"Found objects owned by superusers: {', '.join(object_details[:5])}...")
        
        return result
        
    except Exception as e:
        logger.error(f"Error during RBAC testing: {e}")
        return {
            "category": "Authentication",
            "name": "RBAC Testing",
            "result": "ERROR",
            "details": f"Error during RBAC testing: {str(e)}"
        }
