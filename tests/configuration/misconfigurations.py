"""
Misconfigurations Testing Module
This module tests for database misconfigurations.
"""

import logging

logger = logging.getLogger("security_tests.configuration.misconfigurations")

def run_test(conn, engine, config):
    """
    Run misconfigurations testing against the database.
    
    Args:
        conn: psycopg2 connection object
        engine: SQLAlchemy engine object
        config: Test configuration dictionary
    
    Returns:
        dict: Test result with category, result, and details
    """
    logger.info("Starting misconfigurations testing")
    
    # Initialize result
    result = {
        "category": "Configuration",
        "name": "Misconfigurations",
        "result": "PASS",
        "details": "No database misconfigurations detected"
    }
    
    try:
        # Test 1: Check for public schema permissions
        logger.info("Testing public schema permissions")
        
        with conn.cursor() as cursor:
            # Check public schema permissions
            cursor.execute("""
                SELECT nspacl
                FROM pg_namespace
                WHERE nspname = 'public'
            """)
            
            public_acl = cursor.fetchone()[0]
            
            if public_acl is None or 'public=UC' in public_acl:
                result["result"] = "FAIL"
                result["details"] = "Public schema has excessive permissions"
                logger.warning("Public schema has excessive permissions")
        
        # Test 2: Check for default passwords
        logger.info("Testing for default passwords")
        
        with conn.cursor() as cursor:
            # Check for default passwords (simulated)
            cursor.execute("""
                SELECT rolname
                FROM pg_roles
                WHERE rolname IN ('postgres', 'admin', 'administrator')
                AND rolcanlogin
            """)
            
            default_users = cursor.fetchall()
            
            if default_users:
                user_list = [user[0] for user in default_users]
                
                if result["result"] == "PASS":
                    result["result"] = "WARNING"
                    result["details"] = f"Found default users that might have default passwords: {', '.join(user_list)}"
                else:
                    result["details"] += f"; Found default users that might have default passwords: {', '.join(user_list)}"
                
                logger.warning(f"Found default users that might have default passwords: {', '.join(user_list)}")
        
        # Test 3: Check for excessive permissions
        logger.info("Testing for excessive permissions")
        
        with conn.cursor() as cursor:
            # Check for tables with excessive permissions
            cursor.execute("""
                SELECT c.relname, n.nspname
                FROM pg_class c
                JOIN pg_namespace n ON c.relnamespace = n.oid
                WHERE c.relkind = 'r'
                AND n.nspname NOT IN ('pg_catalog', 'information_schema')
                AND c.relacl::text LIKE '%=arwdDxt/%'
            """)
            
            excessive_tables = cursor.fetchall()
            
            if excessive_tables:
                table_list = [f"{table[1]}.{table[0]}" for table in excessive_tables]
                
                if result["result"] == "PASS":
                    result["result"] = "WARNING"
                    result["details"] = f"Found tables with excessive permissions: {', '.join(table_list[:5])}..."
                else:
                    result["details"] += f"; Found tables with excessive permissions: {', '.join(table_list[:5])}..."
                
                logger.warning(f"Found tables with excessive permissions: {', '.join(table_list[:5])}...")
        
        # Test 4: Check for insecure settings
        logger.info("Testing for insecure settings")
        
        with conn.cursor() as cursor:
            # Check for insecure settings
            cursor.execute("""
                SELECT name, setting
                FROM pg_settings
                WHERE (
                    (name = 'log_connections' AND setting = 'off') OR
                    (name = 'log_disconnections' AND setting = 'off') OR
                    (name = 'log_duration' AND setting = 'off') OR
                    (name = 'log_statement' AND setting = 'none') OR
                    (name = 'log_hostname' AND setting = 'off') OR
                    (name = 'ssl' AND setting = 'off') OR
                    (name = 'password_encryption' AND setting != 'scram-sha-256')
                )
            """)
            
            insecure_settings = cursor.fetchall()
            
            if insecure_settings:
                setting_list = [f"{setting[0]}={setting[1]}" for setting in insecure_settings]
                
                if result["result"] == "PASS":
                    result["result"] = "WARNING"
                    result["details"] = f"Found insecure settings: {', '.join(setting_list)}"
                else:
                    result["details"] += f"; Found insecure settings: {', '.join(setting_list)}"
                
                logger.warning(f"Found insecure settings: {', '.join(setting_list)}")
        
        return result
        
    except Exception as e:
        logger.error(f"Error during misconfigurations testing: {e}")
        return {
            "category": "Configuration",
            "name": "Misconfigurations",
            "result": "ERROR",
            "details": f"Error during misconfigurations testing: {str(e)}"
        }
