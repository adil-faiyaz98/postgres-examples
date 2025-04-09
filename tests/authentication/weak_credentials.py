"""
Weak Credentials Testing Module
This module tests for weak credential vulnerabilities.
"""

import logging
import hashlib

logger = logging.getLogger("security_tests.authentication.weak_credentials")

def run_test(conn, engine, config):
    """
    Run weak credentials testing against the database.
    
    Args:
        conn: psycopg2 connection object
        engine: SQLAlchemy engine object
        config: Test configuration dictionary
    
    Returns:
        dict: Test result with category, result, and details
    """
    logger.info("Starting weak credentials testing")
    
    # Initialize result
    result = {
        "category": "Authentication",
        "name": "Weak Credentials",
        "result": "PASS",
        "details": "No weak credential vulnerabilities detected"
    }
    
    try:
        # Test 1: Check for weak password hashing algorithms
        logger.info("Testing password hashing algorithms")
        
        with conn.cursor() as cursor:
            # Check password encryption setting
            cursor.execute("SHOW password_encryption")
            password_encryption = cursor.fetchone()[0]
            
            if password_encryption != 'scram-sha-256':
                result["result"] = "FAIL"
                result["details"] = f"Weak password encryption method in use: {password_encryption}"
                logger.warning(f"Weak password encryption method in use: {password_encryption}")
        
        # Test 2: Check for common/default usernames
        logger.info("Testing for common/default usernames")
        
        with conn.cursor() as cursor:
            # Check for common usernames
            common_usernames = ['admin', 'administrator', 'root', 'guest', 'test', 'user', 'postgres']
            
            cursor.execute("""
                SELECT rolname
                FROM pg_roles
                WHERE rolname = ANY(%s)
                AND rolcanlogin
            """, (common_usernames,))
            
            found_usernames = cursor.fetchall()
            
            if found_usernames:
                usernames = [row[0] for row in found_usernames]
                
                if result["result"] == "PASS":
                    result["result"] = "WARNING"
                    result["details"] = f"Found common usernames: {', '.join(usernames)}"
                else:
                    result["details"] += f"; Found common usernames: {', '.join(usernames)}"
                
                logger.warning(f"Found common usernames: {', '.join(usernames)}")
        
        return result
        
    except Exception as e:
        logger.error(f"Error during weak credentials testing: {e}")
        return {
            "category": "Authentication",
            "name": "Weak Credentials",
            "result": "ERROR",
            "details": f"Error during weak credentials testing: {str(e)}"
        }
