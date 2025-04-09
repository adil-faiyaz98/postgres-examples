"""
Data in Transit Encryption Testing Module
This module tests for data in transit encryption vulnerabilities.
"""

import logging

logger = logging.getLogger("security_tests.encryption.data_in_transit")

def run_test(conn, engine, config):
    """
    Run data in transit encryption testing against the database.
    
    Args:
        conn: psycopg2 connection object
        engine: SQLAlchemy engine object
        config: Test configuration dictionary
    
    Returns:
        dict: Test result with category, result, and details
    """
    logger.info("Starting data in transit encryption testing")
    
    # Initialize result
    result = {
        "category": "Encryption",
        "name": "Data in Transit",
        "result": "PASS",
        "details": "No data in transit encryption vulnerabilities detected"
    }
    
    try:
        # Test 1: Check for SSL configuration
        logger.info("Testing SSL configuration")
        
        with conn.cursor() as cursor:
            # Check if SSL is enabled
            cursor.execute("SHOW ssl")
            ssl_enabled = cursor.fetchone()[0]
            
            if ssl_enabled != 'on':
                result["result"] = "FAIL"
                result["details"] = "SSL is not enabled"
                logger.warning("SSL is not enabled")
            else:
                # Check SSL certificate and key files
                cursor.execute("SHOW ssl_cert_file")
                ssl_cert_file = cursor.fetchone()[0]
                
                cursor.execute("SHOW ssl_key_file")
                ssl_key_file = cursor.fetchone()[0]
                
                if not ssl_cert_file or not ssl_key_file:
                    result["result"] = "FAIL"
                    result["details"] = "SSL certificate or key file is not configured"
                    logger.warning("SSL certificate or key file is not configured")
        
        # Test 2: Check for SSL cipher configuration
        logger.info("Testing SSL cipher configuration")
        
        with conn.cursor() as cursor:
            # Check SSL cipher configuration
            cursor.execute("SHOW ssl_ciphers")
            ssl_ciphers = cursor.fetchone()[0]
            
            # Check if weak ciphers are allowed
            weak_ciphers = ['DES', 'RC4', 'MD5', 'NULL']
            has_weak_ciphers = any(cipher in ssl_ciphers for cipher in weak_ciphers)
            
            if has_weak_ciphers:
                if result["result"] == "PASS":
                    result["result"] = "WARNING"
                    result["details"] = "Weak SSL ciphers are allowed"
                else:
                    result["details"] += "; Weak SSL ciphers are allowed"
                
                logger.warning("Weak SSL ciphers are allowed")
        
        # Test 3: Check for SSL protocol version
        logger.info("Testing SSL protocol version")
        
        with conn.cursor() as cursor:
            # Check if the connection is using SSL
            cursor.execute("SELECT ssl_is_used()")
            ssl_is_used = cursor.fetchone()[0]
            
            if not ssl_is_used:
                if result["result"] == "PASS":
                    result["result"] = "WARNING"
                    result["details"] = "Current connection is not using SSL"
                else:
                    result["details"] += "; Current connection is not using SSL"
                
                logger.warning("Current connection is not using SSL")
        
        return result
        
    except Exception as e:
        logger.error(f"Error during data in transit encryption testing: {e}")
        return {
            "category": "Encryption",
            "name": "Data in Transit",
            "result": "ERROR",
            "details": f"Error during data in transit encryption testing: {str(e)}"
        }
