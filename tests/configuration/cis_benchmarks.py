"""
CIS Benchmarks Testing Module
This module tests for compliance with CIS benchmarks.
"""

import logging

logger = logging.getLogger("security_tests.configuration.cis_benchmarks")

def run_test(conn, engine, config):
    """
    Run CIS benchmarks testing against the database.
    
    Args:
        conn: psycopg2 connection object
        engine: SQLAlchemy engine object
        config: Test configuration dictionary
    
    Returns:
        dict: Test result with category, result, and details
    """
    logger.info("Starting CIS benchmarks testing")
    
    # Initialize result
    result = {
        "category": "Configuration",
        "name": "CIS Benchmarks",
        "result": "PASS",
        "details": "Database configuration complies with CIS benchmarks"
    }
    
    try:
        # Test 1: Check for secure authentication settings
        logger.info("Testing secure authentication settings")
        
        with conn.cursor() as cursor:
            # Check authentication settings
            cursor.execute("""
                SELECT name, setting
                FROM pg_settings
                WHERE name IN (
                    'password_encryption',
                    'krb_server_keyfile',
                    'ssl',
                    'ssl_cert_file',
                    'ssl_key_file',
                    'ssl_ca_file',
                    'ssl_crl_file'
                )
            """)
            
            settings = {row[0]: row[1] for row in cursor.fetchall()}
            
            issues = []
            
            # Check password encryption
            if settings.get('password_encryption') != 'scram-sha-256':
                issues.append("password_encryption should be set to 'scram-sha-256'")
            
            # Check SSL
            if settings.get('ssl') != 'on':
                issues.append("ssl should be enabled")
            
            if issues:
                result["result"] = "FAIL"
                result["details"] = f"Found {len(issues)} authentication setting issues: {'; '.join(issues)}"
                logger.warning(f"Found {len(issues)} authentication setting issues: {'; '.join(issues)}")
        
        # Test 2: Check for secure logging settings
        logger.info("Testing secure logging settings")
        
        with conn.cursor() as cursor:
            # Check logging settings
            cursor.execute("""
                SELECT name, setting
                FROM pg_settings
                WHERE name IN (
                    'log_connections',
                    'log_disconnections',
                    'log_error_verbosity',
                    'log_hostname',
                    'log_line_prefix',
                    'log_statement',
                    'logging_collector'
                )
            """)
            
            settings = {row[0]: row[1] for row in cursor.fetchall()}
            
            issues = []
            
            # Check connection logging
            if settings.get('log_connections') != 'on':
                issues.append("log_connections should be enabled")
            
            if settings.get('log_disconnections') != 'on':
                issues.append("log_disconnections should be enabled")
            
            if settings.get('log_statement') == 'none':
                issues.append("log_statement should not be set to 'none'")
            
            if settings.get('logging_collector') != 'on':
                issues.append("logging_collector should be enabled")
            
            if issues:
                if result["result"] == "PASS":
                    result["result"] = "FAIL"
                    result["details"] = f"Found {len(issues)} logging setting issues: {'; '.join(issues)}"
                else:
                    result["details"] += f"; Found {len(issues)} logging setting issues: {'; '.join(issues)}"
                
                logger.warning(f"Found {len(issues)} logging setting issues: {'; '.join(issues)}")
        
        # Test 3: Check for secure network settings
        logger.info("Testing secure network settings")
        
        with conn.cursor() as cursor:
            # Check network settings
            cursor.execute("""
                SELECT name, setting
                FROM pg_settings
                WHERE name IN (
                    'listen_addresses',
                    'max_connections',
                    'superuser_reserved_connections',
                    'tcp_keepalives_idle',
                    'tcp_keepalives_interval',
                    'tcp_keepalives_count'
                )
            """)
            
            settings = {row[0]: row[1] for row in cursor.fetchall()}
            
            issues = []
            
            # Check listen_addresses
            if settings.get('listen_addresses') == '*':
                issues.append("listen_addresses should not be set to '*'")
            
            # Check max_connections
            if int(settings.get('max_connections', '0')) > 100:
                issues.append(f"max_connections is set to {settings.get('max_connections')}, which is high")
            
            if issues:
                if result["result"] == "PASS":
                    result["result"] = "WARNING"
                    result["details"] = f"Found {len(issues)} network setting issues: {'; '.join(issues)}"
                else:
                    result["details"] += f"; Found {len(issues)} network setting issues: {'; '.join(issues)}"
                
                logger.warning(f"Found {len(issues)} network setting issues: {'; '.join(issues)}")
        
        return result
        
    except Exception as e:
        logger.error(f"Error during CIS benchmarks testing: {e}")
        return {
            "category": "Configuration",
            "name": "CIS Benchmarks",
            "result": "ERROR",
            "details": f"Error during CIS benchmarks testing: {str(e)}"
        }
