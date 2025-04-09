"""
Basic PostgreSQL Test Module
This module tests basic PostgreSQL functionality.
"""

import logging

logger = logging.getLogger("security_tests.basic_test")

def run_test(conn, engine, config):
    """Run a basic test against the PostgreSQL database."""
    logger.info("Starting basic PostgreSQL test")
    
    results = {
        "category": "Basic",
        "name": "Basic PostgreSQL Test",
        "result": "PASS",
        "details": "Basic PostgreSQL functionality is working correctly"
    }
    
    try:
        # Test 1: Check if the database is running
        logger.info("Testing if the database is running")
        
        with conn.cursor() as cursor:
            cursor.execute("SELECT 1")
            result = cursor.fetchone()[0]
            
            if result != 1:
                results["result"] = "FAIL"
                results["details"] = "Database is not returning expected results"
                logger.warning("Database is not returning expected results")
        
        # Test 2: Check PostgreSQL version
        logger.info("Checking PostgreSQL version")
        
        with conn.cursor() as cursor:
            cursor.execute("SELECT version()")
            version = cursor.fetchone()[0]
            
            logger.info(f"PostgreSQL version: {version}")
            results["details"] += f"; PostgreSQL version: {version}"
        
        # Test 3: Check database name
        logger.info("Checking database name")
        
        with conn.cursor() as cursor:
            cursor.execute("SELECT current_database()")
            database = cursor.fetchone()[0]
            
            logger.info(f"Current database: {database}")
            results["details"] += f"; Current database: {database}"
        
        # Test 4: Check current user
        logger.info("Checking current user")
        
        with conn.cursor() as cursor:
            cursor.execute("SELECT current_user")
            user = cursor.fetchone()[0]
            
            logger.info(f"Current user: {user}")
            results["details"] += f"; Current user: {user}"
        
        return results
        
    except Exception as e:
        logger.error(f"Error during basic PostgreSQL test: {e}")
        results["result"] = "ERROR"
        results["details"] = f"Error during test: {str(e)}"
        return results
