"""
Data at Rest Encryption Testing Module
This module tests for data at rest encryption vulnerabilities.
"""

import logging

logger = logging.getLogger("security_tests.encryption.data_at_rest")

def run_test(conn, engine, config):
    """
    Run data at rest encryption testing against the database.
    
    Args:
        conn: psycopg2 connection object
        engine: SQLAlchemy engine object
        config: Test configuration dictionary
    
    Returns:
        dict: Test result with category, result, and details
    """
    logger.info("Starting data at rest encryption testing")
    
    # Initialize result
    result = {
        "category": "Encryption",
        "name": "Data at Rest",
        "result": "PASS",
        "details": "No data at rest encryption vulnerabilities detected"
    }
    
    try:
        # Test 1: Check for pgcrypto extension
        logger.info("Testing for pgcrypto extension")
        
        with conn.cursor() as cursor:
            # Check if pgcrypto extension is installed
            cursor.execute("""
                SELECT extname, extversion
                FROM pg_extension
                WHERE extname = 'pgcrypto'
            """)
            
            pgcrypto = cursor.fetchone()
            
            if not pgcrypto:
                result["result"] = "FAIL"
                result["details"] = "pgcrypto extension is not installed"
                logger.warning("pgcrypto extension is not installed")
        
        # Test 2: Check for encrypted columns
        logger.info("Testing for encrypted columns")
        
        with conn.cursor() as cursor:
            # Check for columns that might contain sensitive data
            cursor.execute("""
                SELECT c.table_schema, c.table_name, c.column_name, c.data_type
                FROM information_schema.columns c
                JOIN information_schema.tables t ON c.table_schema = t.table_schema AND c.table_name = t.table_name
                WHERE t.table_type = 'BASE TABLE'
                AND c.table_schema NOT IN ('pg_catalog', 'information_schema')
                AND (
                    c.column_name LIKE '%password%' OR
                    c.column_name LIKE '%secret%' OR
                    c.column_name LIKE '%key%' OR
                    c.column_name LIKE '%token%' OR
                    c.column_name LIKE '%credit%' OR
                    c.column_name LIKE '%card%' OR
                    c.column_name LIKE '%ssn%' OR
                    c.column_name LIKE '%social%' OR
                    c.column_name LIKE '%account%'
                )
                AND c.data_type NOT IN ('bytea')
                LIMIT 10
            """)
            
            sensitive_columns = cursor.fetchall()
            
            if sensitive_columns:
                column_details = [f"{col[0]}.{col[1]}.{col[2]} ({col[3]})" for col in sensitive_columns]
                
                if result["result"] == "PASS":
                    result["result"] = "WARNING"
                    result["details"] = f"Found potentially sensitive data in non-encrypted columns: {', '.join(column_details[:5])}..."
                else:
                    result["details"] += f"; Found potentially sensitive data in non-encrypted columns: {', '.join(column_details[:5])}..."
                
                logger.warning(f"Found potentially sensitive data in non-encrypted columns: {', '.join(column_details[:5])}...")
        
        return result
        
    except Exception as e:
        logger.error(f"Error during data at rest encryption testing: {e}")
        return {
            "category": "Encryption",
            "name": "Data at Rest",
            "result": "ERROR",
            "details": f"Error during data at rest encryption testing: {str(e)}"
        }
