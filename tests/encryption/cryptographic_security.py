"""
Cryptographic Security Testing Module
This module tests for cryptographic security vulnerabilities.
"""

import logging

logger = logging.getLogger("security_tests.encryption.cryptographic_security")

def run_test(conn, engine, config):
    """
    Run cryptographic security testing against the database.
    
    Args:
        conn: psycopg2 connection object
        engine: SQLAlchemy engine object
        config: Test configuration dictionary
    
    Returns:
        dict: Test result with category, result, and details
    """
    logger.info("Starting cryptographic security tests")
    
    # Initialize result
    result = {
        "category": "Encryption",
        "name": "Cryptographic Security",
        "result": "PASS",
        "details": "No cryptographic security vulnerabilities detected"
    }
    
    try:
        # Test 1: Check if pgcrypto extension is installed
        logger.info("Checking if pgcrypto extension is installed")
        
        with conn.cursor() as cursor:
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
                return result
        
        # Test 2: Check for strong hash functions
        logger.info("Testing for strong hash functions")
        
        with conn.cursor() as cursor:
            # Create a test function to check available hash functions
            cursor.execute("""
                CREATE OR REPLACE FUNCTION test_hash_functions()
                RETURNS TABLE(hash_function text, available boolean) AS $$
                BEGIN
                    RETURN QUERY SELECT 'md5'::text, EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'md5');
                    RETURN QUERY SELECT 'sha1'::text, EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'sha1');
                    RETURN QUERY SELECT 'sha224'::text, EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'sha224');
                    RETURN QUERY SELECT 'sha256'::text, EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'sha256');
                    RETURN QUERY SELECT 'sha384'::text, EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'sha384');
                    RETURN QUERY SELECT 'sha512'::text, EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'sha512');
                    RETURN QUERY SELECT 'pgp_sym_encrypt'::text, EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'pgp_sym_encrypt');
                    RETURN QUERY SELECT 'pgp_pub_encrypt'::text, EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'pgp_pub_encrypt');
                    RETURN QUERY SELECT 'encrypt'::text, EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'encrypt');
                    RETURN QUERY SELECT 'decrypt'::text, EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'decrypt');
                END;
                $$ LANGUAGE plpgsql;
            """)
            
            # Execute the test function
            cursor.execute("SELECT * FROM test_hash_functions()")
            hash_functions = cursor.fetchall()
            
            # Check for weak hash functions
            weak_hash_functions = ['md5', 'sha1']
            strong_hash_functions = ['sha256', 'sha384', 'sha512']
            
            available_weak_functions = [func[0] for func in hash_functions if func[0] in weak_hash_functions and func[1]]
            available_strong_functions = [func[0] for func in hash_functions if func[0] in strong_hash_functions and func[1]]
            
            if available_weak_functions and not available_strong_functions:
                result["result"] = "FAIL"
                result["details"] = f"Only weak hash functions are available: {', '.join(available_weak_functions)}"
                logger.warning(f"Only weak hash functions are available: {', '.join(available_weak_functions)}")
            elif available_weak_functions:
                result["result"] = "WARNING"
                result["details"] = f"Weak hash functions are available: {', '.join(available_weak_functions)}"
                logger.warning(f"Weak hash functions are available: {', '.join(available_weak_functions)}")
        
        # Test 3: Check for encryption functions
        logger.info("Testing for encryption functions")
        
        with conn.cursor() as cursor:
            # Check for encryption functions
            encryption_functions = [func[0] for func in hash_functions if func[0] in ['pgp_sym_encrypt', 'pgp_pub_encrypt', 'encrypt'] and func[1]]
            
            if not encryption_functions:
                if result["result"] == "PASS":
                    result["result"] = "WARNING"
                    result["details"] = "No encryption functions are available"
                else:
                    result["details"] += "; No encryption functions are available"
                
                logger.warning("No encryption functions are available")
        
        return result
        
    except Exception as e:
        logger.error(f"Error during cryptographic security tests: {e}")
        return {
            "category": "Encryption",
            "name": "Cryptographic Security",
            "result": "ERROR",
            "details": f"Error during cryptographic security tests: {str(e)}"
        }
