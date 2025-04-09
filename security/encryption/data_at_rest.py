"""
Data at Rest Encryption Test Module
Tests for data at rest encryption vulnerabilities in PostgreSQL.
"""

import logging
import re
from security.base_test import BaseSecurityTest

logger = logging.getLogger("security_tests")

class DataAtRestEncryptionTest(BaseSecurityTest):
    """Test for data at rest encryption vulnerabilities."""
    
    def run(self):
        """Run the test and return results."""
        logger.info("Running Data at Rest Encryption Test")
        
        # Test 1: Check for encrypted columns
        self._test_encrypted_columns()
        
        # Test 2: Check for pgcrypto extension
        self._test_pgcrypto_extension()
        
        # Test 3: Check for key management
        self._test_key_management()
        
        # Test 4: Check for sensitive data in tables
        self._test_sensitive_data()
        
        return self.results
    
    def _test_encrypted_columns(self):
        """Test for encrypted columns."""
        try:
            # Check for columns that might contain sensitive data
            sensitive_columns = self.execute_query("""
                SELECT table_schema, table_name, column_name, data_type
                FROM information_schema.columns
                WHERE (column_name LIKE '%password%' OR
                       column_name LIKE '%secret%' OR
                       column_name LIKE '%key%' OR
                       column_name LIKE '%token%' OR
                       column_name LIKE '%credit%' OR
                       column_name LIKE '%card%' OR
                       column_name LIKE '%ssn%' OR
                       column_name LIKE '%social%' OR
                       column_name LIKE '%account%' OR
                       column_name LIKE '%routing%' OR
                       column_name LIKE '%license%')
                AND table_schema NOT IN ('pg_catalog', 'information_schema')
            """)
            
            if sensitive_columns:
                # Check which ones are potentially unencrypted
                unencrypted_columns = []
                for schema, table, column, data_type in sensitive_columns:
                    # Check if the column is likely unencrypted
                    if data_type in ('character varying', 'text', 'character', 'varchar'):
                        unencrypted_columns.append(f"{schema}.{table}.{column} ({data_type})")
                
                if unencrypted_columns:
                    self.add_result(
                        "Encrypted Columns",
                        "FAIL",
                        f"Found {len(unencrypted_columns)} potentially unencrypted sensitive columns: {', '.join(unencrypted_columns)}"
                    )
                else:
                    self.add_result(
                        "Encrypted Columns",
                        "PASS",
                        f"All {len(sensitive_columns)} sensitive columns appear to be using appropriate data types for encryption"
                    )
            else:
                self.add_result(
                    "Encrypted Columns",
                    "PASS",
                    "No sensitive columns found"
                )
                
        except Exception as e:
            logger.error(f"Error in _test_encrypted_columns: {e}")
            self.add_result(
                "Encrypted Columns",
                "ERROR",
                f"Error testing encrypted columns: {str(e)}"
            )
    
    def _test_pgcrypto_extension(self):
        """Test for pgcrypto extension."""
        try:
            # Check if pgcrypto extension is installed
            pgcrypto = self.execute_query("""
                SELECT extname, extversion
                FROM pg_extension
                WHERE extname = 'pgcrypto'
            """)
            
            if pgcrypto:
                self.add_result(
                    "pgcrypto Extension",
                    "PASS",
                    f"pgcrypto extension is installed (version: {pgcrypto[0][1]})"
                )
                
                # Check for functions using pgcrypto
                pgcrypto_usage = self.execute_query("""
                    SELECT n.nspname as schema, p.proname as name
                    FROM pg_proc p
                    JOIN pg_namespace n ON p.pronamespace = n.oid
                    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
                    AND pg_get_functiondef(p.oid) ~* 'encrypt|decrypt|digest|hmac|gen_salt|crypt|pgp'
                """)
                
                if pgcrypto_usage:
                    function_names = [f"{schema}.{name}" for schema, name in pgcrypto_usage]
                    self.add_result(
                        "pgcrypto Usage",
                        "PASS",
                        f"Found {len(pgcrypto_usage)} functions using pgcrypto: {', '.join(function_names)}"
                    )
                else:
                    self.add_result(
                        "pgcrypto Usage",
                        "WARNING",
                        "pgcrypto extension is installed but not used in any functions"
                    )
            else:
                self.add_result(
                    "pgcrypto Extension",
                    "FAIL",
                    "pgcrypto extension is not installed"
                )
                
        except Exception as e:
            logger.error(f"Error in _test_pgcrypto_extension: {e}")
            self.add_result(
                "pgcrypto Extension",
                "ERROR",
                f"Error testing pgcrypto extension: {str(e)}"
            )
    
    def _test_key_management(self):
        """Test for key management."""
        try:
            # Check for key management tables
            key_tables = self.execute_query("""
                SELECT table_schema, table_name
                FROM information_schema.tables
                WHERE (table_name LIKE '%key%' OR
                       table_name LIKE '%encrypt%' OR
                       table_name LIKE '%secret%')
                AND table_schema NOT IN ('pg_catalog', 'information_schema')
            """)
            
            if key_tables:
                key_table_names = [f"{schema}.{table}" for schema, table in key_tables]
                
                # Check for key rotation functions
                key_rotation_functions = self.execute_query("""
                    SELECT n.nspname as schema, p.proname as name
                    FROM pg_proc p
                    JOIN pg_namespace n ON p.pronamespace = n.oid
                    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
                    AND (p.proname LIKE '%rotate%' OR
                         p.proname LIKE '%key%' OR
                         p.proname LIKE '%encrypt%')
                """)
                
                if key_rotation_functions:
                    function_names = [f"{schema}.{name}" for schema, name in key_rotation_functions]
                    self.add_result(
                        "Key Management",
                        "PASS",
                        f"Found key management tables ({', '.join(key_table_names)}) and key rotation functions ({', '.join(function_names)})"
                    )
                else:
                    self.add_result(
                        "Key Management",
                        "WARNING",
                        f"Found key management tables ({', '.join(key_table_names)}) but no key rotation functions"
                    )
            else:
                self.add_result(
                    "Key Management",
                    "FAIL",
                    "No key management tables found"
                )
                
        except Exception as e:
            logger.error(f"Error in _test_key_management: {e}")
            self.add_result(
                "Key Management",
                "ERROR",
                f"Error testing key management: {str(e)}"
            )
    
    def _test_sensitive_data(self):
        """Test for sensitive data in tables."""
        try:
            # Check for tables with potentially sensitive data
            sensitive_tables = self.execute_query("""
                SELECT table_schema, table_name
                FROM information_schema.tables
                WHERE (table_name LIKE '%user%' OR
                       table_name LIKE '%customer%' OR
                       table_name LIKE '%account%' OR
                       table_name LIKE '%payment%' OR
                       table_name LIKE '%credit%' OR
                       table_name LIKE '%financial%' OR
                       table_name LIKE '%personal%' OR
                       table_name LIKE '%profile%')
                AND table_schema NOT IN ('pg_catalog', 'information_schema')
                AND table_type = 'BASE TABLE'
            """)
            
            if sensitive_tables:
                sensitive_table_names = [f"{schema}.{table}" for schema, table in sensitive_tables]
                
                # Check for data classification
                data_classification = self.execute_query("""
                    SELECT table_schema, table_name
                    FROM information_schema.tables
                    WHERE table_name = 'column_classifications'
                    AND table_schema = 'data_classification'
                """)
                
                if data_classification:
                    # Check if sensitive tables are classified
                    classified_tables = []
                    for schema, table in sensitive_tables:
                        classification = self.execute_query("""
                            SELECT COUNT(*)
                            FROM data_classification.column_classifications
                            WHERE schema_name = %s AND table_name = %s
                        """, (schema, table))
                        
                        if classification and classification[0][0] > 0:
                            classified_tables.append(f"{schema}.{table}")
                    
                    if len(classified_tables) == len(sensitive_table_names):
                        self.add_result(
                            "Data Classification",
                            "PASS",
                            f"All sensitive tables are classified: {', '.join(classified_tables)}"
                        )
                    else:
                        unclassified = set(sensitive_table_names) - set(classified_tables)
                        self.add_result(
                            "Data Classification",
                            "WARNING",
                            f"Found {len(unclassified)} unclassified sensitive tables: {', '.join(unclassified)}"
                        )
                else:
                    self.add_result(
                        "Data Classification",
                        "FAIL",
                        "No data classification system found"
                    )
            else:
                self.add_result(
                    "Data Classification",
                    "PASS",
                    "No sensitive tables found"
                )
                
        except Exception as e:
            logger.error(f"Error in _test_sensitive_data: {e}")
            self.add_result(
                "Data Classification",
                "ERROR",
                f"Error testing sensitive data: {str(e)}"
            )
