"""
CIS Benchmarks Test Module
Tests for CIS Benchmarks compliance in PostgreSQL.
"""

import logging
from security.base_test import BaseSecurityTest

logger = logging.getLogger("security_tests")

class CISBenchmarksTest(BaseSecurityTest):
    """Test for CIS Benchmarks compliance."""
    
    def run(self):
        """Run the test and return results."""
        logger.info("Running CIS Benchmarks Test")
        
        # Test 1: Check for secure authentication settings
        self._test_authentication_settings()
        
        # Test 2: Check for secure logging settings
        self._test_logging_settings()
        
        # Test 3: Check for secure connection settings
        self._test_connection_settings()
        
        # Test 4: Check for secure file permissions
        self._test_file_permissions()
        
        return self.results
    
    def _test_authentication_settings(self):
        """Test for secure authentication settings."""
        try:
            # Check authentication settings
            auth_settings = self.execute_query("""
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
            
            settings = {row[0]: row[1] for row in auth_settings}
            
            issues = []
            
            # Check password encryption
            if settings.get('password_encryption') != 'scram-sha-256':
                issues.append("password_encryption should be set to 'scram-sha-256'")
            
            # Check SSL
            if settings.get('ssl') != 'on':
                issues.append("ssl should be enabled")
            
            # Check SSL certificate files
            if not settings.get('ssl_cert_file'):
                issues.append("ssl_cert_file should be configured")
            
            if not settings.get('ssl_key_file'):
                issues.append("ssl_key_file should be configured")
            
            if issues:
                self.add_result(
                    "Authentication Settings",
                    "FAIL",
                    f"Found {len(issues)} authentication setting issues: {'; '.join(issues)}"
                )
            else:
                self.add_result(
                    "Authentication Settings",
                    "PASS",
                    "Authentication settings comply with CIS benchmarks"
                )
                
        except Exception as e:
            logger.error(f"Error in _test_authentication_settings: {e}")
            self.add_result(
                "Authentication Settings",
                "ERROR",
                f"Error testing authentication settings: {str(e)}"
            )
    
    def _test_logging_settings(self):
        """Test for secure logging settings."""
        try:
            # Check logging settings
            logging_settings = self.execute_query("""
                SELECT name, setting
                FROM pg_settings
                WHERE name IN (
                    'log_connections',
                    'log_disconnections',
                    'log_error_verbosity',
                    'log_hostname',
                    'log_line_prefix',
                    'log_statement',
                    'logging_collector',
                    'log_duration',
                    'log_min_duration_statement',
                    'log_min_error_statement',
                    'log_min_messages'
                )
            """)
            
            settings = {row[0]: row[1] for row in logging_settings}
            
            issues = []
            
            # Check connection logging
            if settings.get('log_connections') != 'on':
                issues.append("log_connections should be enabled")
            
            if settings.get('log_disconnections') != 'on':
                issues.append("log_disconnections should be enabled")
            
            # Check logging collector
            if settings.get('logging_collector') != 'on':
                issues.append("logging_collector should be enabled")
            
            # Check log line prefix
            log_line_prefix = settings.get('log_line_prefix', '')
            if '%m' not in log_line_prefix or '%u' not in log_line_prefix or '%d' not in log_line_prefix:
                issues.append("log_line_prefix should include %m, %u, and %d")
            
            # Check statement logging
            if settings.get('log_statement') not in ('ddl', 'mod', 'all'):
                issues.append("log_statement should be set to 'ddl', 'mod', or 'all'")
            
            if issues:
                self.add_result(
                    "Logging Settings",
                    "FAIL",
                    f"Found {len(issues)} logging setting issues: {'; '.join(issues)}"
                )
            else:
                self.add_result(
                    "Logging Settings",
                    "PASS",
                    "Logging settings comply with CIS benchmarks"
                )
                
        except Exception as e:
            logger.error(f"Error in _test_logging_settings: {e}")
            self.add_result(
                "Logging Settings",
                "ERROR",
                f"Error testing logging settings: {str(e)}"
            )
    
    def _test_connection_settings(self):
        """Test for secure connection settings."""
        try:
            # Check connection settings
            connection_settings = self.execute_query("""
                SELECT name, setting
                FROM pg_settings
                WHERE name IN (
                    'listen_addresses',
                    'max_connections',
                    'superuser_reserved_connections',
                    'tcp_keepalives_idle',
                    'tcp_keepalives_interval',
                    'tcp_keepalives_count',
                    'shared_buffers',
                    'track_activities',
                    'track_counts'
                )
            """)
            
            settings = {row[0]: row[1] for row in connection_settings}
            
            issues = []
            
            # Check listen addresses
            listen_addresses = settings.get('listen_addresses', '')
            if listen_addresses == '*' or '0.0.0.0' in listen_addresses:
                issues.append("listen_addresses should not be set to '*' or include '0.0.0.0'")
            
            # Check reserved connections
            max_connections = int(settings.get('max_connections', '100'))
            superuser_reserved = int(settings.get('superuser_reserved_connections', '3'))
            if superuser_reserved < max_connections * 0.05:
                issues.append(f"superuser_reserved_connections ({superuser_reserved}) should be at least 5% of max_connections ({max_connections})")
            
            # Check TCP keepalives
            if settings.get('tcp_keepalives_idle') == '0':
                issues.append("tcp_keepalives_idle should be enabled")
            
            if settings.get('tcp_keepalives_interval') == '0':
                issues.append("tcp_keepalives_interval should be enabled")
            
            if settings.get('tcp_keepalives_count') == '0':
                issues.append("tcp_keepalives_count should be enabled")
            
            # Check tracking
            if settings.get('track_activities') != 'on':
                issues.append("track_activities should be enabled")
            
            if settings.get('track_counts') != 'on':
                issues.append("track_counts should be enabled")
            
            if issues:
                self.add_result(
                    "Connection Settings",
                    "FAIL",
                    f"Found {len(issues)} connection setting issues: {'; '.join(issues)}"
                )
            else:
                self.add_result(
                    "Connection Settings",
                    "PASS",
                    "Connection settings comply with CIS benchmarks"
                )
                
        except Exception as e:
            logger.error(f"Error in _test_connection_settings: {e}")
            self.add_result(
                "Connection Settings",
                "ERROR",
                f"Error testing connection settings: {str(e)}"
            )
    
    def _test_file_permissions(self):
        """Test for secure file permissions."""
        try:
            # Since we can't directly check file permissions from SQL,
            # we'll check for settings related to file security
            
            file_settings = self.execute_query("""
                SELECT name, setting
                FROM pg_settings
                WHERE name IN (
                    'data_directory',
                    'hba_file',
                    'ident_file',
                    'external_pid_file',
                    'log_directory',
                    'log_file_mode'
                )
            """)
            
            settings = {row[0]: row[1] for row in file_settings}
            
            issues = []
            
            # Check log file mode
            log_file_mode = settings.get('log_file_mode', '0600')
            if int(log_file_mode, 8) > 0600:
                issues.append(f"log_file_mode ({log_file_mode}) should be 0600 or more restrictive")
            
            if issues:
                self.add_result(
                    "File Permissions",
                    "WARNING",
                    f"Found {len(issues)} file permission issues: {'; '.join(issues)}"
                )
            else:
                self.add_result(
                    "File Permissions",
                    "PASS",
                    "File permission settings comply with CIS benchmarks"
                )
                
            # Add informational message about file permissions
            self.add_result(
                "File Permissions - Manual Check",
                "WARNING",
                "File permissions on data_directory, hba_file, and ident_file should be manually checked"
            )
                
        except Exception as e:
            logger.error(f"Error in _test_file_permissions: {e}")
            self.add_result(
                "File Permissions",
                "ERROR",
                f"Error testing file permissions: {str(e)}"
            )
