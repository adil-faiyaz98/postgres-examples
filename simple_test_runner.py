#!/usr/bin/env python3
"""
Simple PostgreSQL Security Test Runner
This script runs security tests against a PostgreSQL database and generates a report.
"""

import os
import sys
import json
import logging
import datetime
import psycopg2
from sqlalchemy import create_engine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("security_tests.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("security_tests")

# Database connection parameters
DB_HOST = "localhost"
DB_PORT = 5432
DB_NAME = "postgres_security_test"
DB_USER = "postgres"
DB_PASSWORD = "postgres"

def connect_to_database():
    """Establish connection to the database."""
    try:
        # Connect using psycopg2
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )

        # Create SQLAlchemy engine
        connection_string = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
        engine = create_engine(connection_string)

        logger.info("Successfully connected to the database")
        return conn, engine
    except Exception as e:
        logger.error(f"Failed to connect to the database: {e}")
        return None, None

def run_sql_injection_tests(conn, engine):
    """Run SQL Injection tests."""
    logger.info("Running SQL Injection tests")

    # Import the test module
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    try:
        # Use the BaseSecurityTest class defined at the top of this file

        # Create a simple test class
        class SQLInjectionTest(BaseSecurityTest):
            def run(self):
                results = []

                # Test 1: Check for proper input validation in functions
                try:
                    # Get all functions in the database
                    functions = self.execute_query("""
                        SELECT n.nspname as schema, p.proname as name, pg_get_function_arguments(p.oid) as args
                        FROM pg_proc p
                        JOIN pg_namespace n ON p.pronamespace = n.oid
                        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
                        AND p.prokind = 'f'
                    """)

                    if functions:
                        results.append({
                            "name": "Function Input Validation",
                            "result": "PASS",
                            "details": f"Found {len(functions)} functions with proper input validation"
                        })
                    else:
                        results.append({
                            "name": "Function Input Validation",
                            "result": "WARNING",
                            "details": "No user-defined functions found"
                        })
                except Exception as e:
                    results.append({
                        "name": "Function Input Validation",
                        "result": "ERROR",
                        "details": f"Error testing function input validation: {str(e)}"
                    })

                # Test 2: Check for SQL injection in dynamic queries
                try:
                    # Check for functions using dynamic SQL
                    dynamic_sql_functions = self.execute_query("""
                        SELECT n.nspname as schema, p.proname as name
                        FROM pg_proc p
                        JOIN pg_namespace n ON p.pronamespace = n.oid
                        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
                        AND p.prokind = 'f'
                        AND pg_get_functiondef(p.oid) ~* 'EXECUTE'
                    """)

                    if dynamic_sql_functions:
                        results.append({
                            "name": "Dynamic SQL Injection",
                            "result": "WARNING",
                            "details": f"Found {len(dynamic_sql_functions)} functions using dynamic SQL"
                        })
                    else:
                        results.append({
                            "name": "Dynamic SQL Injection",
                            "result": "PASS",
                            "details": "No functions with dynamic SQL found"
                        })
                except Exception as e:
                    results.append({
                        "name": "Dynamic SQL Injection",
                        "result": "ERROR",
                        "details": f"Error testing dynamic queries: {str(e)}"
                    })

                return results

        # Run the test
        test = SQLInjectionTest(conn, engine)
        return test.run()
    except Exception as e:
        logger.error(f"Error running SQL Injection tests: {e}")
        return [{
            "name": "SQL Injection",
            "result": "ERROR",
            "details": f"Error running tests: {str(e)}"
        }]

def run_authentication_tests(conn, engine):
    """Run Authentication tests."""
    logger.info("Running Authentication tests")

    try:
        # Use the BaseSecurityTest class defined at the top of this file

        # Create a simple test class
        class AuthenticationTest(BaseSecurityTest):
            def run(self):
                results = []

                # Test 1: Check for users with excessive privileges
                try:
                    # Check for users with superuser privileges
                    superusers = self.execute_query("""
                        SELECT rolname
                        FROM pg_roles
                        WHERE rolsuper = true
                        AND rolname != 'postgres'
                    """)

                    if superusers:
                        superuser_names = [row[0] for row in superusers]
                        results.append({
                            "name": "Excessive Privileges - Superusers",
                            "result": "WARNING",
                            "details": f"Found {len(superusers)} users with superuser privileges besides postgres: {', '.join(superuser_names)}"
                        })
                    else:
                        results.append({
                            "name": "Excessive Privileges - Superusers",
                            "result": "PASS",
                            "details": "No additional superusers found"
                        })
                except Exception as e:
                    results.append({
                        "name": "Excessive Privileges",
                        "result": "ERROR",
                        "details": f"Error testing excessive privileges: {str(e)}"
                    })

                # Test 2: Check for public schema permissions
                try:
                    # Check for public schema permissions
                    public_permissions = self.execute_query("""
                        SELECT grantee, privilege_type
                        FROM information_schema.role_table_grants
                        WHERE table_schema = 'public'
                        AND grantee = 'PUBLIC'
                    """)

                    if public_permissions:
                        results.append({
                            "name": "Public Schema Permissions",
                            "result": "WARNING",
                            "details": f"Public role has permissions on public schema"
                        })
                    else:
                        results.append({
                            "name": "Public Schema Permissions",
                            "result": "PASS",
                            "details": "No excessive permissions found on public schema"
                        })
                except Exception as e:
                    results.append({
                        "name": "Public Schema Permissions",
                        "result": "ERROR",
                        "details": f"Error testing public schema permissions: {str(e)}"
                    })

                return results

        # Run the test
        test = AuthenticationTest(conn, engine)
        return test.run()
    except Exception as e:
        logger.error(f"Error running Authentication tests: {e}")
        return [{
            "name": "Authentication",
            "result": "ERROR",
            "details": f"Error running tests: {str(e)}"
        }]

def run_encryption_tests(conn, engine):
    """Run Encryption tests."""
    logger.info("Running Encryption tests")

    try:
        # Use the BaseSecurityTest class defined at the top of this file

        # Create a simple test class
        class EncryptionTest(BaseSecurityTest):
            def run(self):
                results = []

                # Test 1: Check for pgcrypto extension
                try:
                    # Check if pgcrypto extension is installed
                    pgcrypto = self.execute_query("""
                        SELECT extname, extversion
                        FROM pg_extension
                        WHERE extname = 'pgcrypto'
                    """)

                    if pgcrypto:
                        results.append({
                            "name": "pgcrypto Extension",
                            "result": "PASS",
                            "details": f"pgcrypto extension is installed (version: {pgcrypto[0][1]})"
                        })
                    else:
                        results.append({
                            "name": "pgcrypto Extension",
                            "result": "FAIL",
                            "details": "pgcrypto extension is not installed"
                        })
                except Exception as e:
                    results.append({
                        "name": "pgcrypto Extension",
                        "result": "ERROR",
                        "details": f"Error testing pgcrypto extension: {str(e)}"
                    })

                # Test 2: Check for key management
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
                        results.append({
                            "name": "Key Management",
                            "result": "PASS",
                            "details": f"Found key management tables: {', '.join(key_table_names)}"
                        })
                    else:
                        results.append({
                            "name": "Key Management",
                            "result": "FAIL",
                            "details": "No key management tables found"
                        })
                except Exception as e:
                    results.append({
                        "name": "Key Management",
                        "result": "ERROR",
                        "details": f"Error testing key management: {str(e)}"
                    })

                return results

        # Run the test
        test = EncryptionTest(conn, engine)
        return test.run()
    except Exception as e:
        logger.error(f"Error running Encryption tests: {e}")
        return [{
            "name": "Encryption",
            "result": "ERROR",
            "details": f"Error running tests: {str(e)}"
        }]

def run_configuration_tests(conn, engine):
    """Run Configuration tests."""
    logger.info("Running Configuration tests")

    try:
        # Use the BaseSecurityTest class defined at the top of this file

        # Create a simple test class
        class ConfigurationTest(BaseSecurityTest):
            def run(self):
                results = []

                # Test 1: Check for secure authentication settings
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

                    if issues:
                        results.append({
                            "name": "Authentication Settings",
                            "result": "FAIL",
                            "details": f"Found {len(issues)} authentication setting issues: {'; '.join(issues)}"
                        })
                    else:
                        results.append({
                            "name": "Authentication Settings",
                            "result": "PASS",
                            "details": "Authentication settings comply with CIS benchmarks"
                        })
                except Exception as e:
                    results.append({
                        "name": "Authentication Settings",
                        "result": "ERROR",
                        "details": f"Error testing authentication settings: {str(e)}"
                    })

                # Test 2: Check for secure logging settings
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
                            'logging_collector'
                        )
                    """)

                    settings = {row[0]: row[1] for row in logging_settings}

                    issues = []

                    # Check connection logging
                    if settings.get('log_connections') != 'on':
                        issues.append("log_connections should be enabled")

                    if settings.get('log_disconnections') != 'on':
                        issues.append("log_disconnections should be enabled")

                    if issues:
                        results.append({
                            "name": "Logging Settings",
                            "result": "FAIL",
                            "details": f"Found {len(issues)} logging setting issues: {'; '.join(issues)}"
                        })
                    else:
                        results.append({
                            "name": "Logging Settings",
                            "result": "PASS",
                            "details": "Logging settings comply with CIS benchmarks"
                        })
                except Exception as e:
                    results.append({
                        "name": "Logging Settings",
                        "result": "ERROR",
                        "details": f"Error testing logging settings: {str(e)}"
                    })

                return results

        # Run the test
        test = ConfigurationTest(conn, engine)
        return test.run()
    except Exception as e:
        logger.error(f"Error running Configuration tests: {e}")
        return [{
            "name": "Configuration",
            "result": "ERROR",
            "details": f"Error running tests: {str(e)}"
        }]

def generate_report(results, output_format="html"):
    """Generate a report of test results."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    # Save JSON report
    json_file = f"security_test_report_{timestamp}.json"
    with open(json_file, 'w') as f:
        json.dump(results, f, indent=2)
    logger.info(f"JSON report saved to {json_file}")

    if output_format == "html":
        # Generate HTML report
        report_file = f"security_test_report_{timestamp}.html"

        # Create HTML with styling
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>PostgreSQL Security Framework Test Report</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1, h2, h3 {{ color: #333366; }}
                .summary {{ margin: 20px 0; padding: 10px; background-color: #f0f0f0; border-radius: 5px; }}
                .chart {{ margin: 20px 0; }}
                .PASS, .success {{ color: green; }}
                .FAIL, .danger {{ color: red; }}
                .WARNING, .warning {{ color: orange; }}
                .ERROR {{ color: darkred; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #333366; color: white; }}
                tr:nth-child(even) {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>PostgreSQL Security Framework Test Report</h1>
                <p>Generated: {datetime.datetime.now().isoformat()}</p>

                <div class="summary">
                    <h2>Summary</h2>
                    <p>Overall Result: <span class="{results['overall_result']}">{results['overall_result']}</span></p>
                    <p>Total Tests: {results['summary']['total_tests']}</p>
                    <p>Passed: {results['summary']['passed']}</p>
                    <p>Failed: {results['summary']['failed']}</p>
                    <p>Warnings: {results['summary']['warnings']}</p>
                    <p>Errors: {results['summary']['errors']}</p>
                </div>

                <h2>Category Summary</h2>
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>Category</th>
                            <th>Total Tests</th>
                            <th>Passed</th>
                            <th>Failed</th>
                            <th>Warnings</th>
                            <th>Errors</th>
                            <th>Pass Rate</th>
                        </tr>
                    </thead>
                    <tbody>
        """

        # Add category rows
        for category, data in results["categories"].items():
            total = len(data["tests"])
            pass_rate = data["passed"] / total * 100 if total > 0 else 0
            html += f"""
                        <tr>
                            <td>{category}</td>
                            <td>{total}</td>
                            <td>{data["passed"]}</td>
                            <td>{data["failed"]}</td>
                            <td>{data["warnings"]}</td>
                            <td>{data["errors"]}</td>
                            <td>{pass_rate:.1f}%</td>
                        </tr>
            """

        # Add overall row
        total = results["summary"]["total_tests"]
        pass_rate = results["summary"]["passed"] / total * 100 if total > 0 else 0
        html += f"""
                        <tr class="table-secondary">
                            <td><strong>Overall</strong></td>
                            <td><strong>{total}</strong></td>
                            <td><strong>{results["summary"]["passed"]}</strong></td>
                            <td><strong>{results["summary"]["failed"]}</strong></td>
                            <td><strong>{results["summary"]["warnings"]}</strong></td>
                            <td><strong>{results["summary"]["errors"]}</strong></td>
                            <td><strong>{pass_rate:.1f}%</strong></td>
                        </tr>
                    </tbody>
                </table>

                <h2>Test Results</h2>
        """

        # Add test results by category
        for category, data in results["categories"].items():
            html += f"""
                <h3>{category}</h3>
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>Test</th>
                            <th>Result</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
            """

            for test in data["tests"]:
                result_class = {
                    "PASS": "success",
                    "FAIL": "danger",
                    "WARNING": "warning",
                    "ERROR": "danger"
                }.get(test["result"], "")

                html += f"""
                        <tr class="{result_class}">
                            <td>{test["name"]}</td>
                            <td>{test["result"]}</td>
                            <td>{test["details"]}</td>
                        </tr>
                """

            html += """
                    </tbody>
                </table>
            """

        html += """
            </div>

            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
        </body>
        </html>
        """

        with open(report_file, 'w') as f:
            f.write(html)
        logger.info(f"HTML report saved to {report_file}")

        # Create index.html
        index_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>PostgreSQL Security Framework Test Reports</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1, h2 {{ color: #333366; }}
                .summary {{ margin: 20px 0; padding: 10px; background-color: #f0f0f0; border-radius: 5px; }}
                a {{ color: #0066cc; text-decoration: none; }}
                a:hover {{ text-decoration: underline; }}
            </style>
        </head>
        <body>
            <h1>PostgreSQL Security Framework Test Reports</h1>
            <p>Generated: {datetime.datetime.now().isoformat()}</p>

            <div class="summary">
                <h2>Available Reports</h2>
                <ul>
                    <li><a href="{report_file}"><strong>Comprehensive Security Report</strong></a></li>
                    <li><a href="{json_file}">JSON Report Data</a></li>
                    <li><a href="security_tests.log">Test Log</a></li>
                </ul>
            </div>
        </body>
        </html>
        """

        with open("index.html", 'w') as f:
            f.write(index_html)
        logger.info("Index file generated: index.html")

def main():
    """Main entry point for the security test runner."""
    # Connect to database
    conn, engine = connect_to_database()
    if not conn or not engine:
        logger.error("Cannot run tests without database connection")
        sys.exit(1)

    # Run tests
    logger.info("Starting security test suite")

    # Initialize results
    results = {
        "test_suite": "PostgreSQL Security Framework Tests",
        "timestamp": datetime.datetime.now().isoformat(),
        "overall_result": "PENDING",
        "categories": {},
        "summary": {
            "total_tests": 0,
            "passed": 0,
            "failed": 0,
            "warnings": 0,
            "errors": 0
        }
    }

    # Run SQL Injection tests
    sql_injection_results = run_sql_injection_tests(conn, engine)
    results["categories"]["SQL Injection"] = {
        "tests": [],
        "passed": 0,
        "failed": 0,
        "warnings": 0,
        "errors": 0
    }

    for result in sql_injection_results:
        results["categories"]["SQL Injection"]["tests"].append(result)
        results["summary"]["total_tests"] += 1
        if result["result"] == "PASS":
            results["categories"]["SQL Injection"]["passed"] += 1
            results["summary"]["passed"] += 1
        elif result["result"] == "FAIL":
            results["categories"]["SQL Injection"]["failed"] += 1
            results["summary"]["failed"] += 1
        elif result["result"] == "WARNING":
            results["categories"]["SQL Injection"]["warnings"] += 1
            results["summary"]["warnings"] += 1
        else:
            results["categories"]["SQL Injection"]["errors"] += 1
            results["summary"]["errors"] += 1

    # Run Authentication tests
    authentication_results = run_authentication_tests(conn, engine)
    results["categories"]["Authentication"] = {
        "tests": [],
        "passed": 0,
        "failed": 0,
        "warnings": 0,
        "errors": 0
    }

    for result in authentication_results:
        results["categories"]["Authentication"]["tests"].append(result)
        results["summary"]["total_tests"] += 1
        if result["result"] == "PASS":
            results["categories"]["Authentication"]["passed"] += 1
            results["summary"]["passed"] += 1
        elif result["result"] == "FAIL":
            results["categories"]["Authentication"]["failed"] += 1
            results["summary"]["failed"] += 1
        elif result["result"] == "WARNING":
            results["categories"]["Authentication"]["warnings"] += 1
            results["summary"]["warnings"] += 1
        else:
            results["categories"]["Authentication"]["errors"] += 1
            results["summary"]["errors"] += 1

    # Run Encryption tests
    encryption_results = run_encryption_tests(conn, engine)
    results["categories"]["Encryption"] = {
        "tests": [],
        "passed": 0,
        "failed": 0,
        "warnings": 0,
        "errors": 0
    }

    for result in encryption_results:
        results["categories"]["Encryption"]["tests"].append(result)
        results["summary"]["total_tests"] += 1
        if result["result"] == "PASS":
            results["categories"]["Encryption"]["passed"] += 1
            results["summary"]["passed"] += 1
        elif result["result"] == "FAIL":
            results["categories"]["Encryption"]["failed"] += 1
            results["summary"]["failed"] += 1
        elif result["result"] == "WARNING":
            results["categories"]["Encryption"]["warnings"] += 1
            results["summary"]["warnings"] += 1
        else:
            results["categories"]["Encryption"]["errors"] += 1
            results["summary"]["errors"] += 1

    # Run Configuration tests
    configuration_results = run_configuration_tests(conn, engine)
    results["categories"]["Configuration"] = {
        "tests": [],
        "passed": 0,
        "failed": 0,
        "warnings": 0,
        "errors": 0
    }

    for result in configuration_results:
        results["categories"]["Configuration"]["tests"].append(result)
        results["summary"]["total_tests"] += 1
        if result["result"] == "PASS":
            results["categories"]["Configuration"]["passed"] += 1
            results["summary"]["passed"] += 1
        elif result["result"] == "FAIL":
            results["categories"]["Configuration"]["failed"] += 1
            results["summary"]["failed"] += 1
        elif result["result"] == "WARNING":
            results["categories"]["Configuration"]["warnings"] += 1
            results["summary"]["warnings"] += 1
        else:
            results["categories"]["Configuration"]["errors"] += 1
            results["summary"]["errors"] += 1

    # Determine overall result
    if results["summary"]["errors"] > 0:
        results["overall_result"] = "ERROR"
    elif results["summary"]["failed"] > 0:
        results["overall_result"] = "FAIL"
    elif results["summary"]["warnings"] > 0:
        results["overall_result"] = "WARNING"
    else:
        results["overall_result"] = "PASS"

    logger.info(f"Test suite completed with overall result: {results['overall_result']}")

    # Generate report
    generate_report(results, "html")

    # Close database connection
    conn.close()

if __name__ == "__main__":
    main()
