#!/usr/bin/env python3
"""
PostgreSQL Security Test Runner
This script runs security tests against a PostgreSQL database and generates a report.
"""

import os
import sys
import json
import time
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

def connect_to_database(config):
    """Establish connection to the database."""
    try:
        # Connect using psycopg2
        conn = psycopg2.connect(
            host=config["database"]["host"],
            port=config["database"]["port"],
            database=config["database"]["name"],
            user=config["database"]["user"],
            password=config["database"]["password"]
        )

        # Create SQLAlchemy engine
        connection_string = f"postgresql://{config['database']['user']}:{config['database']['password']}@{config['database']['host']}:{config['database']['port']}/{config['database']['name']}"
        engine = create_engine(connection_string)

        logger.info("Successfully connected to the database")
        return conn, engine
    except Exception as e:
        logger.error(f"Failed to connect to the database: {e}")
        return None, None

def load_config(config_file):
    """Load configuration from JSON file."""
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load config file: {e}")
        sys.exit(1)

def run_tests(conn, engine):
    """Run the security tests."""
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
    try:
        logger.info("Running SQL Injection - Advanced test")

        # Add the current directory to the Python path
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))

        # Import the test module
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from sql_injection.advanced_injection import AdvancedSQLInjectionTest

        # Run the test
        test = AdvancedSQLInjectionTest(conn, engine)
        test_results = test.run()

        # Process results
        if "SQL Injection" not in results["categories"]:
            results["categories"]["SQL Injection"] = {
                "tests": [],
                "passed": 0,
                "failed": 0,
                "warnings": 0,
                "errors": 0
            }

        for result in test_results:
            results["categories"]["SQL Injection"]["tests"].append({
                "name": f"Advanced SQL Injection - {result['name']}",
                "result": result["result"],
                "details": result["details"],
                "duration": 0,
                "timestamp": datetime.datetime.now().isoformat()
            })

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
    except Exception as e:
        logger.error(f"Error running SQL Injection - Advanced test: {e}")

        if "SQL Injection" not in results["categories"]:
            results["categories"]["SQL Injection"] = {
                "tests": [],
                "passed": 0,
                "failed": 0,
                "warnings": 0,
                "errors": 0
            }

        results["categories"]["SQL Injection"]["tests"].append({
            "name": "Advanced SQL Injection",
            "result": "ERROR",
            "details": f"Error running test: {str(e)}",
            "duration": 0,
            "timestamp": datetime.datetime.now().isoformat()
        })

        results["summary"]["total_tests"] += 1
        results["categories"]["SQL Injection"]["errors"] += 1
        results["summary"]["errors"] += 1

    # Run Authentication tests
    try:
        logger.info("Running Authentication - Privilege Escalation test")

        # Import the test module
        from authentication.privilege_escalation import PrivilegeEscalationTest

        # Run the test
        test = PrivilegeEscalationTest(conn, engine)
        test_results = test.run()

        # Process results
        if "Authentication" not in results["categories"]:
            results["categories"]["Authentication"] = {
                "tests": [],
                "passed": 0,
                "failed": 0,
                "warnings": 0,
                "errors": 0
            }

        for result in test_results:
            results["categories"]["Authentication"]["tests"].append({
                "name": f"Privilege Escalation - {result['name']}",
                "result": result["result"],
                "details": result["details"],
                "duration": 0,
                "timestamp": datetime.datetime.now().isoformat()
            })

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
    except Exception as e:
        logger.error(f"Error running Authentication - Privilege Escalation test: {e}")

        if "Authentication" not in results["categories"]:
            results["categories"]["Authentication"] = {
                "tests": [],
                "passed": 0,
                "failed": 0,
                "warnings": 0,
                "errors": 0
            }

        results["categories"]["Authentication"]["tests"].append({
            "name": "Privilege Escalation",
            "result": "ERROR",
            "details": f"Error running test: {str(e)}",
            "duration": 0,
            "timestamp": datetime.datetime.now().isoformat()
        })

        results["summary"]["total_tests"] += 1
        results["categories"]["Authentication"]["errors"] += 1
        results["summary"]["errors"] += 1

    # Run Encryption tests
    try:
        logger.info("Running Encryption - Data at Rest test")

        # Import the test module
        from encryption.data_at_rest import DataAtRestEncryptionTest

        # Run the test
        test = DataAtRestEncryptionTest(conn, engine)
        test_results = test.run()

        # Process results
        if "Encryption" not in results["categories"]:
            results["categories"]["Encryption"] = {
                "tests": [],
                "passed": 0,
                "failed": 0,
                "warnings": 0,
                "errors": 0
            }

        for result in test_results:
            results["categories"]["Encryption"]["tests"].append({
                "name": f"Data at Rest - {result['name']}",
                "result": result["result"],
                "details": result["details"],
                "duration": 0,
                "timestamp": datetime.datetime.now().isoformat()
            })

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
    except Exception as e:
        logger.error(f"Error running Encryption - Data at Rest test: {e}")

        if "Encryption" not in results["categories"]:
            results["categories"]["Encryption"] = {
                "tests": [],
                "passed": 0,
                "failed": 0,
                "warnings": 0,
                "errors": 0
            }

        results["categories"]["Encryption"]["tests"].append({
            "name": "Data at Rest",
            "result": "ERROR",
            "details": f"Error running test: {str(e)}",
            "duration": 0,
            "timestamp": datetime.datetime.now().isoformat()
        })

        results["summary"]["total_tests"] += 1
        results["categories"]["Encryption"]["errors"] += 1
        results["summary"]["errors"] += 1

    # Run Configuration tests
    try:
        logger.info("Running Configuration - CIS Benchmarks test")

        # Import the test module
        from configuration.cis_benchmarks import CISBenchmarksTest

        # Run the test
        test = CISBenchmarksTest(conn, engine)
        test_results = test.run()

        # Process results
        if "Configuration" not in results["categories"]:
            results["categories"]["Configuration"] = {
                "tests": [],
                "passed": 0,
                "failed": 0,
                "warnings": 0,
                "errors": 0
            }

        for result in test_results:
            results["categories"]["Configuration"]["tests"].append({
                "name": f"CIS Benchmarks - {result['name']}",
                "result": result["result"],
                "details": result["details"],
                "duration": 0,
                "timestamp": datetime.datetime.now().isoformat()
            })

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
    except Exception as e:
        logger.error(f"Error running Configuration - CIS Benchmarks test: {e}")

        if "Configuration" not in results["categories"]:
            results["categories"]["Configuration"] = {
                "tests": [],
                "passed": 0,
                "failed": 0,
                "warnings": 0,
                "errors": 0
            }

        results["categories"]["Configuration"]["tests"].append({
            "name": "CIS Benchmarks",
            "result": "ERROR",
            "details": f"Error running test: {str(e)}",
            "duration": 0,
            "timestamp": datetime.datetime.now().isoformat()
        })

        results["summary"]["total_tests"] += 1
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

    return results

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
                <p>Generated: {results["timestamp"]}</p>

                <div class="summary">
                    <h2>Summary</h2>
                    <p>Overall Result: <span class="{results["overall_result"]}">{results["overall_result"]}</span></p>
                    <p>Total Tests: {results["summary"]["total_tests"]}</p>
                    <p>Passed: {results["summary"]["passed"]}</p>
                    <p>Failed: {results["summary"]["failed"]}</p>
                    <p>Warnings: {results["summary"]["warnings"]}</p>
                    <p>Errors: {results["summary"]["errors"]}</p>
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
            <p>Generated: {results["timestamp"]}</p>

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
    import argparse

    parser = argparse.ArgumentParser(description="PostgreSQL Security Test Runner")
    parser.add_argument("--config", default="docker_config.json", help="Path to configuration file")
    parser.add_argument("--output", default="html", choices=["json", "html"], help="Output format for the report")
    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config)

    # Connect to database
    conn, engine = connect_to_database(config)
    if not conn or not engine:
        logger.error("Cannot run tests without database connection")
        sys.exit(1)

    # Run tests
    logger.info("Starting security test suite")
    results = run_tests(conn, engine)
    logger.info(f"Test suite completed with overall result: {results['overall_result']}")

    # Generate report
    generate_report(results, args.output)

    # Close database connection
    conn.close()

if __name__ == "__main__":
    main()
