#!/usr/bin/env python3
"""
PostgreSQL Security Test Runner
This script runs all the security tests against a PostgreSQL database.
"""

import os
import sys
import json
import time
import logging
import argparse
import datetime
import psycopg2
import importlib
from sqlalchemy import create_engine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("test_run.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("postgres_tests")

# Add the root directory to the Python path
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

def load_config(config_file):
    """Load configuration from JSON file."""
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load config file: {e}")
        sys.exit(1)

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

def run_test(test_module, conn, engine, config):
    """Run a single test and return the result."""
    try:
        # Import the test module
        module = importlib.import_module(f"tests.{test_module}")

        # Run the test
        start_time = time.time()
        result = module.run_test(conn, engine, config)
        end_time = time.time()

        # Add timing information
        result["duration"] = end_time - start_time

        return result
    except Exception as e:
        logger.error(f"Error running test {test_module}: {e}")
        return {
            "category": "Unknown",
            "name": test_module,
            "result": "ERROR",
            "details": f"Error running test: {str(e)}",
            "duration": 0
        }

def run_all_tests(config, conn, engine):
    """Run all tests and return the results."""
    results = {
        "timestamp": datetime.datetime.now().isoformat(),
        "overall_result": "PASS",
        "tests": []
    }

    # Define test modules to run
    test_modules = [
        "basic_test",
        "sql_injection.advanced_injection",
        "sql_injection.blind",
        "sql_injection.error_based",
        "sql_injection.union_based",
        "authentication.privilege_escalation",
        "authentication.rbac_testing",
        "authentication.weak_credentials",
        "encryption.data_at_rest",
        "encryption.data_in_transit",
        "encryption.cryptographic_security",
        "input_validation.buffer_overflow",
        "input_validation.malicious_payloads",
        "configuration.cis_benchmarks",
        "configuration.misconfigurations"
    ]

    # Run each test
    for test_module in test_modules:
        logger.info(f"Running test: {test_module}")
        result = run_test(test_module, conn, engine, config)
        results["tests"].append(result)

        # Update overall result
        if result["result"] == "FAIL":
            results["overall_result"] = "FAIL"
        elif result["result"] == "ERROR" and results["overall_result"] != "FAIL":
            results["overall_result"] = "ERROR"
        elif result["result"] == "WARNING" and results["overall_result"] not in ["FAIL", "ERROR"]:
            results["overall_result"] = "WARNING"

    return results

def save_results(results, output_file):
    """Save test results to a file."""
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to {output_file}")
    except Exception as e:
        logger.error(f"Failed to save results: {e}")

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="PostgreSQL Security Test Runner")
    parser.add_argument("--config", default="config.json", help="Path to config file")
    parser.add_argument("--output", default="test_results.json", help="Path to output file")
    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config)

    # Connect to the database
    conn, engine = connect_to_database(config)
    if not conn or not engine:
        sys.exit(1)

    try:
        # Run all tests
        results = run_all_tests(config, conn, engine)

        # Save results
        save_results(results, args.output)

        # Print summary
        logger.info(f"Test run completed with overall result: {results['overall_result']}")
        logger.info(f"Total tests: {len(results['tests'])}")
        logger.info(f"Passed: {sum(1 for test in results['tests'] if test['result'] == 'PASS')}")
        logger.info(f"Failed: {sum(1 for test in results['tests'] if test['result'] == 'FAIL')}")
        logger.info(f"Warnings: {sum(1 for test in results['tests'] if test['result'] == 'WARNING')}")
        logger.info(f"Errors: {sum(1 for test in results['tests'] if test['result'] == 'ERROR')}")
    finally:
        # Close the connection
        if conn:
            conn.close()

if __name__ == "__main__":
    main()
