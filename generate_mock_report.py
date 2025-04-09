#!/usr/bin/env python3
"""
Mock Security Report Generator
This script generates a mock security report for demonstration purposes.
"""

import json
import datetime
import os
import random

# Create mock test results
def generate_mock_results():
    """Generate mock test results."""
    categories = [
        "SQL Injection",
        "Authentication",
        "Encryption",
        "Input Validation",
        "Configuration",
        "Stealth",
        "AI Security",
        "Infrastructure",
        "Insider Threats",
        "Audit",
        "Stored Procedures",
        "Timing Attacks"
    ]
    
    results = {
        "test_suite": "PostgreSQL Security Framework Tests",
        "timestamp": datetime.datetime.now().isoformat(),
        "overall_result": "WARNING",
        "categories": {},
        "summary": {
            "total_tests": 0,
            "passed": 0,
            "failed": 0,
            "warnings": 0,
            "errors": 0
        }
    }
    
    # Generate random test results for each category
    for category in categories:
        num_tests = random.randint(3, 10)
        passed = random.randint(0, num_tests)
        failed = random.randint(0, num_tests - passed)
        warnings = random.randint(0, num_tests - passed - failed)
        errors = num_tests - passed - failed - warnings
        
        results["categories"][category] = {
            "tests": [],
            "passed": passed,
            "failed": failed,
            "warnings": warnings,
            "errors": errors
        }
        
        # Generate individual test results
        for i in range(num_tests):
            if i < passed:
                result = "PASS"
                details = "No vulnerabilities detected"
            elif i < passed + failed:
                result = "FAIL"
                details = f"Vulnerability detected in {category.lower()} test"
            elif i < passed + failed + warnings:
                result = "WARNING"
                details = f"Potential vulnerability detected in {category.lower()} test"
            else:
                result = "ERROR"
                details = f"Error during {category.lower()} test execution"
            
            results["categories"][category]["tests"].append({
                "name": f"{category} Test {i+1}",
                "result": result,
                "details": details,
                "duration": random.uniform(0.1, 5.0),
                "timestamp": datetime.datetime.now().isoformat()
            })
        
        # Update summary statistics
        results["summary"]["total_tests"] += num_tests
        results["summary"]["passed"] += passed
        results["summary"]["failed"] += failed
        results["summary"]["warnings"] += warnings
        results["summary"]["errors"] += errors
    
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

# Generate HTML report
def generate_html_report(results, output_file):
    """Generate an HTML report from test results."""
    # Create HTML for test summary
    summary_html = f"""
    <div class="summary">
        <h2>Summary</h2>
        <p>Overall Result: <span class="{results['overall_result']}">{results['overall_result']}</span></p>
        <p>Total Tests: {results['summary']['total_tests']}</p>
        <p>Passed: {results['summary']['passed']}</p>
        <p>Failed: {results['summary']['failed']}</p>
        <p>Warnings: {results['summary']['warnings']}</p>
        <p>Errors: {results['summary']['errors']}</p>
    </div>
    """
    
    # Create HTML for test details
    test_details_html = ""
    for category, data in results["categories"].items():
        test_details_html += f"<h3>{category}</h3>\n"
        test_details_html += "<table class='table table-striped'>\n"
        test_details_html += "<thead><tr><th>Test</th><th>Result</th><th>Details</th></tr></thead>\n"
        test_details_html += "<tbody>\n"
        
        for test in data["tests"]:
            result_class = {
                "PASS": "success",
                "FAIL": "danger",
                "WARNING": "warning",
                "ERROR": "danger"
            }.get(test["result"], "")
            
            test_details_html += f"<tr class='{result_class}'>"
            test_details_html += f"<td>{test['name']}</td>"
            test_details_html += f"<td>{test['result']}</td>"
            test_details_html += f"<td>{test.get('details', '')}</td>"
            test_details_html += "</tr>\n"
        
        test_details_html += "</tbody></table>\n"
    
    # Create full HTML report
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
            <p>Generated: {results['timestamp']}</p>
            
            {summary_html}
            
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
                    {"".join([f"<tr><td>{category}</td><td>{len(data['tests'])}</td><td>{data['passed']}</td><td>{data['failed']}</td><td>{data['warnings']}</td><td>{data['errors']}</td><td>{data['passed'] / len(data['tests']) * 100:.1f}%</td></tr>" for category, data in results["categories"].items()])}
                    <tr class="table-secondary">
                        <td><strong>Overall</strong></td>
                        <td><strong>{results['summary']['total_tests']}</strong></td>
                        <td><strong>{results['summary']['passed']}</strong></td>
                        <td><strong>{results['summary']['failed']}</strong></td>
                        <td><strong>{results['summary']['warnings']}</strong></td>
                        <td><strong>{results['summary']['errors']}</strong></td>
                        <td><strong>{results['summary']['passed'] / results['summary']['total_tests'] * 100:.1f}%</strong></td>
                    </tr>
                </tbody>
            </table>
            
            <h2>Test Details</h2>
            {test_details_html}
        </div>
        
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    """
    
    # Write HTML report to file
    with open(output_file, 'w') as f:
        f.write(html)

def main():
    """Main entry point for the report generator."""
    # Generate mock results
    results = generate_mock_results()
    
    # Save results to JSON file
    json_file = f"security_test_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(json_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    # Generate HTML report
    html_file = f"security_test_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    generate_html_report(results, html_file)
    
    print(f"Mock JSON report generated: {json_file}")
    print(f"Mock HTML report generated: {html_file}")
    
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
                <li><a href="{html_file}">Latest HTML Report</a></li>
                <li><a href="{json_file}">Latest JSON Report</a></li>
            </ul>
        </div>
    </body>
    </html>
    """
    
    with open("index.html", 'w') as f:
        f.write(index_html)
    
    print(f"Index file generated: index.html")

if __name__ == "__main__":
    main()
