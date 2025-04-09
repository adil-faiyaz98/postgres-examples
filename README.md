# PostgreSQL Security Testing Framework

This repository contains a comprehensive security testing framework for PostgreSQL databases. It includes tests for SQL injection, authentication vulnerabilities, encryption, input validation, and configuration issues.

## Overview

The framework is designed to evaluate the security posture of PostgreSQL databases by applying security tiers and running tests against them. It focuses on post-authentication security, testing what an authenticated user could potentially do if they attempted to exploit vulnerabilities.

## Security Tiers

The framework implements three security tiers:

### Basic Security Tier
- Role-based access control
- Strong password hashing (scram-sha-256)
- Restricted superuser access

### Intermediate Security Tier
- Encryption for data at rest using pgcrypto
- Audit logging
- Row-Level Security (RLS)

### Advanced Security Tier
- SSL/TLS for data in transit
- Advanced authentication with password complexity checks
- Intrusion detection mechanisms
- Buffer overflow protection
- SQL injection prevention

## Test Categories

The framework includes 15 test modules across 6 categories:

1. **SQL Injection Tests**
   - Advanced SQL Injection
   - Blind SQL Injection
   - Error-Based SQL Injection
   - Union-Based SQL Injection

2. **Authentication Tests**
   - Privilege Escalation
   - RBAC Testing
   - Weak Credentials

3. **Encryption Tests**
   - Cryptographic Security
   - Data at Rest
   - Data in Transit

4. **Input Validation Tests**
   - Buffer Overflow
   - Malicious Payloads

5. **Configuration Tests**
   - CIS Benchmarks
   - Misconfigurations

6. **Basic Functionality Test**
   - Basic PostgreSQL Test

## Getting Started

### Prerequisites

- PostgreSQL 16 or later
- Python 3.8 or later
- Required Python packages: psycopg2, sqlalchemy, pandas, matplotlib, seaborn

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/adil-faiyaz98/postgres-examples.git
   cd postgres-examples
   ```

2. Install required Python packages:
   ```
   pip install psycopg2 sqlalchemy pandas matplotlib seaborn
   ```

3. Configure your database connection in `tests/config.json`:
   ```json
   {
     "database": {
       "host": "localhost",
       "port": 5433,
       "name": "postgres",
       "user": "postgres",
       "password": "your_password"
     }
   }
   ```

## Running the Tests

### Apply Security Tiers and Run All Tests

To apply all security tiers and run all tests:

```
.\apply_security_fixes.bat
```

This script will:
1. Apply security tiers to your PostgreSQL database
2. Run all security tests
3. Generate a detailed HTML report

### Run SQL Injection Tests Only

To run only the SQL injection and hacking tests:

```
py run_sql_injection_tests.py
```

### Generate Security Report

To generate a detailed security report:

```
py generate_security_report.py
```

After running the tests, open `security_test_report.html` in your browser to view the detailed security report. This report includes:

- Test summary
- Visual charts
- Detailed test results
- Attack attempts and defense mechanisms
- Security tiers effectiveness
- Recommendations

## Understanding the Results

The security report provides a comprehensive view of your database's post-authentication security posture. It shows:

1. Which attack vectors were attempted
2. How the security tiers blocked these attacks
3. Any remaining vulnerabilities
4. Recommendations for further security improvements

## Security Fixes

If vulnerabilities are found, you can apply the security fixes:

```
.\apply_security_fixes.bat
```

This script applies fixes for:
- SQL injection vulnerabilities
- Buffer overflow vulnerabilities
- Configuration weaknesses
- Monitoring gaps

## Project Structure

```
postgres-examples/
├── scripts/
│   └── security_fixes/         # SQL scripts to fix security issues
├── tests/                      # Test modules
│   ├── authentication/         # Authentication tests
│   ├── configuration/          # Configuration tests
│   ├── encryption/             # Encryption tests
│   ├── input_validation/       # Input validation tests
│   ├── sql_injection/          # SQL injection tests
│   ├── base_test.py            # Base test class
│   ├── basic_test.py           # Basic functionality test
│   ├── config.json             # Test configuration
│   └── run_tests.py            # Test runner
├── apply_security_fixes.bat    # Script to apply security fixes
├── generate_security_report.py # Script to generate security report
├── run_sql_injection_tests.py  # Script to run SQL injection tests
├── SECURITY.md                 # Security documentation
└── README.md                   # This file
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- PostgreSQL Security Documentation
- OWASP Database Security Cheat Sheet
- CIS PostgreSQL Benchmark
