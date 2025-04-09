@echo off
echo Applying PostgreSQL Security Fixes

REM Set PostgreSQL connection parameters
set PGHOST=localhost
set PGPORT=5433
set PGDATABASE=postgres
set PGUSER=postgres
set PGPASSWORD=admin

echo.
echo Step 1: Fixing Union-Based SQL Injection Vulnerability...
"C:\Program Files\PostgreSQL\16\bin\psql.exe" -f scripts/security_fixes/fix_union_injection.sql

echo.
echo Step 2: Addressing Buffer Overflow Warnings (Comprehensive Fix)...
"C:\Program Files\PostgreSQL\16\bin\psql.exe" -f scripts/security_fixes/fix_buffer_overflow_comprehensive.sql

echo.
echo Step 3: Enhancing Database Security Configuration...
"C:\Program Files\PostgreSQL\16\bin\psql.exe" -f scripts/security_fixes/enhance_security_config.sql

echo.
echo Step 4: Setting Up Real-time Security Monitoring...
"C:\Program Files\PostgreSQL\16\bin\psql.exe" -f scripts/security_fixes/setup_security_monitoring.sql

echo.
echo Step 5: Running Security Tests to Verify Fixes...
py run_sql_injection_tests.py

echo.
echo Step 6: Generating Updated Security Report...
py generate_security_report.py

echo.
echo Security fixes applied successfully!
echo Please review the security_test_report.html file to verify that the vulnerabilities have been addressed.
pause
