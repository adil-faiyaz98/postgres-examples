@echo off
echo Applying PostgreSQL Security Tiers and Running Tests

REM Set PostgreSQL connection parameters
set PGHOST=localhost
set PGPORT=5433
set PGDATABASE=postgres
set PGUSER=postgres
set PGPASSWORD=admin

echo.
echo Step 1: Applying security tiers...
cd scripts
"C:\Program Files\PostgreSQL\16\bin\psql.exe" -f apply_all_security_tiers.sql
cd ..

echo.
echo Step 2: Running security tests...
py tests/run_tests.py --config tests/config.json

echo.
echo Process completed!
pause
