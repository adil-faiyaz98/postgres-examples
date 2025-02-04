\c db_dev;

-- Listen for RLS violation alerts
LISTEN rls_violation;

-- Listen for business rule violations
LISTEN business_rule_violation;

-- Listen for partition management alerts
LISTEN partition_management;

-- Monitor notifications in real-time
SELECT pg_sleep(10); -- Keeps session open to listen for 10 seconds
