\c db_dev;

-- Listen for RLS violation alerts
LISTEN rls_violation;

-- Listen for business rule violations
LISTEN business_rule_violation;

-- Listen for partition management alerts
LISTEN partition_management;
