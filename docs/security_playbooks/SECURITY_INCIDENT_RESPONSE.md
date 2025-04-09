# Security Incident Response Playbook

This playbook outlines the procedures for responding to security incidents in the PostgreSQL Security Framework.

## Incident Classification

Security incidents are classified into the following severity levels:

| Severity | Description | Response Time | Escalation |
|----------|-------------|---------------|------------|
| Critical | Incidents that pose an immediate threat to the confidentiality, integrity, or availability of sensitive data or critical systems. | Immediate (< 30 minutes) | CISO, CTO |
| High | Incidents that pose a significant threat but are contained or limited in scope. | < 2 hours | Security Team Lead |
| Medium | Incidents that pose a moderate threat with limited impact. | < 8 hours | Security Engineer |
| Low | Incidents that pose a minimal threat with no immediate impact. | < 24 hours | Security Analyst |

## Incident Response Team

- **Incident Commander**: Coordinates the overall response effort
- **Security Analyst**: Performs initial triage and investigation
- **Database Administrator**: Assists with database-specific remediation
- **System Administrator**: Assists with system-level remediation
- **Communications Lead**: Handles internal and external communications

## Incident Response Process

### 1. Detection and Reporting

- Incidents may be detected through:
  - Automated alerts from the monitoring system
  - Anomaly detection system
  - User reports
  - Security scanning tools

- When an incident is detected, immediately create an incident ticket with:
  - Date and time of detection
  - Source of detection
  - Initial severity assessment
  - Brief description of the incident

### 2. Triage and Initial Response

#### For Unauthorized Access Attempts

```sql
-- Check failed login attempts
SELECT username, source_ip, count(*) as attempt_count
FROM logs.notification_log
WHERE event_type = 'LOGIN_FAILURE'
  AND logged_at > NOW() - INTERVAL '24 hours'
GROUP BY username, source_ip
ORDER BY attempt_count DESC;

-- Check if IP is in threat intelligence database
SELECT * FROM threat_intel.check_ip('[SUSPICIOUS_IP]');

-- Temporarily block suspicious IP
INSERT INTO threat_intel.blocklists (name, type, value, data)
VALUES ('incident_response', 'ip', '[SUSPICIOUS_IP]', '{"reason": "Suspicious login attempts", "incident_id": "[INCIDENT_ID]"}');
```

#### For Suspicious Database Activity

```sql
-- Identify suspicious queries
SELECT usename, query, query_start, state
FROM pg_stat_activity
WHERE state = 'active'
  AND query_start < NOW() - INTERVAL '1 hour';

-- Terminate suspicious sessions
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE pid = [SUSPICIOUS_PID];

-- Check for anomalies
SELECT * FROM analytics.get_recent_anomalies(24, 'MEDIUM');
```

#### For Data Exfiltration Attempts

```sql
-- Check for large result sets
SELECT usename, query, rows_processed
FROM pg_stat_statements
JOIN pg_stat_activity ON pg_stat_statements.userid = pg_stat_activity.usesysid
WHERE rows_processed > 10000
ORDER BY rows_processed DESC;

-- Check for unusual data access patterns
SELECT * FROM analytics.get_user_activity_summary('[SUSPICIOUS_USER]', 7);
```

### 3. Containment

#### Immediate Containment Actions

- Isolate affected systems
- Revoke user access if necessary:

```sql
-- Revoke user access
ALTER ROLE [COMPROMISED_USER] NOLOGIN;

-- Terminate all sessions for the user
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE usename = '[COMPROMISED_USER]';
```

- Implement additional monitoring:

```sql
-- Create a custom metric to monitor the specific activity
SELECT metrics.register_metric(
    'incident_[INCIDENT_ID]_activity',
    'counter',
    'Monitoring for incident [INCIDENT_ID]',
    $$
    SELECT
        count(*) AS value,
        jsonb_build_object('username', usename) AS labels
    FROM pg_stat_activity
    WHERE query LIKE '%[SUSPICIOUS_PATTERN]%'
    GROUP BY usename
    $$,
    ARRAY['username'],
    30  -- 30 seconds
);
```

### 4. Investigation

#### Evidence Collection

- Preserve logs:

```sql
-- Export relevant logs to a secure location
COPY (
    SELECT *
    FROM logs.notification_log
    WHERE logged_at BETWEEN '[START_TIME]' AND '[END_TIME]'
      AND (username = '[SUSPICIOUS_USER]' OR source_ip = '[SUSPICIOUS_IP]')
) TO '/secure/evidence/incident_[INCIDENT_ID]_logs.csv' WITH CSV HEADER;
```

- Capture system state:

```sql
-- Capture active connections
COPY (
    SELECT *
    FROM pg_stat_activity
) TO '/secure/evidence/incident_[INCIDENT_ID]_connections.csv' WITH CSV HEADER;

-- Capture query statistics
COPY (
    SELECT *
    FROM pg_stat_statements
) TO '/secure/evidence/incident_[INCIDENT_ID]_queries.csv' WITH CSV HEADER;
```

#### Forensic Analysis

- Analyze query patterns:

```sql
-- Analyze query patterns for the suspicious user
SELECT query_pattern, frequency, avg_duration, is_anomalous, anomaly_score
FROM analytics.query_patterns
WHERE query_pattern LIKE '%[SUSPICIOUS_PATTERN]%'
ORDER BY frequency DESC;
```

- Analyze user behavior:

```sql
-- Analyze user behavior
SELECT *
FROM analytics.user_profiles
WHERE username = '[SUSPICIOUS_USER]';
```

### 5. Remediation

#### For Unauthorized Access

- Reset credentials:

```sql
-- Reset user password
ALTER ROLE [COMPROMISED_USER] PASSWORD '[NEW_SECURE_PASSWORD]';
```

- Implement additional authentication requirements:

```sql
-- Require SSL for the user
ALTER ROLE [COMPROMISED_USER] SET ssl = on;

-- Set shorter session timeout
ALTER ROLE [COMPROMISED_USER] SET statement_timeout = '15min';
```

#### For SQL Injection Attempts

- Implement input validation:

```sql
-- Create a function to sanitize input
CREATE OR REPLACE FUNCTION security.sanitize_input(p_input text)
RETURNS text AS $$
BEGIN
    -- Remove potentially dangerous characters
    RETURN regexp_replace(p_input, '[;''\\-]', '', 'g');
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
```

- Implement prepared statements in application code

#### For Privilege Escalation

- Review and adjust permissions:

```sql
-- Revoke unnecessary privileges
REVOKE ALL ON SCHEMA [SCHEMA_NAME] FROM [COMPROMISED_USER];
GRANT USAGE ON SCHEMA [SCHEMA_NAME] TO [COMPROMISED_USER];
GRANT SELECT ON [NECESSARY_TABLES] TO [COMPROMISED_USER];
```

- Implement row-level security:

```sql
-- Enable row-level security
ALTER TABLE [TABLE_NAME] ENABLE ROW LEVEL SECURITY;

-- Create policy
CREATE POLICY [POLICY_NAME] ON [TABLE_NAME]
    USING (tenant_id = current_setting('app.tenant_id')::INTEGER);
```

### 6. Recovery

- Restore from backup if necessary:

```bash
# Restore from backup
pg_restore -h [HOST] -U [ADMIN_USER] -d [DATABASE] -c [BACKUP_FILE]
```

- Verify data integrity:

```sql
-- Verify row counts
SELECT count(*) FROM [TABLE_NAME];

-- Verify data integrity
SELECT count(*) FROM [TABLE_NAME] WHERE [INTEGRITY_CHECK_CONDITION];
```

- Re-enable services gradually:

```sql
-- Re-enable user login
ALTER ROLE [COMPROMISED_USER] LOGIN;
```

### 7. Post-Incident Activities

#### Documentation

Document the incident with:
- Timeline of events
- Actions taken
- Evidence collected
- Root cause analysis
- Lessons learned

#### Improvement Actions

- Update security controls:

```sql
-- Implement additional monitoring
SELECT metrics.register_metric(
    'security_[VULNERABILITY_TYPE]_attempts',
    'counter',
    'Monitoring for [VULNERABILITY_TYPE] attempts',
    $$
    SELECT
        count(*) AS value,
        jsonb_build_object('username', username) AS labels
    FROM logs.notification_log
    WHERE event_type = '[RELEVANT_EVENT_TYPE]'
      AND logged_at > NOW() - INTERVAL '1 hour'
    GROUP BY username
    $$,
    ARRAY['username'],
    60  -- 1 minute
);
```

- Update threat intelligence:

```sql
-- Add indicators to threat intelligence
SELECT threat_intel.add_indicator(
    'ip',
    '[MALICIOUS_IP]',
    'incident_response',
    TRUE,
    90,
    '{"incident_id": "[INCIDENT_ID]", "reason": "Involved in security incident"}'::jsonb
);
```

## Specific Incident Response Procedures

### 1. Data Breach Response

1. **Identify affected data**:
   ```sql
   -- Identify accessed tables
   SELECT relname, seq_scan, idx_scan
   FROM pg_stat_user_tables
   WHERE schemaname = '[AFFECTED_SCHEMA]'
   ORDER BY seq_scan + idx_scan DESC;
   ```

2. **Assess impact**:
   ```sql
   -- Check data classification
   SELECT * FROM data_classification.get_table_classification('[AFFECTED_SCHEMA]', '[AFFECTED_TABLE]');
   ```

3. **Contain the breach**:
   ```sql
   -- Revoke all access to affected data
   REVOKE ALL ON [AFFECTED_TABLE] FROM PUBLIC;
   ```

4. **Notify affected parties** according to regulatory requirements

### 2. Ransomware Response

1. **Isolate affected systems**
2. **Assess the encryption scope**:
   ```sql
   -- Check for database encryption
   SELECT count(*) FROM pg_catalog.pg_class
   WHERE relname LIKE '%encrypt%' OR relname LIKE '%ransom%';
   ```

3. **Restore from clean backups**:
   ```bash
   # Restore from last known good backup
   pg_restore -h [HOST] -U [ADMIN_USER] -d [DATABASE] -c [BACKUP_FILE]
   ```

4. **Scan for persistence mechanisms**:
   ```sql
   -- Check for suspicious functions
   SELECT proname, prosrc
   FROM pg_proc
   WHERE prosrc LIKE '%encrypt%' OR prosrc LIKE '%ransom%';
   ```

### 3. Insider Threat Response

1. **Identify suspicious activity**:
   ```sql
   -- Check for unusual data access
   SELECT * FROM analytics.detect_user_anomalies();
   ```

2. **Review access logs**:
   ```sql
   -- Review user activity
   SELECT event_type, severity, message, logged_at
   FROM logs.notification_log
   WHERE username = '[SUSPICIOUS_USER]'
   ORDER BY logged_at DESC;
   ```

3. **Implement enhanced monitoring**:
   ```sql
   -- Create trigger to audit all actions
   CREATE TRIGGER [AUDIT_TRIGGER]
   AFTER INSERT OR UPDATE OR DELETE ON [SENSITIVE_TABLE]
   FOR EACH ROW EXECUTE FUNCTION audit.log_change();
   ```

4. **Adjust permissions** based on the principle of least privilege

## Contact Information

- **Security Team**: security@example.com
- **Database Team**: dba@example.com
- **CISO**: ciso@example.com
- **Legal Team**: legal@example.com

## Appendix: Useful Commands

### Database Forensics

```sql
-- Check for recently modified database objects
SELECT nspname, relname, last_vacuum, last_analyze
FROM pg_catalog.pg_stat_user_tables
JOIN pg_catalog.pg_namespace ON pg_stat_user_tables.schemaname = pg_namespace.nspname
ORDER BY greatest(last_vacuum, last_analyze) DESC NULLS LAST;

-- Check for recently created roles
SELECT rolname, rolcreatedb, rolsuper, rolcanlogin, rolvaliduntil
FROM pg_roles
WHERE rolname NOT IN ('postgres', 'pg_signal_backend')
ORDER BY oid DESC;

-- Check for recently granted privileges
SELECT grantor, grantee, table_schema, table_name, privilege_type
FROM information_schema.table_privileges
WHERE grantee NOT IN ('postgres', 'PUBLIC')
ORDER BY table_schema, table_name;
```

### Security Hardening

```sql
-- Enable SSL
ALTER SYSTEM SET ssl = on;
ALTER SYSTEM SET ssl_cert_file = '/path/to/server.crt';
ALTER SYSTEM SET ssl_key_file = '/path/to/server.key';

-- Set password policy
ALTER SYSTEM SET password_encryption = 'scram-sha-256';

-- Limit connection attempts
ALTER SYSTEM SET max_connections = 100;

-- Enable logging
ALTER SYSTEM SET log_connections = on;
ALTER SYSTEM SET log_disconnections = on;
ALTER SYSTEM SET log_statement = 'ddl';
```
