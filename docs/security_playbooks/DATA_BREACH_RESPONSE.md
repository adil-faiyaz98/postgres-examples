# Data Breach Response Playbook

This playbook provides detailed procedures for responding to a data breach in the PostgreSQL Security Framework.

## Breach Classification

Data breaches are classified based on the sensitivity of the compromised data:

| Classification | Description | Examples | Response Time |
|----------------|-------------|----------|---------------|
| Critical | Highly sensitive data with regulatory implications | PII, PHI, payment data | Immediate (< 15 minutes) |
| High | Sensitive internal data | Internal documents, intellectual property | < 1 hour |
| Medium | Non-sensitive but proprietary data | Product data, non-sensitive customer data | < 4 hours |
| Low | Public or non-sensitive data | Public documentation, test data | < 24 hours |

## Response Team Roles

- **Incident Commander**: Coordinates the overall response effort
- **Database Security Lead**: Leads technical investigation and containment
- **Legal Counsel**: Advises on legal and regulatory requirements
- **Communications Lead**: Manages internal and external communications
- **Forensics Specialist**: Collects and analyzes evidence
- **Privacy Officer**: Ensures compliance with privacy regulations

## Detection Phase

### Potential Breach Indicators

- Anomalous database activity alerts
- Unusual query patterns or data access
- Unexpected data exports or large result sets
- Unauthorized schema changes
- Reports of data appearing in unauthorized locations

### Initial Assessment

```sql
-- Check for unusual query patterns
SELECT * FROM analytics.get_recent_anomalies(24, 'MEDIUM');

-- Check for large data exports
SELECT usename, query, rows_processed
FROM pg_stat_statements
JOIN pg_stat_activity ON pg_stat_statements.userid = pg_stat_activity.usesysid
WHERE rows_processed > 10000
ORDER BY rows_processed DESC;

-- Check for unauthorized access attempts
SELECT username, source_ip, count(*) as attempt_count
FROM logs.notification_log
WHERE event_type = 'LOGIN_FAILURE'
  AND logged_at > NOW() - INTERVAL '24 hours'
GROUP BY username, source_ip
ORDER BY attempt_count DESC;
```

## Containment Phase

### Immediate Actions

1. **Isolate affected systems**:
   ```sql
   -- Disable network access to the database (system level)
   -- This would be done at the network/firewall level
   
   -- Alternatively, restrict to only specific IPs
   -- Edit pg_hba.conf to restrict access
   ```

2. **Terminate suspicious sessions**:
   ```sql
   -- Identify suspicious sessions
   SELECT pid, usename, client_addr, query, query_start
   FROM pg_stat_activity
   WHERE usename = '[SUSPICIOUS_USER]' OR client_addr = '[SUSPICIOUS_IP]';
   
   -- Terminate suspicious sessions
   SELECT pg_terminate_backend(pid)
   FROM pg_stat_activity
   WHERE pid = [SUSPICIOUS_PID];
   ```

3. **Revoke compromised credentials**:
   ```sql
   -- Disable user account
   ALTER ROLE [COMPROMISED_USER] NOLOGIN;
   
   -- Revoke sensitive privileges
   REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA [SCHEMA_NAME] FROM [COMPROMISED_USER];
   ```

4. **Implement additional access controls**:
   ```sql
   -- Enable row-level security
   ALTER TABLE [AFFECTED_TABLE] ENABLE ROW LEVEL SECURITY;
   
   -- Create restrictive policy
   CREATE POLICY emergency_lockdown ON [AFFECTED_TABLE]
       USING (current_user = 'security_admin');
   ```

## Investigation Phase

### Determine Breach Scope

1. **Identify affected data**:
   ```sql
   -- Check data classification of potentially affected tables
   SELECT schema_name, table_name, column_name, level_name, category_name
   FROM data_classification.classification_overview
   WHERE schema_name = '[AFFECTED_SCHEMA]';
   
   -- Identify accessed tables
   SELECT relname, seq_scan, idx_scan
   FROM pg_stat_user_tables
   WHERE schemaname = '[AFFECTED_SCHEMA]'
   ORDER BY seq_scan + idx_scan DESC;
   ```

2. **Identify access patterns**:
   ```sql
   -- Check query patterns for suspicious user
   SELECT query_pattern, frequency, avg_duration, is_anomalous
   FROM analytics.query_patterns
   WHERE query_pattern LIKE '%[AFFECTED_TABLE]%'
   ORDER BY frequency DESC;
   
   -- Check user activity
   SELECT * FROM analytics.get_user_activity_summary('[SUSPICIOUS_USER]', 30);
   ```

3. **Determine timeline**:
   ```sql
   -- Check first signs of suspicious activity
   SELECT min(logged_at) as first_activity, max(logged_at) as last_activity
   FROM logs.notification_log
   WHERE username = '[SUSPICIOUS_USER]'
     AND event_type IN ('LOGIN_SUCCESS', 'PERMISSION_DENIED', 'QUERY_EXECUTED')
     AND logged_at > NOW() - INTERVAL '30 days';
   ```

### Evidence Collection

1. **Preserve logs**:
   ```sql
   -- Export relevant logs to a secure location
   COPY (
       SELECT *
       FROM logs.notification_log
       WHERE logged_at BETWEEN '[START_TIME]' AND '[END_TIME]'
         AND (username = '[SUSPICIOUS_USER]' OR source_ip = '[SUSPICIOUS_IP]')
   ) TO '/secure/evidence/breach_[INCIDENT_ID]_logs.csv' WITH CSV HEADER;
   
   -- Export query statistics
   COPY (
       SELECT *
       FROM pg_stat_statements
       WHERE query LIKE '%[AFFECTED_TABLE]%'
   ) TO '/secure/evidence/breach_[INCIDENT_ID]_queries.csv' WITH CSV HEADER;
   ```

2. **Capture system state**:
   ```sql
   -- Capture table structure
   COPY (
       SELECT *
       FROM information_schema.columns
       WHERE table_schema = '[AFFECTED_SCHEMA]'
         AND table_name = '[AFFECTED_TABLE]'
   ) TO '/secure/evidence/breach_[INCIDENT_ID]_structure.csv' WITH CSV HEADER;
   
   -- Capture permissions
   COPY (
       SELECT *
       FROM information_schema.role_table_grants
       WHERE table_schema = '[AFFECTED_SCHEMA]'
         AND table_name = '[AFFECTED_TABLE]'
   ) TO '/secure/evidence/breach_[INCIDENT_ID]_permissions.csv' WITH CSV HEADER;
   ```

3. **Document chain of custody**:
   - Record who collected the evidence
   - Record when the evidence was collected
   - Record where the evidence is stored
   - Ensure evidence is cryptographically hashed for integrity verification

## Remediation Phase

### Immediate Remediation

1. **Reset credentials**:
   ```sql
   -- Reset user password
   ALTER ROLE [COMPROMISED_USER] PASSWORD '[NEW_SECURE_PASSWORD]';
   
   -- Or create a new user with appropriate permissions
   CREATE ROLE [NEW_USER] LOGIN PASSWORD '[SECURE_PASSWORD]';
   GRANT [APPROPRIATE_ROLE] TO [NEW_USER];
   ```

2. **Patch vulnerabilities**:
   ```sql
   -- Fix permissions
   REVOKE ALL ON SCHEMA [SCHEMA_NAME] FROM PUBLIC;
   GRANT USAGE ON SCHEMA [SCHEMA_NAME] TO [ROLE_NAME];
   
   -- Implement row-level security
   ALTER TABLE [TABLE_NAME] ENABLE ROW LEVEL SECURITY;
   CREATE POLICY [POLICY_NAME] ON [TABLE_NAME]
       USING (tenant_id = current_setting('app.tenant_id')::INTEGER);
   ```

3. **Implement additional security controls**:
   ```sql
   -- Implement data encryption for sensitive columns
   ALTER TABLE [TABLE_NAME] 
   ADD COLUMN [ENCRYPTED_COLUMN] TEXT GENERATED ALWAYS AS (
       key_management.encrypt([ORIGINAL_COLUMN], 'data_encryption_key')
   ) STORED;
   
   -- Implement audit logging
   CREATE TRIGGER [AUDIT_TRIGGER]
   AFTER INSERT OR UPDATE OR DELETE ON [TABLE_NAME]
   FOR EACH ROW EXECUTE FUNCTION audit.log_change();
   ```

### Long-term Remediation

1. **Implement data minimization**:
   ```sql
   -- Remove unnecessary sensitive data
   UPDATE [TABLE_NAME]
   SET [SENSITIVE_COLUMN] = NULL
   WHERE [RETENTION_CONDITION];
   
   -- Implement data masking
   SELECT privacy.register_column(
       '[SCHEMA_NAME]', '[TABLE_NAME]', '[COLUMN_NAME]',
       'partial_mask', '{"visible_start": 0, "visible_end": 4, "mask_char": "*"}'
   );
   ```

2. **Enhance monitoring**:
   ```sql
   -- Create custom metric for sensitive data access
   SELECT metrics.register_metric(
       'sensitive_data_access',
       'counter',
       'Access to sensitive data tables',
       $$
       SELECT
           count(*) AS value,
           jsonb_build_object('username', usename, 'table', current_query()) AS labels
       FROM pg_stat_activity
       WHERE query LIKE '%[SENSITIVE_TABLE]%'
         AND state = 'active'
       GROUP BY usename
       $$,
       ARRAY['username', 'table'],
       30  -- 30 seconds
   );
   ```

3. **Implement additional authentication requirements**:
   ```sql
   -- Require SSL for all users
   ALTER SYSTEM SET ssl = on;
   
   -- Set shorter session timeout
   ALTER ROLE [USER_ROLE] SET statement_timeout = '15min';
   ```

## Notification Phase

### Regulatory Assessment

1. **Determine notification requirements**:
   - GDPR: 72 hours for EU data subjects
   - CCPA: "Expedient time" for California residents
   - HIPAA: 60 days for PHI breaches
   - PCI-DSS: Immediate notification for payment data

2. **Prepare notification content**:
   - Nature of the breach
   - Types of information compromised
   - Steps taken to protect data
   - Steps individuals should take
   - Contact information for questions

### Stakeholder Communication

1. **Internal communication**:
   - Executive leadership
   - Board of directors
   - Employees

2. **External communication**:
   - Affected individuals
   - Regulatory authorities
   - Law enforcement (if criminal activity suspected)
   - Partners and vendors (if their data was affected)

## Recovery Phase

### Data Integrity Verification

```sql
-- Verify row counts
SELECT count(*) FROM [TABLE_NAME];

-- Verify data integrity
SELECT count(*) FROM [TABLE_NAME] WHERE [INTEGRITY_CHECK_CONDITION];

-- Verify permissions
SELECT grantee, privilege_type
FROM information_schema.role_table_grants
WHERE table_schema = '[SCHEMA_NAME]'
  AND table_name = '[TABLE_NAME]'
ORDER BY grantee, privilege_type;
```

### Service Restoration

```sql
-- Re-enable user access
ALTER ROLE [USER_ROLE] LOGIN;

-- Remove emergency policies
DROP POLICY emergency_lockdown ON [AFFECTED_TABLE];

-- Create appropriate policies
CREATE POLICY [APPROPRIATE_POLICY] ON [AFFECTED_TABLE]
    USING ([APPROPRIATE_CONDITION]);
```

## Post-Incident Activities

### Documentation

Document the incident with:
- Timeline of events
- Actions taken
- Evidence collected
- Root cause analysis
- Lessons learned

### Improvement Actions

```sql
-- Implement enhanced auditing
CREATE OR REPLACE FUNCTION audit.enhanced_log_change()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO audit.log (
            table_name, operation, row_data, changed_by
        ) VALUES (
            TG_TABLE_NAME, TG_OP, row_to_json(NEW), current_user
        );
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO audit.log (
            table_name, operation, row_data, changed_fields, changed_by
        ) VALUES (
            TG_TABLE_NAME, TG_OP, 
            row_to_json(NEW), 
            jsonb_diff_val(row_to_json(OLD)::jsonb, row_to_json(NEW)::jsonb),
            current_user
        );
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO audit.log (
            table_name, operation, row_data, changed_by
        ) VALUES (
            TG_TABLE_NAME, TG_OP, row_to_json(OLD), current_user
        );
        RETURN OLD;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Apply to all sensitive tables
CREATE TRIGGER enhanced_audit_trigger
AFTER INSERT OR UPDATE OR DELETE ON [SENSITIVE_TABLE]
FOR EACH ROW EXECUTE FUNCTION audit.enhanced_log_change();
```

## Appendix: Data Breach Checklist

### Initial Response (First 24 Hours)

- [ ] Assemble response team
- [ ] Assess breach severity and scope
- [ ] Contain the breach
- [ ] Preserve evidence
- [ ] Notify legal counsel
- [ ] Document initial findings

### Investigation (24-72 Hours)

- [ ] Determine how the breach occurred
- [ ] Identify all affected data
- [ ] Determine timeline of the breach
- [ ] Assess regulatory implications
- [ ] Continue evidence collection
- [ ] Update documentation

### Remediation (72+ Hours)

- [ ] Implement immediate fixes
- [ ] Develop long-term remediation plan
- [ ] Test remediation measures
- [ ] Update security controls
- [ ] Prepare notification materials
- [ ] Conduct training if necessary

### Recovery and Closure

- [ ] Verify data integrity
- [ ] Restore normal operations
- [ ] Complete all notifications
- [ ] Conduct post-incident review
- [ ] Update security policies and procedures
- [ ] Implement lessons learned
