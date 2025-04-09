# Ransomware Response Playbook

This playbook provides detailed procedures for responding to a ransomware attack affecting the PostgreSQL Security Framework.

## Ransomware Classification

Ransomware incidents are classified based on the scope and impact:

| Classification | Description | Examples | Response Time |
|----------------|-------------|----------|---------------|
| Critical | Complete database encryption, production systems affected | All data encrypted, operations halted | Immediate (< 15 minutes) |
| High | Partial database encryption, critical systems affected | Some tables encrypted, critical operations impacted | < 30 minutes |
| Medium | Limited encryption, non-critical systems affected | Test/dev environments affected | < 2 hours |
| Low | Attempted encryption, no successful data impact | Failed encryption attempt | < 4 hours |

## Response Team Roles

- **Incident Commander**: Coordinates the overall response effort
- **Database Recovery Lead**: Leads technical recovery operations
- **System Administrator**: Assists with system-level isolation and recovery
- **Forensics Specialist**: Analyzes the ransomware and infection vectors
- **Communications Lead**: Manages internal and external communications
- **Legal Counsel**: Advises on legal implications and ransom considerations

## Detection Phase

### Potential Ransomware Indicators

- Sudden database performance degradation
- Unusual encryption-related queries
- Appearance of ransom notes in the database
- Unexpected schema changes or table modifications
- Unusual system resource utilization
- Database files with changed extensions or corruption

### Initial Assessment

```sql
-- Check for suspicious encryption-related queries
SELECT usename, query, query_start
FROM pg_stat_activity
WHERE query ILIKE '%encrypt%' 
   OR query ILIKE '%crypt%'
   OR query ILIKE '%ransom%';

-- Check for recently modified tables
SELECT schemaname, relname, last_vacuum, last_analyze, 
       last_autoanalyze, last_autovacuum
FROM pg_stat_user_tables
ORDER BY greatest(last_vacuum, last_analyze, 
                 last_autoanalyze, last_autovacuum) DESC NULLS LAST
LIMIT 20;

-- Check for unusual functions that might contain encryption logic
SELECT nspname, proname, prosrc
FROM pg_proc p
JOIN pg_namespace n ON p.pronamespace = n.oid
WHERE prosrc ILIKE '%encrypt%' 
   OR prosrc ILIKE '%crypt%'
   OR prosrc ILIKE '%ransom%'
ORDER BY proname;
```

## Containment Phase

### Immediate Actions

1. **Isolate affected systems**:
   ```bash
   # Disconnect network access to prevent spread
   # This would typically be done at the network/firewall level
   
   # Stop the PostgreSQL service on affected systems
   systemctl stop postgresql
   ```

2. **Preserve evidence**:
   ```bash
   # Create a forensic copy of affected database files
   cp -a /var/lib/postgresql/data /forensics/postgresql_data_copy
   
   # Capture system memory if possible
   # Using tools like LiME or memory acquisition tools
   ```

3. **Identify the ransomware variant**:
   - Look for ransom notes in the database or filesystem
   - Check file signatures and encryption patterns
   - Use ransomware identification tools or services

4. **Document the incident**:
   - Take screenshots of ransom messages
   - Record the timestamp of discovery
   - Document affected systems and databases
   - Record any communication from attackers

## Assessment Phase

### Determine Encryption Scope

1. **Identify affected databases and tables**:
   ```sql
   -- After restarting PostgreSQL in safe mode or on a backup
   -- Check for tables that might be encrypted or corrupted
   
   -- Check for tables that can't be read
   DO $$
   DECLARE
       r RECORD;
       v_error TEXT;
       v_affected_tables TEXT := '';
   BEGIN
       FOR r IN (SELECT schemaname, tablename 
                 FROM pg_tables 
                 WHERE schemaname NOT IN ('pg_catalog', 'information_schema'))
       LOOP
           BEGIN
               EXECUTE 'SELECT count(*) FROM ' || quote_ident(r.schemaname) || '.' || quote_ident(r.tablename) || ' LIMIT 1';
           EXCEPTION WHEN OTHERS THEN
               v_error := SQLERRM;
               v_affected_tables := v_affected_tables || r.schemaname || '.' || r.tablename || ': ' || v_error || E'\n';
           END;
       END LOOP;
       
       IF v_affected_tables <> '' THEN
           RAISE NOTICE 'Potentially affected tables: %', v_affected_tables;
       ELSE
           RAISE NOTICE 'No obviously corrupted tables found.';
       END IF;
   END $$;
   ```

2. **Check database file integrity**:
   ```bash
   # Check PostgreSQL data files for corruption
   cd /var/lib/postgresql/data
   find . -type f -name "*.dat" -exec file {} \; | grep -v "PostgreSQL"
   
   # Look for unusual file extensions that might indicate encryption
   find . -type f -not -name "*.conf" -not -name "*.dat" -not -name "*.wal" | grep -v "pg_"
   ```

3. **Assess backup availability**:
   ```bash
   # List available backups
   ls -la /path/to/backup/directory
   
   # Check the most recent backup timestamp
   stat /path/to/backup/directory/latest_backup
   ```

### Determine Attack Vector

1. **Check for unauthorized access**:
   ```sql
   -- Review recent logins
   SELECT * FROM logs.notification_log
   WHERE event_type = 'LOGIN_SUCCESS'
     AND logged_at > NOW() - INTERVAL '7 days'
   ORDER BY logged_at DESC;
   
   -- Check for unusual source IPs
   SELECT source_ip, count(*) 
   FROM logs.notification_log
   WHERE logged_at > NOW() - INTERVAL '7 days'
   GROUP BY source_ip
   ORDER BY count(*) DESC;
   ```

2. **Check for suspicious processes**:
   ```bash
   # Look for unusual processes
   ps aux | grep -i "crypt\|ransom\|encrypt"
   
   # Check for unusual network connections
   netstat -antup | grep postgres
   ```

3. **Review system logs**:
   ```bash
   # Check authentication logs
   grep "authentication" /var/log/postgresql/*.log
   
   # Check for unusual errors
   grep "ERROR" /var/log/postgresql/*.log | tail -100
   ```

## Recovery Phase

### Decision: Restore from Backup vs. Pay Ransom

> **Important Note**: The decision to pay a ransom should be made only after consulting with legal counsel, law enforcement, and cybersecurity experts. Many law enforcement agencies advise against paying ransoms.

Factors to consider:
- Availability and recency of backups
- Criticality of the encrypted data
- Cost of downtime vs. ransom amount
- Likelihood of receiving decryption keys after payment
- Legal and regulatory implications

### Recovery from Backup

1. **Prepare the environment**:
   ```bash
   # Stop PostgreSQL if still running
   systemctl stop postgresql
   
   # Move or rename the affected data directory
   mv /var/lib/postgresql/data /var/lib/postgresql/data_encrypted
   
   # Create a new data directory
   mkdir -p /var/lib/postgresql/data
   chown postgres:postgres /var/lib/postgresql/data
   chmod 700 /var/lib/postgresql/data
   ```

2. **Restore from backup**:
   ```bash
   # For physical backup (e.g., pg_basebackup)
   cp -a /path/to/backup/directory/* /var/lib/postgresql/data/
   
   # For logical backup (e.g., pg_dump)
   # First initialize a new database
   su - postgres -c "initdb -D /var/lib/postgresql/data"
   
   # Start PostgreSQL
   systemctl start postgresql
   
   # Restore from dump
   su - postgres -c "psql -f /path/to/backup.sql postgres"
   ```

3. **Verify data integrity**:
   ```sql
   -- Check database consistency
   SELECT * FROM pg_stat_database;
   
   -- Run ANALYZE to update statistics
   ANALYZE VERBOSE;
   
   -- Check row counts in critical tables
   SELECT 'public.users' as table_name, count(*) FROM public.users
   UNION ALL
   SELECT 'public.transactions' as table_name, count(*) FROM public.transactions;
   ```

4. **Apply security hardening**:
   ```sql
   -- Reset all user passwords
   ALTER ROLE user1 PASSWORD 'new_secure_password1';
   ALTER ROLE user2 PASSWORD 'new_secure_password2';
   
   -- Revoke unnecessary privileges
   REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
   
   -- Enable enhanced logging
   ALTER SYSTEM SET log_connections = on;
   ALTER SYSTEM SET log_disconnections = on;
   ALTER SYSTEM SET log_statement = 'ddl';
   SELECT pg_reload_conf();
   ```

### If No Viable Backup Exists

1. **Attempt data recovery**:
   - Use PostgreSQL forensic tools to recover data structures
   - Check for unencrypted transaction logs that might allow partial recovery
   - Consider specialized database recovery services

2. **If considering ransom payment**:
   - Consult with legal counsel and law enforcement
   - Verify the legitimacy of the ransomware group (some provide "proof of decryption")
   - Use cryptocurrency experts for payment if decided
   - Document all communications and transactions

3. **After obtaining decryption keys**:
   - Test decryption on non-critical systems first
   - Verify data integrity after decryption
   - Do not trust the decrypted environment - rebuild from scratch after extracting data

## Post-Recovery Phase

### Security Enhancements

1. **Implement database encryption**:
   ```sql
   -- Set up proper encryption using the key management system
   SELECT key_management.generate_key('data_encryption_key', 'AES-256', 365);
   
   -- Encrypt sensitive columns
   ALTER TABLE users 
   ADD COLUMN encrypted_ssn TEXT GENERATED ALWAYS AS (
       key_management.encrypt(ssn, 'data_encryption_key')
   ) STORED;
   ```

2. **Implement enhanced backup strategy**:
   ```bash
   # Set up more frequent backups
   echo "0 */4 * * * postgres /usr/bin/pg_basebackup -D /path/to/backup/directory -F tar -z -X fetch" > /etc/cron.d/postgres_backup
   
   # Ensure backups are stored offline or in immutable storage
   ```

3. **Implement enhanced monitoring**:
   ```sql
   -- Create custom metric for encryption-related activities
   SELECT metrics.register_metric(
       'encryption_activity',
       'counter',
       'Monitoring for encryption-related queries',
       $$
       SELECT
           count(*) AS value,
           jsonb_build_object('username', usename) AS labels
       FROM pg_stat_activity
       WHERE query ILIKE '%encrypt%' OR query ILIKE '%crypt%'
       GROUP BY usename
       $$,
       ARRAY['username'],
       30  -- 30 seconds
   );
   ```

### Root Cause Analysis

Document the following:
- Initial infection vector
- Timeline of the attack
- Lateral movement within systems
- Data exfiltration (if any)
- Encryption methodology
- Missed detection opportunities

### Lessons Learned

1. **Update security policies**:
   - Review and enhance access controls
   - Implement principle of least privilege
   - Enhance network segmentation
   - Improve backup strategies

2. **Conduct training**:
   - Security awareness training for all staff
   - Specific database security training for DBAs
   - Phishing awareness (if relevant to the attack vector)

3. **Update incident response plan**:
   - Incorporate lessons from the incident
   - Conduct tabletop exercises
   - Test backup restoration procedures regularly

## Appendix: Ransomware Prevention Measures

### Database Hardening

```sql
-- Implement row-level security
ALTER TABLE sensitive_data ENABLE ROW LEVEL SECURITY;
CREATE POLICY data_access ON sensitive_data
    USING (tenant_id = current_setting('app.tenant_id')::INTEGER);

-- Implement strict permission model
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO app_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON specific_table TO app_role;

-- Enable comprehensive auditing
CREATE EXTENSION IF NOT EXISTS pgaudit;
ALTER SYSTEM SET pgaudit.log = 'write, ddl';
ALTER SYSTEM SET pgaudit.log_catalog = on;
```

### System Hardening

```bash
# Restrict network access in pg_hba.conf
echo "host all all 192.168.1.0/24 scram-sha-256" >> /etc/postgresql/pg_hba.conf

# Enable SSL
echo "ssl = on" >> /etc/postgresql/postgresql.conf
echo "ssl_cert_file = '/etc/ssl/certs/ssl-cert-snakeoil.pem'" >> /etc/postgresql/postgresql.conf
echo "ssl_key_file = '/etc/ssl/private/ssl-cert-snakeoil.key'" >> /etc/postgresql/postgresql.conf

# Set appropriate file permissions
find /var/lib/postgresql -type f -exec chmod 600 {} \;
find /var/lib/postgresql -type d -exec chmod 700 {} \;
```

### Backup Strategy

```bash
# Daily full backup
pg_basebackup -D /backup/full/$(date +%Y%m%d) -F tar -z -X fetch

# Continuous WAL archiving
echo "archive_mode = on" >> /etc/postgresql/postgresql.conf
echo "archive_command = 'cp %p /backup/wal/%f'" >> /etc/postgresql/postgresql.conf

# Test restoration regularly
pg_basebackup -D /tmp/test_restore -F tar -z -X fetch
```

### Monitoring and Detection

```sql
-- Create alerts for suspicious activities
CREATE OR REPLACE FUNCTION security.alert_on_suspicious_activity()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DROP' OR TG_OP = 'TRUNCATE' THEN
        INSERT INTO logs.notification_log (
            event_type, severity, username, message
        ) VALUES (
            'SUSPICIOUS_ACTIVITY', 'HIGH', current_user, 
            'Potential destructive operation: ' || TG_OP || ' on ' || TG_TABLE_NAME
        );
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Apply to all tables
CREATE TRIGGER alert_suspicious_activity
AFTER DROP OR TRUNCATE ON ALL TABLES
EXECUTE FUNCTION security.alert_on_suspicious_activity();
```
