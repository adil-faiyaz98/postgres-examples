-- Continuous Database Security Scanning for PostgreSQL Security Framework
CREATE SCHEMA IF NOT EXISTS security_scanning;

-- Table for storing vulnerability scan results
CREATE TABLE IF NOT EXISTS security_scanning.vulnerability_scans (
    id SERIAL PRIMARY KEY,
    scan_id UUID NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    scan_type TEXT NOT NULL,
    scan_result TEXT NOT NULL,
    vulnerabilities_found INTEGER NOT NULL DEFAULT 0,
    highest_severity TEXT,
    scan_report JSONB
);

-- Table for storing detected vulnerabilities
CREATE TABLE IF NOT EXISTS security_scanning.vulnerabilities (
    id SERIAL PRIMARY KEY,
    scan_id UUID NOT NULL,
    vulnerability_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    component TEXT NOT NULL,
    description TEXT NOT NULL,
    remediation TEXT,
    cve_id TEXT,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved BOOLEAN NOT NULL DEFAULT FALSE,
    resolved_at TIMESTAMPTZ,
    resolved_by TEXT
);

-- Function to scan for privilege escalation vulnerabilities
CREATE OR REPLACE FUNCTION security_scanning.scan_privilege_escalation() RETURNS UUID AS $$
DECLARE
    v_scan_id UUID;
    v_vulnerabilities_found INTEGER := 0;
    v_highest_severity TEXT := 'LOW';
BEGIN
    -- Generate scan ID
    v_scan_id := gen_random_uuid();
    
    -- Start scan
    INSERT INTO security_scanning.vulnerability_scans (
        scan_id, scan_type, scan_result
    ) VALUES (
        v_scan_id, 'PRIVILEGE_ESCALATION', 'IN_PROGRESS'
    );
    
    -- Check for users with superuser privileges
    FOR i IN (
        SELECT rolname
        FROM pg_roles
        WHERE rolsuper = TRUE AND rolname NOT IN ('postgres')
    ) LOOP
        INSERT INTO security_scanning.vulnerabilities (
            scan_id, vulnerability_type, severity, component,
            description, remediation
        ) VALUES (
            v_scan_id, 'EXCESSIVE_PRIVILEGES', 'HIGH', 'ROLE:' || i.rolname,
            'User has superuser privileges which violates principle of least privilege',
            'Remove superuser privilege and grant only necessary permissions'
        );
        
        v_vulnerabilities_found := v_vulnerabilities_found + 1;
        v_highest_severity := 'HIGH';
    END LOOP;
    
    -- Check for public schema permissions
    FOR i IN (
        SELECT grantee, privilege_type
        FROM information_schema.role_table_grants
        WHERE table_schema = 'public'
          AND grantee = 'PUBLIC'
          AND privilege_type IN ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE')
    ) LOOP
        INSERT INTO security_scanning.vulnerabilities (
            scan_id, vulnerability_type, severity, component,
            description, remediation
        ) VALUES (
            v_scan_id, 'PUBLIC_WRITE_ACCESS', 'HIGH', 'SCHEMA:public',
            'Public role has ' || i.privilege_type || ' privileges on public schema tables',
            'Revoke public write access and grant only to specific roles'
        );
        
        v_vulnerabilities_found := v_vulnerabilities_found + 1;
        v_highest_severity := 'HIGH';
    END LOOP;
    
    -- Check for roles with CREATEROLE privilege
    FOR i IN (
        SELECT rolname
        FROM pg_roles
        WHERE rolcreaterole = TRUE AND rolname NOT IN ('postgres')
    ) LOOP
        INSERT INTO security_scanning.vulnerabilities (
            scan_id, vulnerability_type, severity, component,
            description, remediation
        ) VALUES (
            v_scan_id, 'ROLE_CREATION_PRIVILEGE', 'MEDIUM', 'ROLE:' || i.rolname,
            'User can create new roles which could lead to privilege escalation',
            'Remove CREATEROLE privilege unless absolutely necessary'
        );
        
        v_vulnerabilities_found := v_vulnerabilities_found + 1;
        IF v_highest_severity <> 'HIGH' THEN
            v_highest_severity := 'MEDIUM';
        END IF;
    END LOOP;
    
    -- Complete scan
    UPDATE security_scanning.vulnerability_scans
    SET completed_at = NOW(),
        scan_result = 'COMPLETED',
        vulnerabilities_found = v_vulnerabilities_found,
        highest_severity = v_highest_severity,
        scan_report = jsonb_build_object(
            'summary', format('%s privilege escalation vulnerabilities found', v_vulnerabilities_found),
            'highest_severity', v_highest_severity
        )
    WHERE scan_id = v_scan_id;
    
    -- Log scan completion
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'SECURITY_SCAN_COMPLETED', 'INFO', current_user, 
        format('Privilege escalation scan completed: %s vulnerabilities found', v_vulnerabilities_found)
    );
    
    RETURN v_scan_id;
END;
$$ LANGUAGE plpgsql;

-- Function to scan for SQL injection vulnerabilities
CREATE OR REPLACE FUNCTION security_scanning.scan_sql_injection() RETURNS UUID AS $$
DECLARE
    v_scan_id UUID;
    v_vulnerabilities_found INTEGER := 0;
    v_highest_severity TEXT := 'LOW';
BEGIN
    -- Generate scan ID
    v_scan_id := gen_random_uuid();
    
    -- Start scan
    INSERT INTO security_scanning.vulnerability_scans (
        scan_id, scan_type, scan_result
    ) VALUES (
        v_scan_id, 'SQL_INJECTION', 'IN_PROGRESS'
    );
    
    -- Check for functions using dynamic SQL without proper sanitization
    FOR i IN (
        SELECT n.nspname AS schema_name, p.proname AS function_name
        FROM pg_proc p
        JOIN pg_namespace n ON p.pronamespace = n.oid
        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND p.prosrc LIKE '%EXECUTE%'
          AND p.prosrc NOT LIKE '%quote_ident%'
          AND p.prosrc NOT LIKE '%quote_literal%'
    ) LOOP
        INSERT INTO security_scanning.vulnerabilities (
            scan_id, vulnerability_type, severity, component,
            description, remediation
        ) VALUES (
            v_scan_id, 'DYNAMIC_SQL_INJECTION', 'HIGH', 'FUNCTION:' || i.schema_name || '.' || i.function_name,
            'Function uses dynamic SQL without proper sanitization',
            'Use quote_ident() for identifiers and quote_literal() for values, or use parameterized queries'
        );
        
        v_vulnerabilities_found := v_vulnerabilities_found + 1;
        v_highest_severity := 'HIGH';
    END LOOP;
    
    -- Check for functions using string concatenation in SQL
    FOR i IN (
        SELECT n.nspname AS schema_name, p.proname AS function_name
        FROM pg_proc p
        JOIN pg_namespace n ON p.pronamespace = n.oid
        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND p.prosrc LIKE '%EXECUTE%'
          AND (p.prosrc LIKE '%||%' OR p.prosrc LIKE '%concat%')
    ) LOOP
        INSERT INTO security_scanning.vulnerabilities (
            scan_id, vulnerability_type, severity, component,
            description, remediation
        ) VALUES (
            v_scan_id, 'STRING_CONCATENATION_SQL', 'MEDIUM', 'FUNCTION:' || i.schema_name || '.' || i.function_name,
            'Function uses string concatenation in dynamic SQL which may lead to SQL injection',
            'Use format() with proper parameter types or parameterized queries'
        );
        
        v_vulnerabilities_found := v_vulnerabilities_found + 1;
        IF v_highest_severity <> 'HIGH' THEN
            v_highest_severity := 'MEDIUM';
        END IF;
    END LOOP;
    
    -- Complete scan
    UPDATE security_scanning.vulnerability_scans
    SET completed_at = NOW(),
        scan_result = 'COMPLETED',
        vulnerabilities_found = v_vulnerabilities_found,
        highest_severity = v_highest_severity,
        scan_report = jsonb_build_object(
            'summary', format('%s SQL injection vulnerabilities found', v_vulnerabilities_found),
            'highest_severity', v_highest_severity
        )
    WHERE scan_id = v_scan_id;
    
    -- Log scan completion
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'SECURITY_SCAN_COMPLETED', 'INFO', current_user, 
        format('SQL injection scan completed: %s vulnerabilities found', v_vulnerabilities_found)
    );
    
    RETURN v_scan_id;
END;
$$ LANGUAGE plpgsql;

-- Function to scan for missing security controls
CREATE OR REPLACE FUNCTION security_scanning.scan_missing_controls() RETURNS UUID AS $$
DECLARE
    v_scan_id UUID;
    v_vulnerabilities_found INTEGER := 0;
    v_highest_severity TEXT := 'LOW';
BEGIN
    -- Generate scan ID
    v_scan_id := gen_random_uuid();
    
    -- Start scan
    INSERT INTO security_scanning.vulnerability_scans (
        scan_id, scan_type, scan_result
    ) VALUES (
        v_scan_id, 'MISSING_CONTROLS', 'IN_PROGRESS'
    );
    
    -- Check for tables without row-level security
    FOR i IN (
        SELECT c.table_schema, c.table_name
        FROM information_schema.tables c
        JOIN data_classification.column_classifications dc 
            ON c.table_schema = dc.schema_name 
            AND c.table_name = dc.table_name
        JOIN data_classification.levels l ON dc.level_id = l.id
        LEFT JOIN pg_tables t ON c.table_schema = t.schemaname AND c.table_name = t.tablename
        LEFT JOIN pg_class cls ON cls.relname = c.table_name
        WHERE l.level_order >= 3  -- Confidential or higher
          AND c.table_type = 'BASE TABLE'
          AND NOT EXISTS (
              SELECT 1 FROM pg_catalog.pg_policy pol
              WHERE pol.polrelid = cls.oid
          )
        GROUP BY c.table_schema, c.table_name
    ) LOOP
        INSERT INTO security_scanning.vulnerabilities (
            scan_id, vulnerability_type, severity, component,
            description, remediation
        ) VALUES (
            v_scan_id, 'MISSING_RLS', 'HIGH', 'TABLE:' || i.table_schema || '.' || i.table_name,
            'Table contains sensitive data but lacks row-level security',
            'Enable row-level security and create appropriate policies'
        );
        
        v_vulnerabilities_found := v_vulnerabilities_found + 1;
        v_highest_severity := 'HIGH';
    END LOOP;
    
    -- Check for missing audit logging
    FOR i IN (
        SELECT c.table_schema, c.table_name
        FROM information_schema.tables c
        WHERE c.table_schema NOT IN ('pg_catalog', 'information_schema')
          AND c.table_type = 'BASE TABLE'
          AND NOT EXISTS (
              SELECT 1 FROM pg_trigger t
              JOIN pg_class cls ON t.tgrelid = cls.oid
              JOIN pg_namespace n ON cls.relnamespace = n.oid
              WHERE n.nspname = c.table_schema
                AND cls.relname = c.table_name
                AND t.tgname LIKE '%audit%'
          )
    ) LOOP
        INSERT INTO security_scanning.vulnerabilities (
            scan_id, vulnerability_type, severity, component,
            description, remediation
        ) VALUES (
            v_scan_id, 'MISSING_AUDIT', 'MEDIUM', 'TABLE:' || i.table_schema || '.' || i.table_name,
            'Table lacks audit logging triggers',
            'Implement audit logging using triggers or pgAudit extension'
        );
        
        v_vulnerabilities_found := v_vulnerabilities_found + 1;
        IF v_highest_severity <> 'HIGH' THEN
            v_highest_severity := 'MEDIUM';
        END IF;
    END LOOP;
    
    -- Check for unencrypted sensitive columns
    FOR i IN (
        SELECT c.table_schema, c.table_name, c.column_name
        FROM information_schema.columns c
        JOIN data_classification.column_classifications dc 
            ON c.table_schema = dc.schema_name 
            AND c.table_name = dc.table_name
            AND c.column_name = dc.column_name
        JOIN data_classification.levels l ON dc.level_id = l.id
        WHERE l.level_order >= 3  -- Confidential or higher
          AND c.column_name NOT LIKE '%encrypted%'
          AND c.column_name NOT LIKE '%token%'
          AND c.column_name NOT LIKE '%hash%'
    ) LOOP
        INSERT INTO security_scanning.vulnerabilities (
            scan_id, vulnerability_type, severity, component,
            description, remediation
        ) VALUES (
            v_scan_id, 'UNENCRYPTED_DATA', 'HIGH', 'COLUMN:' || i.table_schema || '.' || i.table_name || '.' || i.column_name,
            'Sensitive column is not encrypted',
            'Implement column-level encryption using the key_management functions'
        );
        
        v_vulnerabilities_found := v_vulnerabilities_found + 1;
        v_highest_severity := 'HIGH';
    END LOOP;
    
    -- Complete scan
    UPDATE security_scanning.vulnerability_scans
    SET completed_at = NOW(),
        scan_result = 'COMPLETED',
        vulnerabilities_found = v_vulnerabilities_found,
        highest_severity = v_highest_severity,
        scan_report = jsonb_build_object(
            'summary', format('%s missing security controls found', v_vulnerabilities_found),
            'highest_severity', v_highest_severity
        )
    WHERE scan_id = v_scan_id;
    
    -- Log scan completion
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'SECURITY_SCAN_COMPLETED', 'INFO', current_user, 
        format('Missing controls scan completed: %s vulnerabilities found', v_vulnerabilities_found)
    );
    
    RETURN v_scan_id;
END;
$$ LANGUAGE plpgsql;

-- Function to scan for configuration vulnerabilities
CREATE OR REPLACE FUNCTION security_scanning.scan_configuration() RETURNS UUID AS $$
DECLARE
    v_scan_id UUID;
    v_vulnerabilities_found INTEGER := 0;
    v_highest_severity TEXT := 'LOW';
    v_setting TEXT;
BEGIN
    -- Generate scan ID
    v_scan_id := gen_random_uuid();
    
    -- Start scan
    INSERT INTO security_scanning.vulnerability_scans (
        scan_id, scan_type, scan_result
    ) VALUES (
        v_scan_id, 'CONFIGURATION', 'IN_PROGRESS'
    );
    
    -- Check SSL configuration
    SELECT setting INTO v_setting FROM pg_settings WHERE name = 'ssl';
    IF v_setting = 'off' THEN
        INSERT INTO security_scanning.vulnerabilities (
            scan_id, vulnerability_type, severity, component,
            description, remediation
        ) VALUES (
            v_scan_id, 'SSL_DISABLED', 'HIGH', 'CONFIGURATION:ssl',
            'SSL is disabled, allowing unencrypted connections',
            'Enable SSL by setting ssl=on and configuring certificates'
        );
        
        v_vulnerabilities_found := v_vulnerabilities_found + 1;
        v_highest_severity := 'HIGH';
    END IF;
    
    -- Check password encryption
    SELECT setting INTO v_setting FROM pg_settings WHERE name = 'password_encryption';
    IF v_setting <> 'scram-sha-256' THEN
        INSERT INTO security_scanning.vulnerabilities (
            scan_id, vulnerability_type, severity, component,
            description, remediation
        ) VALUES (
            v_scan_id, 'WEAK_PASSWORD_ENCRYPTION', 'HIGH', 'CONFIGURATION:password_encryption',
            'Weak password encryption method in use: ' || v_setting,
            'Set password_encryption=scram-sha-256'
        );
        
        v_vulnerabilities_found := v_vulnerabilities_found + 1;
        v_highest_severity := 'HIGH';
    END IF;
    
    -- Check logging configuration
    SELECT setting INTO v_setting FROM pg_settings WHERE name = 'log_connections';
    IF v_setting = 'off' THEN
        INSERT INTO security_scanning.vulnerabilities (
            scan_id, vulnerability_type, severity, component,
            description, remediation
        ) VALUES (
            v_scan_id, 'INSUFFICIENT_LOGGING', 'MEDIUM', 'CONFIGURATION:log_connections',
            'Connection logging is disabled',
            'Enable connection logging by setting log_connections=on'
        );
        
        v_vulnerabilities_found := v_vulnerabilities_found + 1;
        IF v_highest_severity <> 'HIGH' THEN
            v_highest_severity := 'MEDIUM';
        END IF;
    END IF;
    
    SELECT setting INTO v_setting FROM pg_settings WHERE name = 'log_disconnections';
    IF v_setting = 'off' THEN
        INSERT INTO security_scanning.vulnerabilities (
            scan_id, vulnerability_type, severity, component,
            description, remediation
        ) VALUES (
            v_scan_id, 'INSUFFICIENT_LOGGING', 'MEDIUM', 'CONFIGURATION:log_disconnections',
            'Disconnection logging is disabled',
            'Enable disconnection logging by setting log_disconnections=on'
        );
        
        v_vulnerabilities_found := v_vulnerabilities_found + 1;
        IF v_highest_severity <> 'HIGH' THEN
            v_highest_severity := 'MEDIUM';
        END IF;
    END IF;
    
    -- Complete scan
    UPDATE security_scanning.vulnerability_scans
    SET completed_at = NOW(),
        scan_result = 'COMPLETED',
        vulnerabilities_found = v_vulnerabilities_found,
        highest_severity = v_highest_severity,
        scan_report = jsonb_build_object(
            'summary', format('%s configuration vulnerabilities found', v_vulnerabilities_found),
            'highest_severity', v_highest_severity
        )
    WHERE scan_id = v_scan_id;
    
    -- Log scan completion
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'SECURITY_SCAN_COMPLETED', 'INFO', current_user, 
        format('Configuration scan completed: %s vulnerabilities found', v_vulnerabilities_found)
    );
    
    RETURN v_scan_id;
END;
$$ LANGUAGE plpgsql;

-- Function to run all security scans
CREATE OR REPLACE FUNCTION security_scanning.run_all_scans() RETURNS SETOF UUID AS $$
DECLARE
    v_scan_id UUID;
BEGIN
    -- Run privilege escalation scan
    v_scan_id := security_scanning.scan_privilege_escalation();
    RETURN NEXT v_scan_id;
    
    -- Run SQL injection scan
    v_scan_id := security_scanning.scan_sql_injection();
    RETURN NEXT v_scan_id;
    
    -- Run missing controls scan
    v_scan_id := security_scanning.scan_missing_controls();
    RETURN NEXT v_scan_id;
    
    -- Run configuration scan
    v_scan_id := security_scanning.scan_configuration();
    RETURN NEXT v_scan_id;
    
    RETURN;
END;
$$ LANGUAGE plpgsql;

-- Function to get scan results
CREATE OR REPLACE FUNCTION security_scanning.get_scan_results(
    p_scan_id UUID
) RETURNS TABLE (
    vulnerability_id INTEGER,
    vulnerability_type TEXT,
    severity TEXT,
    component TEXT,
    description TEXT,
    remediation TEXT,
    resolved BOOLEAN
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        v.id,
        v.vulnerability_type,
        v.severity,
        v.component,
        v.description,
        v.remediation,
        v.resolved
    FROM security_scanning.vulnerabilities v
    WHERE v.scan_id = p_scan_id
    ORDER BY 
        CASE v.severity
            WHEN 'HIGH' THEN 1
            WHEN 'MEDIUM' THEN 2
            WHEN 'LOW' THEN 3
            ELSE 4
        END,
        v.vulnerability_type;
END;
$$ LANGUAGE plpgsql;

-- Function to resolve a vulnerability
CREATE OR REPLACE FUNCTION security_scanning.resolve_vulnerability(
    p_vulnerability_id INTEGER,
    p_resolution_notes TEXT
) RETURNS VOID AS $$
BEGIN
    -- Update vulnerability
    UPDATE security_scanning.vulnerabilities
    SET resolved = TRUE,
        resolved_at = NOW(),
        resolved_by = current_user
    WHERE id = p_vulnerability_id;
    
    -- Log resolution
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'VULNERABILITY_RESOLVED', 'INFO', current_user, 
        format('Resolved vulnerability %s: %s', p_vulnerability_id, p_resolution_notes)
    );
END;
$$ LANGUAGE plpgsql;

-- Function to get security posture score
CREATE OR REPLACE FUNCTION security_scanning.get_security_posture() RETURNS TABLE (
    category TEXT,
    score INTEGER,
    max_score INTEGER,
    percentage NUMERIC,
    vulnerabilities_count INTEGER,
    high_severity_count INTEGER,
    medium_severity_count INTEGER,
    low_severity_count INTEGER
) AS $$
BEGIN
    RETURN QUERY
    WITH latest_scans AS (
        SELECT DISTINCT ON (scan_type) *
        FROM security_scanning.vulnerability_scans
        WHERE scan_result = 'COMPLETED'
        ORDER BY scan_type, started_at DESC
    ),
    vulnerability_counts AS (
        SELECT
            ls.scan_type,
            count(*) FILTER (WHERE NOT v.resolved) AS total_vulnerabilities,
            count(*) FILTER (WHERE v.severity = 'HIGH' AND NOT v.resolved) AS high_severity,
            count(*) FILTER (WHERE v.severity = 'MEDIUM' AND NOT v.resolved) AS medium_severity,
            count(*) FILTER (WHERE v.severity = 'LOW' AND NOT v.resolved) AS low_severity
        FROM latest_scans ls
        JOIN security_scanning.vulnerabilities v ON ls.scan_id = v.scan_id
        GROUP BY ls.scan_type
    )
    SELECT
        vc.scan_type AS category,
        CASE
            WHEN vc.total_vulnerabilities = 0 THEN 100
            ELSE GREATEST(0, 100 - (vc.high_severity * 10) - (vc.medium_severity * 5) - (vc.low_severity * 1))
        END AS score,
        100 AS max_score,
        CASE
            WHEN vc.total_vulnerabilities = 0 THEN 100
            ELSE GREATEST(0, 100 - (vc.high_severity * 10) - (vc.medium_severity * 5) - (vc.low_severity * 1))
        END AS percentage,
        vc.total_vulnerabilities,
        vc.high_severity,
        vc.medium_severity,
        vc.low_severity
    FROM vulnerability_counts vc
    ORDER BY score;
END;
$$ LANGUAGE plpgsql;

-- Grant permissions
GRANT USAGE ON SCHEMA security_scanning TO security_admin;
GRANT SELECT ON ALL TABLES IN SCHEMA security_scanning TO security_admin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA security_scanning TO security_admin;
