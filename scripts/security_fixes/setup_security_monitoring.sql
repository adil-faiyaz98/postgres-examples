-- Implement Real-time Security Monitoring
-- This script sets up real-time security monitoring for the PostgreSQL database

-- 1. Create a dedicated schema for security monitoring
CREATE SCHEMA IF NOT EXISTS security_monitoring;

-- 2. Create a table to store security events
CREATE TABLE IF NOT EXISTS security_monitoring.security_events (
    id SERIAL PRIMARY KEY,
    event_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,
    description TEXT,
    severity TEXT CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    source TEXT,
    username TEXT,
    database_name TEXT,
    client_addr TEXT,
    query TEXT,
    resolved BOOLEAN DEFAULT FALSE,
    resolution_notes TEXT,
    resolution_time TIMESTAMP WITH TIME ZONE
);

-- 3. Create a function to log security events
CREATE OR REPLACE FUNCTION security_monitoring.log_security_event(
    event_type TEXT,
    description TEXT,
    severity TEXT,
    query TEXT DEFAULT NULL
)
RETURNS VOID AS $$
BEGIN
    INSERT INTO security_monitoring.security_events (
        event_type,
        description,
        severity,
        source,
        username,
        database_name,
        client_addr,
        query
    ) VALUES (
        event_type,
        description,
        severity,
        current_setting('application_name'),
        current_user,
        current_database(),
        inet_client_addr()::TEXT,
        COALESCE(query, current_query())
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 4. Create a view to show recent security events
CREATE OR REPLACE VIEW security_monitoring.recent_events AS
SELECT
    id,
    event_time,
    event_type,
    description,
    severity,
    username,
    client_addr,
    resolved
FROM
    security_monitoring.security_events
WHERE
    event_time > (CURRENT_TIMESTAMP - INTERVAL '24 hours')
ORDER BY
    event_time DESC;

-- 5. Create a function to monitor for suspicious queries
CREATE OR REPLACE FUNCTION security_monitoring.monitor_suspicious_queries()
RETURNS TRIGGER AS $$
BEGIN
    -- Check for suspicious patterns in queries
    IF NEW.query ~* 'drop|truncate|delete from.*where|update.*where' THEN
        PERFORM security_monitoring.log_security_event(
            'SUSPICIOUS_QUERY',
            'Potentially dangerous query detected',
            'MEDIUM',
            NEW.query
        );
    END IF;
    
    -- Check for potential SQL injection patterns
    IF NEW.query ~* 'union.*select|;.*select|--.*select|/\*.*select' THEN
        PERFORM security_monitoring.log_security_event(
            'POTENTIAL_SQL_INJECTION',
            'Potential SQL injection pattern detected',
            'HIGH',
            NEW.query
        );
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 6. Create a function to monitor for privilege escalation
CREATE OR REPLACE FUNCTION security_monitoring.monitor_privilege_changes()
RETURNS event_trigger AS $$
DECLARE
    obj record;
BEGIN
    FOR obj IN SELECT * FROM pg_event_trigger_ddl_commands() LOOP
        IF obj.command_tag IN ('CREATE ROLE', 'ALTER ROLE', 'GRANT') THEN
            PERFORM security_monitoring.log_security_event(
                'PRIVILEGE_CHANGE',
                'Role or privilege change detected: ' || obj.command_tag,
                'MEDIUM'
            );
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- 7. Create event trigger for privilege changes
DROP EVENT TRIGGER IF EXISTS privilege_change_trigger;
CREATE EVENT TRIGGER privilege_change_trigger ON ddl_command_end
WHEN TAG IN ('CREATE ROLE', 'ALTER ROLE', 'GRANT')
EXECUTE FUNCTION security_monitoring.monitor_privilege_changes();

-- 8. Create a function to generate security reports
CREATE OR REPLACE FUNCTION security_monitoring.generate_security_report(
    start_time TIMESTAMP WITH TIME ZONE DEFAULT (CURRENT_TIMESTAMP - INTERVAL '7 days'),
    end_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
)
RETURNS TABLE (
    event_type TEXT,
    count BIGINT,
    highest_severity TEXT,
    most_recent TIMESTAMP WITH TIME ZONE
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        se.event_type,
        COUNT(*) AS count,
        MAX(se.severity) AS highest_severity,
        MAX(se.event_time) AS most_recent
    FROM
        security_monitoring.security_events se
    WHERE
        se.event_time BETWEEN start_time AND end_time
    GROUP BY
        se.event_type
    ORDER BY
        count DESC;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 9. Create a function to detect anomalous login patterns
CREATE OR REPLACE FUNCTION security_monitoring.detect_anomalous_logins()
RETURNS VOID AS $$
DECLARE
    unusual_time BOOLEAN;
    unusual_location BOOLEAN;
    unusual_frequency BOOLEAN;
    login_count INTEGER;
BEGIN
    -- Check for logins at unusual times
    SELECT EXISTS (
        SELECT 1
        FROM pg_stat_activity
        WHERE EXTRACT(HOUR FROM backend_start) BETWEEN 0 AND 5
        AND backend_start > (CURRENT_TIMESTAMP - INTERVAL '1 hour')
    ) INTO unusual_time;
    
    -- Check for logins from unusual locations
    SELECT EXISTS (
        SELECT 1
        FROM pg_stat_activity
        WHERE client_addr NOT IN (
            SELECT DISTINCT client_addr
            FROM pg_stat_activity
            WHERE backend_start < (CURRENT_TIMESTAMP - INTERVAL '7 days')
        )
        AND backend_start > (CURRENT_TIMESTAMP - INTERVAL '1 hour')
    ) INTO unusual_location;
    
    -- Check for unusually high frequency of logins
    SELECT COUNT(*) INTO login_count
    FROM pg_stat_activity
    WHERE backend_start > (CURRENT_TIMESTAMP - INTERVAL '1 hour');
    
    unusual_frequency := (login_count > 20); -- Adjust threshold as needed
    
    -- Log any anomalies detected
    IF unusual_time THEN
        PERFORM security_monitoring.log_security_event(
            'ANOMALOUS_LOGIN',
            'Login detected during unusual hours (midnight to 5 AM)',
            'MEDIUM'
        );
    END IF;
    
    IF unusual_location THEN
        PERFORM security_monitoring.log_security_event(
            'ANOMALOUS_LOGIN',
            'Login detected from unusual IP address',
            'HIGH'
        );
    END IF;
    
    IF unusual_frequency THEN
        PERFORM security_monitoring.log_security_event(
            'ANOMALOUS_LOGIN',
            'Unusually high frequency of logins detected',
            'MEDIUM'
        );
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 10. Create a scheduled job to run the anomaly detection (requires pg_cron extension)
-- Note: This requires the pg_cron extension to be installed
-- CREATE EXTENSION IF NOT EXISTS pg_cron;
-- SELECT cron.schedule('0 * * * *', 'SELECT security_monitoring.detect_anomalous_logins()');

-- 11. Grant appropriate permissions
GRANT USAGE ON SCHEMA security_monitoring TO app_admin;
GRANT SELECT ON security_monitoring.recent_events TO app_admin;
GRANT EXECUTE ON FUNCTION security_monitoring.generate_security_report TO app_admin;

-- 12. Add comments
COMMENT ON SCHEMA security_monitoring IS 'Schema for PostgreSQL security monitoring';
COMMENT ON TABLE security_monitoring.security_events IS 'Table to store security events';
COMMENT ON FUNCTION security_monitoring.log_security_event IS 'Function to log security events';
COMMENT ON FUNCTION security_monitoring.monitor_suspicious_queries IS 'Function to monitor for suspicious queries';
COMMENT ON FUNCTION security_monitoring.monitor_privilege_changes IS 'Function to monitor for privilege changes';
COMMENT ON FUNCTION security_monitoring.generate_security_report IS 'Function to generate security reports';
COMMENT ON FUNCTION security_monitoring.detect_anomalous_logins IS 'Function to detect anomalous login patterns';
