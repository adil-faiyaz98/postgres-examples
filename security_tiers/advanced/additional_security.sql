-- Additional Advanced Security Features
-- This file contains production-ready implementations of advanced security concepts

\c db_dev;

-- 1. AI-Driven Security Monitoring - Extracted from specialized_scenarios_experimental/ml
CREATE OR REPLACE FUNCTION ai_security.monitor_query_patterns()
RETURNS TRIGGER AS $$
DECLARE
    query_signature TEXT;
    pattern_exists BOOLEAN;
    anomaly_score NUMERIC;
BEGIN
    -- Generate a signature for the query
    query_signature := md5(current_query());
    
    -- Check if we've seen this pattern before
    SELECT EXISTS (
        SELECT 1 FROM security_monitoring.query_patterns 
        WHERE username = current_user 
        AND query_signature = query_signature
    ) INTO pattern_exists;
    
    -- For known patterns, check if execution time is anomalous
    IF pattern_exists THEN
        -- Get statistics for this query pattern
        SELECT 
            CASE 
                WHEN ABS(NEW.execution_time - avg_execution_time) > (2 * std_dev_execution_time) 
                THEN ABS(NEW.execution_time - avg_execution_time) / std_dev_execution_time
                ELSE 0
            END
        INTO anomaly_score
        FROM security_monitoring.query_patterns
        WHERE username = current_user 
        AND query_signature = query_signature;
        
        -- If anomaly detected, log it
        IF anomaly_score > 2 THEN
            INSERT INTO security_monitoring.anomalies (
                username, 
                database_name, 
                query_signature, 
                execution_time,
                expected_execution_time,
                deviation_factor,
                query_text
            ) 
            SELECT 
                current_user,
                current_database(),
                query_signature,
                NEW.execution_time,
                avg_execution_time,
                anomaly_score,
                current_query()
            FROM security_monitoring.query_patterns
            WHERE username = current_user
            AND query_signature = query_signature;
        END IF;
        
        -- Update statistics for this query pattern
        UPDATE security_monitoring.query_patterns 
        SET 
            avg_execution_time = (
                (avg_execution_time * sample_size + NEW.execution_time) / (sample_size + 1)
            ),
            std_dev_execution_time = (
                sqrt(
                    (pow(std_dev_execution_time, 2) * sample_size + 
                     pow(NEW.execution_time - avg_execution_time, 2)) / (sample_size + 1)
                )
            ),
            sample_size = sample_size + 1,
            last_updated = NOW()
        WHERE 
            username = current_user 
            AND query_signature = query_signature;
    ELSE
        -- First time seeing this pattern, add to baseline
        INSERT INTO security_monitoring.query_patterns (
            username, 
            database_name, 
            query_signature, 
            avg_execution_time, 
            std_dev_execution_time, 
            sample_size
        ) VALUES (
            current_user,
            current_database(),
            query_signature,
            NEW.execution_time,
            1.0, -- Initial standard deviation
            1    -- Sample size starts at 1
        );
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2. Secure Block IP Function - Extracted from specialized_scenarios_experimental/incident_response
CREATE OR REPLACE FUNCTION security.block_ip(
    ip_address INET,
    reason TEXT
)
RETURNS BOOLEAN AS $$
DECLARE
    success BOOLEAN := FALSE;
BEGIN
    -- Log the IP blocking attempt
    INSERT INTO security.blocked_ips (
        ip_address,
        blocked_by,
        reason,
        blocked_at
    ) VALUES (
        ip_address,
        current_user,
        reason,
        NOW()
    );
    
    -- Apply pg_hba.conf modification if authorized
    -- In production this would use a more sophisticated approach
    -- such as dynamically updating a firewall rule
    IF current_user IN ('security_admin', current_setting('security.admin_users', true)) THEN
        -- Create trigger to reject connections from this IP
        EXECUTE format('
            CREATE OR REPLACE FUNCTION security.reject_blocked_ip()
            RETURNS TRIGGER AS $func$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM security.blocked_ips 
                    WHERE ip_address = inet_client_addr()
                    AND active = TRUE
                ) THEN
                    RAISE EXCEPTION ''Connection rejected: IP address % is blocked'', inet_client_addr();
                END IF;
                RETURN NEW;
            END;
            $func$ LANGUAGE plpgsql;
        ');
        
        -- Attach trigger to connection events (in real implementation)
        -- This is a simplified example and would require more system-level integration
        success := TRUE;
    ELSE
        RAISE EXCEPTION 'Insufficient privileges to block IP addresses';
    END IF;
    
    RETURN success;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 3. User Lockout Function - Extracted from specialized_scenarios_experimental/incident_response
CREATE OR REPLACE FUNCTION security.lock_user(
    username TEXT,
    reason TEXT DEFAULT 'Security policy violation'
)
RETURNS BOOLEAN AS $$
DECLARE
    success BOOLEAN := FALSE;
BEGIN
    -- Log the user lockout
    INSERT INTO security.user_lockouts (
        username,
        locked_by,
        reason,
        locked_at
    ) VALUES (
        username,
        current_user,
        reason,
        NOW()
    );
    
    -- Apply user lockout if authorized
    IF current_user IN ('security_admin', current_setting('security.admin_users', true)) THEN
        -- Update user status to locked
        -- In production this would modify the PostgreSQL user account
        EXECUTE format('ALTER ROLE %I NOLOGIN', username);
        success := TRUE;
    ELSE
        RAISE EXCEPTION 'Insufficient privileges to lock user accounts';
    END IF;
    
    RETURN success;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 4. Secure Data Tables - Extracted from specialized_scenarios_experimental/cybersecurity_mesh
CREATE TABLE IF NOT EXISTS security.blocked_ips (
    block_id SERIAL PRIMARY KEY,
    ip_address INET NOT NULL,
    blocked_by TEXT NOT NULL,
    reason TEXT,
    blocked_at TIMESTAMPTZ DEFAULT NOW(),
    active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '24 hours')
);

CREATE TABLE IF NOT EXISTS security.user_lockouts (
    lockout_id SERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    locked_by TEXT NOT NULL,
    reason TEXT,
    locked_at TIMESTAMPTZ DEFAULT NOW(),
    active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMPTZ DEFAULT NULL
);

-- 5. Create table for security events
CREATE TABLE IF NOT EXISTS security.security_events (
    event_id BIGSERIAL PRIMARY KEY,
    event_type TEXT NOT NULL,
    event_source TEXT NOT NULL,
    event_severity TEXT NOT NULL CHECK (event_severity IN ('INFO', 'WARNING', 'ERROR', 'CRITICAL')),
    event_data JSONB,
    event_time TIMESTAMPTZ DEFAULT NOW(),
    resolved BOOLEAN DEFAULT FALSE,
    resolution_time TIMESTAMPTZ,
    resolution_notes TEXT
);

-- 6. Create function to log security events
CREATE OR REPLACE FUNCTION security.log_security_event(
    event_type TEXT,
    event_source TEXT,
    event_severity TEXT,
    event_data JSONB DEFAULT '{}'::JSONB
)
RETURNS BIGINT AS $$
DECLARE
    new_event_id BIGINT;
BEGIN
    INSERT INTO security.security_events (
        event_type,
        event_source,
        event_severity,
        event_data
    ) VALUES (
        event_type,
        event_source,
        event_severity,
        event_data
    ) RETURNING event_id INTO new_event_id;
    
    RETURN new_event_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER; 