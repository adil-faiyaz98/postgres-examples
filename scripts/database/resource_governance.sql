-- Resource Governance for PostgreSQL Security Framework
CREATE SCHEMA IF NOT EXISTS resource_governance;

-- Table for storing resource limits
CREATE TABLE IF NOT EXISTS resource_governance.limits (
    id SERIAL PRIMARY KEY,
    role_name TEXT NOT NULL,
    max_connections INTEGER,
    cpu_limit INTEGER, -- percentage
    memory_limit INTEGER, -- MB
    io_limit INTEGER, -- IOPS
    query_timeout INTEGER, -- seconds
    max_locks INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(role_name)
);

-- Table for storing resource usage
CREATE TABLE IF NOT EXISTS resource_governance.usage (
    id SERIAL PRIMARY KEY,
    role_name TEXT NOT NULL,
    pid INTEGER NOT NULL,
    username TEXT NOT NULL,
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ,
    cpu_usage NUMERIC,
    memory_usage NUMERIC,
    io_usage NUMERIC,
    query TEXT,
    query_hash TEXT,
    terminated BOOLEAN NOT NULL DEFAULT FALSE,
    termination_reason TEXT
);

-- Create index on role_name for faster lookups
CREATE INDEX IF NOT EXISTS idx_usage_role_name ON resource_governance.usage (role_name);

-- Function to set resource limits for a role
CREATE OR REPLACE FUNCTION resource_governance.set_limits(
    p_role_name TEXT,
    p_max_connections INTEGER DEFAULT NULL,
    p_cpu_limit INTEGER DEFAULT NULL,
    p_memory_limit INTEGER DEFAULT NULL,
    p_io_limit INTEGER DEFAULT NULL,
    p_query_timeout INTEGER DEFAULT NULL,
    p_max_locks INTEGER DEFAULT NULL
) RETURNS VOID AS $$
BEGIN
    -- Insert or update limits
    INSERT INTO resource_governance.limits (
        role_name, max_connections, cpu_limit, memory_limit, 
        io_limit, query_timeout, max_locks
    ) VALUES (
        p_role_name, p_max_connections, p_cpu_limit, p_memory_limit, 
        p_io_limit, p_query_timeout, p_max_locks
    ) ON CONFLICT (role_name) DO UPDATE
    SET max_connections = COALESCE(p_max_connections, resource_governance.limits.max_connections),
        cpu_limit = COALESCE(p_cpu_limit, resource_governance.limits.cpu_limit),
        memory_limit = COALESCE(p_memory_limit, resource_governance.limits.memory_limit),
        io_limit = COALESCE(p_io_limit, resource_governance.limits.io_limit),
        query_timeout = COALESCE(p_query_timeout, resource_governance.limits.query_timeout),
        max_locks = COALESCE(p_max_locks, resource_governance.limits.max_locks),
        updated_at = NOW();
    
    -- Apply connection limit if specified
    IF p_max_connections IS NOT NULL THEN
        EXECUTE format(
            'ALTER ROLE %I CONNECTION LIMIT %s',
            p_role_name,
            p_max_connections
        );
    END IF;
    
    -- Apply statement timeout if specified
    IF p_query_timeout IS NOT NULL THEN
        EXECUTE format(
            'ALTER ROLE %I SET statement_timeout = %s',
            p_role_name,
            p_query_timeout * 1000 -- convert to milliseconds
        );
    END IF;
    
    -- Apply lock timeout if specified
    IF p_max_locks IS NOT NULL THEN
        EXECUTE format(
            'ALTER ROLE %I SET lock_timeout = %s',
            p_role_name,
            30000 -- 30 seconds in milliseconds
        );
    END IF;
    
    -- Log limit setting
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'RESOURCE_LIMITS_SET', 'INFO', current_user, 
        format('Set resource limits for role %s', p_role_name)
    );
END;
$$ LANGUAGE plpgsql;

-- Function to monitor resource usage
CREATE OR REPLACE FUNCTION resource_governance.monitor_usage() RETURNS SETOF resource_governance.usage AS $$
DECLARE
    v_limit RECORD;
    v_activity RECORD;
    v_usage_id INTEGER;
    v_terminated BOOLEAN;
    v_termination_reason TEXT;
BEGIN
    -- Loop through active roles with limits
    FOR v_limit IN
        SELECT * FROM resource_governance.limits
    LOOP
        -- Loop through active sessions for this role
        FOR v_activity IN
            SELECT 
                pid,
                usename AS username,
                query_start AS start_time,
                query,
                md5(query) AS query_hash,
                EXTRACT(EPOCH FROM (NOW() - query_start)) AS duration_seconds,
                state
            FROM pg_stat_activity
            WHERE usename IN (
                SELECT rolname FROM pg_roles
                WHERE pg_has_role(rolname, v_limit.role_name, 'member')
                   OR rolname = v_limit.role_name
            )
            AND state = 'active'
            AND pid <> pg_backend_pid()
        LOOP
            -- Check if query exceeds timeout
            v_terminated := FALSE;
            v_termination_reason := NULL;
            
            IF v_limit.query_timeout IS NOT NULL AND 
               v_activity.duration_seconds > v_limit.query_timeout THEN
                -- Terminate long-running query
                PERFORM pg_terminate_backend(v_activity.pid);
                v_terminated := TRUE;
                v_termination_reason := 'Query timeout exceeded';
                
                -- Log termination
                INSERT INTO logs.notification_log (
                    event_type, severity, username, message, additional_data
                ) VALUES (
                    'QUERY_TERMINATED', 'WARNING', v_activity.username, 
                    format('Terminated query exceeding timeout of %s seconds', v_limit.query_timeout),
                    jsonb_build_object(
                        'pid', v_activity.pid,
                        'query', v_activity.query,
                        'duration', v_activity.duration_seconds
                    )
                );
            END IF;
            
            -- Record usage
            INSERT INTO resource_governance.usage (
                role_name, pid, username, start_time, end_time,
                query, query_hash, terminated, termination_reason
            ) VALUES (
                v_limit.role_name, v_activity.pid, v_activity.username, 
                v_activity.start_time, 
                CASE WHEN v_terminated THEN NOW() ELSE NULL END,
                v_activity.query, v_activity.query_hash, 
                v_terminated, v_termination_reason
            ) RETURNING id INTO v_usage_id;
            
            -- Return usage record
            RETURN QUERY
            SELECT * FROM resource_governance.usage
            WHERE id = v_usage_id;
        END LOOP;
    END LOOP;
    
    RETURN;
END;
$$ LANGUAGE plpgsql;

-- Function to get resource usage statistics
CREATE OR REPLACE FUNCTION resource_governance.get_usage_stats(
    p_role_name TEXT DEFAULT NULL,
    p_start_time TIMESTAMPTZ DEFAULT NOW() - INTERVAL '1 day',
    p_end_time TIMESTAMPTZ DEFAULT NOW()
) RETURNS TABLE (
    role_name TEXT,
    total_queries INTEGER,
    avg_duration NUMERIC,
    max_duration NUMERIC,
    terminated_queries INTEGER,
    termination_rate NUMERIC
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        u.role_name,
        count(*)::INTEGER AS total_queries,
        avg(EXTRACT(EPOCH FROM (COALESCE(u.end_time, NOW()) - u.start_time)))::NUMERIC AS avg_duration,
        max(EXTRACT(EPOCH FROM (COALESCE(u.end_time, NOW()) - u.start_time)))::NUMERIC AS max_duration,
        count(*) FILTER (WHERE u.terminated)::INTEGER AS terminated_queries,
        CASE
            WHEN count(*) > 0 THEN
                (count(*) FILTER (WHERE u.terminated)::NUMERIC / count(*)::NUMERIC) * 100
            ELSE 0
        END AS termination_rate
    FROM resource_governance.usage u
    WHERE (p_role_name IS NULL OR u.role_name = p_role_name)
      AND u.start_time >= p_start_time
      AND (u.end_time IS NULL OR u.end_time <= p_end_time)
    GROUP BY u.role_name
    ORDER BY total_queries DESC;
END;
$$ LANGUAGE plpgsql;

-- Function to identify resource-intensive queries
CREATE OR REPLACE FUNCTION resource_governance.identify_intensive_queries(
    p_role_name TEXT DEFAULT NULL,
    p_start_time TIMESTAMPTZ DEFAULT NOW() - INTERVAL '1 day',
    p_end_time TIMESTAMPTZ DEFAULT NOW(),
    p_limit INTEGER DEFAULT 10
) RETURNS TABLE (
    query_hash TEXT,
    query TEXT,
    execution_count INTEGER,
    avg_duration NUMERIC,
    max_duration NUMERIC,
    total_duration NUMERIC,
    termination_count INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        u.query_hash,
        substring(u.query, 1, 200) AS query,
        count(*)::INTEGER AS execution_count,
        avg(EXTRACT(EPOCH FROM (COALESCE(u.end_time, NOW()) - u.start_time)))::NUMERIC AS avg_duration,
        max(EXTRACT(EPOCH FROM (COALESCE(u.end_time, NOW()) - u.start_time)))::NUMERIC AS max_duration,
        sum(EXTRACT(EPOCH FROM (COALESCE(u.end_time, NOW()) - u.start_time)))::NUMERIC AS total_duration,
        count(*) FILTER (WHERE u.terminated)::INTEGER AS termination_count
    FROM resource_governance.usage u
    WHERE (p_role_name IS NULL OR u.role_name = p_role_name)
      AND u.start_time >= p_start_time
      AND (u.end_time IS NULL OR u.end_time <= p_end_time)
      AND u.query_hash IS NOT NULL
    GROUP BY u.query_hash, query
    ORDER BY total_duration DESC
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql;

-- Function to create a resource pool
CREATE OR REPLACE FUNCTION resource_governance.create_resource_pool(
    p_pool_name TEXT,
    p_max_connections INTEGER,
    p_cpu_limit INTEGER,
    p_memory_limit INTEGER
) RETURNS VOID AS $$
BEGIN
    -- Create role for the resource pool
    EXECUTE format(
        'CREATE ROLE %I WITH NOLOGIN CONNECTION LIMIT %s',
        p_pool_name,
        p_max_connections
    );
    
    -- Set resource limits
    PERFORM resource_governance.set_limits(
        p_pool_name,
        p_max_connections,
        p_cpu_limit,
        p_memory_limit
    );
    
    -- Log pool creation
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'RESOURCE_POOL_CREATED', 'INFO', current_user, 
        format('Created resource pool %s with max connections: %s, CPU limit: %s%%, memory limit: %s MB',
               p_pool_name, p_max_connections, p_cpu_limit, p_memory_limit)
    );
END;
$$ LANGUAGE plpgsql;

-- Function to assign a role to a resource pool
CREATE OR REPLACE FUNCTION resource_governance.assign_to_pool(
    p_role_name TEXT,
    p_pool_name TEXT
) RETURNS VOID AS $$
BEGIN
    -- Grant pool role to user role
    EXECUTE format(
        'GRANT %I TO %I',
        p_pool_name,
        p_role_name
    );
    
    -- Log assignment
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'RESOURCE_POOL_ASSIGNMENT', 'INFO', current_user, 
        format('Assigned role %s to resource pool %s',
               p_role_name, p_pool_name)
    );
END;
$$ LANGUAGE plpgsql;

-- Function to clean up old usage data
CREATE OR REPLACE FUNCTION resource_governance.cleanup_usage(
    p_retention_days INTEGER DEFAULT 30
) RETURNS INTEGER AS $$
DECLARE
    v_count INTEGER;
BEGIN
    -- Delete old usage data
    DELETE FROM resource_governance.usage
    WHERE end_time < NOW() - (p_retention_days || ' days')::INTERVAL
    RETURNING count(*) INTO v_count;
    
    -- Log cleanup
    IF v_count > 0 THEN
        INSERT INTO logs.notification_log (
            event_type, severity, username, message
        ) VALUES (
            'RESOURCE_USAGE_CLEANUP', 'INFO', current_user, 
            format('Cleaned up %s old resource usage records', v_count)
        );
    END IF;
    
    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

-- Grant permissions
GRANT USAGE ON SCHEMA resource_governance TO security_admin;
GRANT SELECT ON resource_governance.limits TO security_admin;
GRANT SELECT ON resource_governance.usage TO security_admin;
GRANT EXECUTE ON FUNCTION resource_governance.set_limits TO security_admin;
GRANT EXECUTE ON FUNCTION resource_governance.monitor_usage TO security_admin;
GRANT EXECUTE ON FUNCTION resource_governance.get_usage_stats TO security_admin;
GRANT EXECUTE ON FUNCTION resource_governance.identify_intensive_queries TO security_admin;
GRANT EXECUTE ON FUNCTION resource_governance.create_resource_pool TO security_admin;
GRANT EXECUTE ON FUNCTION resource_governance.assign_to_pool TO security_admin;
GRANT EXECUTE ON FUNCTION resource_governance.cleanup_usage TO security_admin;
