-- Read Replica Manager for PostgreSQL Security Framework
CREATE SCHEMA IF NOT EXISTS replica_manager;

-- Table to track read replicas
CREATE TABLE IF NOT EXISTS replica_manager.replicas (
    id SERIAL PRIMARY KEY,
    hostname TEXT NOT NULL UNIQUE,
    port INTEGER NOT NULL DEFAULT 5432,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_checked TIMESTAMPTZ,
    lag_seconds INTEGER,
    status TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Function to register a replica
CREATE OR REPLACE FUNCTION replica_manager.register_replica(
    p_hostname TEXT,
    p_port INTEGER DEFAULT 5432
) RETURNS INTEGER AS $$
DECLARE
    v_id INTEGER;
BEGIN
    INSERT INTO replica_manager.replicas (
        hostname, port
    ) VALUES (
        p_hostname, p_port
    ) ON CONFLICT (hostname) DO UPDATE
    SET port = p_port,
        is_active = TRUE,
        updated_at = NOW()
    RETURNING id INTO v_id;
    
    RETURN v_id;
END;
$$ LANGUAGE plpgsql;

-- Function to check replica status
CREATE OR REPLACE FUNCTION replica_manager.check_replica_status(
    p_hostname TEXT,
    p_port INTEGER DEFAULT 5432
) RETURNS RECORD AS $$
DECLARE
    v_result RECORD;
    v_conn_string TEXT;
    v_lag INTEGER;
    v_status TEXT;
BEGIN
    -- Build connection string
    v_conn_string := format(
        'host=%s port=%s dbname=postgres user=%s password=%s',
        p_hostname, p_port, 
        current_setting('replica_manager.user'),
        current_setting('replica_manager.password')
    );
    
    -- Check replica status
    BEGIN
        -- Check replication lag
        EXECUTE format('
            SELECT EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()))::INTEGER
            FROM dblink(%L, %L) AS t(lag INTEGER)
        ', v_conn_string, 'SELECT EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()))::INTEGER')
        INTO v_lag;
        
        v_status := 'online';
    EXCEPTION
        WHEN OTHERS THEN
            v_lag := NULL;
            v_status := 'offline';
    END;
    
    -- Update replica status
    UPDATE replica_manager.replicas
    SET last_checked = NOW(),
        lag_seconds = v_lag,
        status = v_status,
        updated_at = NOW()
    WHERE hostname = p_hostname
    RETURNING * INTO v_result;
    
    RETURN v_result;
END;
$$ LANGUAGE plpgsql;

-- Function to check all replicas
CREATE OR REPLACE FUNCTION replica_manager.check_all_replicas() RETURNS SETOF replica_manager.replicas AS $$
DECLARE
    v_replica RECORD;
    v_result RECORD;
BEGIN
    FOR v_replica IN
        SELECT * FROM replica_manager.replicas
        WHERE is_active = TRUE
    LOOP
        SELECT * FROM replica_manager.check_replica_status(
            v_replica.hostname, v_replica.port
        ) INTO v_result;
        
        RETURN NEXT v_result;
    END LOOP;
    
    RETURN;
END;
$$ LANGUAGE plpgsql;

-- Function to route read queries to replicas
CREATE OR REPLACE FUNCTION replica_manager.execute_on_replica(
    p_query TEXT,
    p_max_lag_seconds INTEGER DEFAULT 30
) RETURNS SETOF RECORD AS $$
DECLARE
    v_replica RECORD;
    v_conn_string TEXT;
BEGIN
    -- Find suitable replica
    SELECT * INTO v_replica
    FROM replica_manager.replicas
    WHERE is_active = TRUE
      AND status = 'online'
      AND (lag_seconds IS NULL OR lag_seconds <= p_max_lag_seconds)
    ORDER BY lag_seconds NULLS LAST, random()
    LIMIT 1;
    
    IF v_replica IS NULL THEN
        RAISE EXCEPTION 'No suitable replica found';
    END IF;
    
    -- Build connection string
    v_conn_string := format(
        'host=%s port=%s dbname=postgres user=%s password=%s',
        v_replica.hostname, v_replica.port, 
        current_setting('replica_manager.user'),
        current_setting('replica_manager.password')
    );
    
    -- Execute query on replica
    RETURN QUERY
    SELECT * FROM dblink(v_conn_string, p_query) AS t;
END;
$$ LANGUAGE plpgsql;

-- Function to get replica statistics
CREATE OR REPLACE FUNCTION replica_manager.get_replica_stats() RETURNS TABLE (
    hostname TEXT,
    port INTEGER,
    status TEXT,
    lag_seconds INTEGER,
    last_checked TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        r.hostname,
        r.port,
        r.status,
        r.lag_seconds,
        r.last_checked
    FROM replica_manager.replicas r
    WHERE r.is_active = TRUE
    ORDER BY r.hostname;
END;
$$ LANGUAGE plpgsql;

-- Grant permissions
GRANT USAGE ON SCHEMA replica_manager TO security_admin;
GRANT SELECT ON replica_manager.replicas TO security_admin;
GRANT EXECUTE ON FUNCTION replica_manager.register_replica TO security_admin;
GRANT EXECUTE ON FUNCTION replica_manager.check_replica_status TO security_admin;
GRANT EXECUTE ON FUNCTION replica_manager.check_all_replicas TO security_admin;
GRANT EXECUTE ON FUNCTION replica_manager.execute_on_replica TO app_user, security_admin;
GRANT EXECUTE ON FUNCTION replica_manager.get_replica_stats TO app_user, security_admin;
