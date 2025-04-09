-- Query Caching for PostgreSQL Security Framework
CREATE SCHEMA IF NOT EXISTS query_cache;

-- Create extension for Redis integration
CREATE EXTENSION IF NOT EXISTS redis_fdw;

-- Create server connection to Redis
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_foreign_server WHERE srvname = 'redis_server'
    ) THEN
        CREATE SERVER redis_server
            FOREIGN DATA WRAPPER redis_fdw
            OPTIONS (address 'redis-cache', port '6379');
            
        CREATE USER MAPPING FOR PUBLIC
            SERVER redis_server
            OPTIONS (password 'redis_password');
    END IF;
END $$;

-- Create foreign table for Redis cache
CREATE FOREIGN TABLE IF NOT EXISTS query_cache.cache (
    key TEXT,
    value TEXT
) SERVER redis_server
OPTIONS (database '0');

-- Table for storing cache metadata
CREATE TABLE IF NOT EXISTS query_cache.metadata (
    cache_key TEXT PRIMARY KEY,
    query_hash TEXT NOT NULL,
    table_dependencies TEXT[] NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    hit_count INTEGER NOT NULL DEFAULT 0,
    last_accessed TIMESTAMPTZ
);

-- Create index on query_hash for faster lookups
CREATE INDEX IF NOT EXISTS idx_metadata_query_hash ON query_cache.metadata (query_hash);

-- Function to generate a cache key
CREATE OR REPLACE FUNCTION query_cache.generate_key(
    p_query TEXT,
    p_params JSONB DEFAULT NULL
) RETURNS TEXT AS $$
DECLARE
    v_query_hash TEXT;
    v_params_hash TEXT := '';
BEGIN
    -- Hash the query
    v_query_hash := md5(p_query);
    
    -- Hash the parameters if provided
    IF p_params IS NOT NULL THEN
        v_params_hash := md5(p_params::text);
    END IF;
    
    -- Combine query hash and params hash
    RETURN 'qc:' || v_query_hash || ':' || v_params_hash;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Function to extract table dependencies from a query
CREATE OR REPLACE FUNCTION query_cache.extract_dependencies(
    p_query TEXT
) RETURNS TEXT[] AS $$
DECLARE
    v_tables TEXT[];
    v_schema_table TEXT;
    v_query TEXT;
BEGIN
    -- Prepare query to extract dependencies
    v_query := format(
        'EXPLAIN (FORMAT JSON) %s',
        p_query
    );
    
    -- Execute EXPLAIN and extract table dependencies
    BEGIN
        EXECUTE v_query INTO v_tables;
    EXCEPTION
        WHEN OTHERS THEN
            -- If EXPLAIN fails, extract tables using regex
            SELECT array_agg(DISTINCT schema_table)
            INTO v_tables
            FROM (
                SELECT substring(p_query FROM '(?i)FROM\s+([a-zA-Z0-9_\.]+)')
                    AS schema_table
                UNION ALL
                SELECT substring(p_query FROM '(?i)JOIN\s+([a-zA-Z0-9_\.]+)')
                    AS schema_table
                UNION ALL
                SELECT substring(p_query FROM '(?i)UPDATE\s+([a-zA-Z0-9_\.]+)')
                    AS schema_table
                UNION ALL
                SELECT substring(p_query FROM '(?i)INSERT\s+INTO\s+([a-zA-Z0-9_\.]+)')
                    AS schema_table
                UNION ALL
                SELECT substring(p_query FROM '(?i)DELETE\s+FROM\s+([a-zA-Z0-9_\.]+)')
                    AS schema_table
            ) t
            WHERE schema_table IS NOT NULL;
    END;
    
    RETURN v_tables;
END;
$$ LANGUAGE plpgsql;

-- Function to cache a query result
CREATE OR REPLACE FUNCTION query_cache.set(
    p_query TEXT,
    p_result TEXT,
    p_params JSONB DEFAULT NULL,
    p_ttl_seconds INTEGER DEFAULT 300
) RETURNS TEXT AS $$
DECLARE
    v_cache_key TEXT;
    v_dependencies TEXT[];
    v_expires_at TIMESTAMPTZ;
BEGIN
    -- Generate cache key
    v_cache_key := query_cache.generate_key(p_query, p_params);
    
    -- Extract table dependencies
    v_dependencies := query_cache.extract_dependencies(p_query);
    
    -- Calculate expiration time
    v_expires_at := NOW() + (p_ttl_seconds || ' seconds')::INTERVAL;
    
    -- Store result in Redis
    DELETE FROM query_cache.cache WHERE key = v_cache_key;
    INSERT INTO query_cache.cache (key, value) VALUES (v_cache_key, p_result);
    
    -- Store metadata
    INSERT INTO query_cache.metadata (
        cache_key, query_hash, table_dependencies, expires_at
    ) VALUES (
        v_cache_key, md5(p_query), v_dependencies, v_expires_at
    ) ON CONFLICT (cache_key) DO UPDATE
    SET table_dependencies = v_dependencies,
        expires_at = v_expires_at,
        created_at = NOW();
    
    -- Set TTL in Redis
    PERFORM redis_fdw_command('EXPIRE', ARRAY[v_cache_key, p_ttl_seconds::text]);
    
    RETURN v_cache_key;
END;
$$ LANGUAGE plpgsql;

-- Function to get a cached query result
CREATE OR REPLACE FUNCTION query_cache.get(
    p_query TEXT,
    p_params JSONB DEFAULT NULL
) RETURNS TEXT AS $$
DECLARE
    v_cache_key TEXT;
    v_result TEXT;
BEGIN
    -- Generate cache key
    v_cache_key := query_cache.generate_key(p_query, p_params);
    
    -- Get result from Redis
    SELECT value INTO v_result
    FROM query_cache.cache
    WHERE key = v_cache_key;
    
    -- Update metadata if cache hit
    IF v_result IS NOT NULL THEN
        UPDATE query_cache.metadata
        SET hit_count = hit_count + 1,
            last_accessed = NOW()
        WHERE cache_key = v_cache_key;
    END IF;
    
    RETURN v_result;
END;
$$ LANGUAGE plpgsql;

-- Function to invalidate cache entries for a table
CREATE OR REPLACE FUNCTION query_cache.invalidate_table(
    p_schema_name TEXT,
    p_table_name TEXT
) RETURNS INTEGER AS $$
DECLARE
    v_table_name TEXT;
    v_cache_key TEXT;
    v_count INTEGER := 0;
BEGIN
    -- Format table name
    v_table_name := p_schema_name || '.' || p_table_name;
    
    -- Find cache entries that depend on the table
    FOR v_cache_key IN
        SELECT cache_key
        FROM query_cache.metadata
        WHERE v_table_name = ANY(table_dependencies)
    LOOP
        -- Delete from Redis
        DELETE FROM query_cache.cache
        WHERE key = v_cache_key;
        
        -- Delete metadata
        DELETE FROM query_cache.metadata
        WHERE cache_key = v_cache_key;
        
        v_count := v_count + 1;
    END LOOP;
    
    -- Log invalidation
    IF v_count > 0 THEN
        INSERT INTO logs.notification_log (
            event_type, severity, username, message
        ) VALUES (
            'CACHE_INVALIDATED', 'INFO', current_user, 
            format('Invalidated %s cache entries for table %s', v_count, v_table_name)
        );
    END IF;
    
    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

-- Function to execute a query with caching
CREATE OR REPLACE FUNCTION query_cache.execute_cached(
    p_query TEXT,
    p_params JSONB DEFAULT NULL,
    p_ttl_seconds INTEGER DEFAULT 300
) RETURNS TEXT AS $$
DECLARE
    v_result TEXT;
BEGIN
    -- Try to get from cache
    v_result := query_cache.get(p_query, p_params);
    
    -- If not in cache, execute query and cache result
    IF v_result IS NULL THEN
        -- Execute query
        EXECUTE p_query INTO v_result;
        
        -- Cache result
        PERFORM query_cache.set(p_query, v_result, p_params, p_ttl_seconds);
    END IF;
    
    RETURN v_result;
END;
$$ LANGUAGE plpgsql;

-- Function to clean up expired cache entries
CREATE OR REPLACE FUNCTION query_cache.cleanup_expired() RETURNS INTEGER AS $$
DECLARE
    v_cache_key TEXT;
    v_count INTEGER := 0;
BEGIN
    -- Find expired cache entries
    FOR v_cache_key IN
        SELECT cache_key
        FROM query_cache.metadata
        WHERE expires_at < NOW()
    LOOP
        -- Delete from Redis
        DELETE FROM query_cache.cache
        WHERE key = v_cache_key;
        
        -- Delete metadata
        DELETE FROM query_cache.metadata
        WHERE cache_key = v_cache_key;
        
        v_count := v_count + 1;
    END LOOP;
    
    -- Log cleanup
    IF v_count > 0 THEN
        INSERT INTO logs.notification_log (
            event_type, severity, username, message
        ) VALUES (
            'CACHE_CLEANUP', 'INFO', current_user, 
            format('Cleaned up %s expired cache entries', v_count)
        );
    END IF;
    
    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

-- Function to get cache statistics
CREATE OR REPLACE FUNCTION query_cache.get_stats() RETURNS TABLE (
    total_entries INTEGER,
    total_size_bytes BIGINT,
    hit_count BIGINT,
    avg_ttl_seconds NUMERIC,
    oldest_entry TIMESTAMPTZ,
    newest_entry TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        count(*)::INTEGER AS total_entries,
        sum(length(value))::BIGINT AS total_size_bytes,
        sum(hit_count)::BIGINT AS hit_count,
        avg(EXTRACT(EPOCH FROM (expires_at - created_at)))::NUMERIC AS avg_ttl_seconds,
        min(created_at) AS oldest_entry,
        max(created_at) AS newest_entry
    FROM query_cache.metadata m
    JOIN query_cache.cache c ON m.cache_key = c.key;
END;
$$ LANGUAGE plpgsql;

-- Create trigger function to invalidate cache on table changes
CREATE OR REPLACE FUNCTION query_cache.invalidate_on_change() RETURNS TRIGGER AS $$
BEGIN
    -- Invalidate cache for the modified table
    PERFORM query_cache.invalidate_table(TG_TABLE_SCHEMA, TG_TABLE_NAME);
    
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Function to add cache invalidation trigger to a table
CREATE OR REPLACE FUNCTION query_cache.add_invalidation_trigger(
    p_schema_name TEXT,
    p_table_name TEXT
) RETURNS VOID AS $$
DECLARE
    v_trigger_name TEXT;
BEGIN
    -- Generate trigger name
    v_trigger_name := format(
        'trg_%s_cache_invalidate',
        p_table_name
    );
    
    -- Create trigger
    EXECUTE format(
        'CREATE TRIGGER %I
         AFTER INSERT OR UPDATE OR DELETE ON %I.%I
         FOR EACH STATEMENT
         EXECUTE FUNCTION query_cache.invalidate_on_change()',
        v_trigger_name,
        p_schema_name,
        p_table_name
    );
    
    -- Log trigger creation
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'CACHE_TRIGGER_CREATED', 'INFO', current_user, 
        format('Created cache invalidation trigger for %I.%I',
               p_schema_name, p_table_name)
    );
END;
$$ LANGUAGE plpgsql;

-- Grant permissions
GRANT USAGE ON SCHEMA query_cache TO app_user, security_admin;
GRANT SELECT ON query_cache.cache TO app_user, security_admin;
GRANT SELECT ON query_cache.metadata TO app_user, security_admin;
GRANT EXECUTE ON FUNCTION query_cache.generate_key TO app_user, security_admin;
GRANT EXECUTE ON FUNCTION query_cache.extract_dependencies TO app_user, security_admin;
GRANT EXECUTE ON FUNCTION query_cache.set TO app_user, security_admin;
GRANT EXECUTE ON FUNCTION query_cache.get TO app_user, security_admin;
GRANT EXECUTE ON FUNCTION query_cache.invalidate_table TO app_user, security_admin;
GRANT EXECUTE ON FUNCTION query_cache.execute_cached TO app_user, security_admin;
GRANT EXECUTE ON FUNCTION query_cache.cleanup_expired TO security_admin;
GRANT EXECUTE ON FUNCTION query_cache.get_stats TO app_user, security_admin;
GRANT EXECUTE ON FUNCTION query_cache.add_invalidation_trigger TO security_admin;
