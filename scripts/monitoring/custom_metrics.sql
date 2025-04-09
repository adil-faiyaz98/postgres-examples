-- Custom Metrics for PostgreSQL Security Framework
CREATE SCHEMA IF NOT EXISTS metrics;

-- Table for storing metric definitions
CREATE TABLE IF NOT EXISTS metrics.definitions (
    id SERIAL PRIMARY KEY,
    metric_name TEXT NOT NULL UNIQUE,
    metric_type TEXT NOT NULL,
    description TEXT NOT NULL,
    query TEXT NOT NULL,
    labels TEXT[],
    interval_seconds INTEGER NOT NULL DEFAULT 60,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Table for storing metric values
CREATE TABLE IF NOT EXISTS metrics.values (
    id SERIAL PRIMARY KEY,
    metric_id INTEGER NOT NULL REFERENCES metrics.definitions(id),
    value NUMERIC NOT NULL,
    labels JSONB,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_values_metric_id ON metrics.values (metric_id);
CREATE INDEX IF NOT EXISTS idx_values_collected_at ON metrics.values (collected_at);

-- Function to register a new metric
CREATE OR REPLACE FUNCTION metrics.register_metric(
    p_metric_name TEXT,
    p_metric_type TEXT,
    p_description TEXT,
    p_query TEXT,
    p_labels TEXT[] DEFAULT NULL,
    p_interval_seconds INTEGER DEFAULT 60
) RETURNS INTEGER AS $$
DECLARE
    v_metric_id INTEGER;
BEGIN
    -- Validate metric type
    IF p_metric_type NOT IN ('counter', 'gauge', 'histogram', 'summary') THEN
        RAISE EXCEPTION 'Invalid metric type: %. Must be one of: counter, gauge, histogram, summary', p_metric_type;
    END IF;
    
    -- Insert metric definition
    INSERT INTO metrics.definitions (
        metric_name, metric_type, description, query, labels, interval_seconds
    ) VALUES (
        p_metric_name, p_metric_type, p_description, p_query, p_labels, p_interval_seconds
    ) ON CONFLICT (metric_name) DO UPDATE
    SET metric_type = p_metric_type,
        description = p_description,
        query = p_query,
        labels = p_labels,
        interval_seconds = p_interval_seconds,
        updated_at = NOW()
    RETURNING id INTO v_metric_id;
    
    -- Log metric registration
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'METRIC_REGISTERED', 'INFO', current_user, 
        format('Registered metric %s of type %s', p_metric_name, p_metric_type)
    );
    
    RETURN v_metric_id;
END;
$$ LANGUAGE plpgsql;

-- Function to collect a metric
CREATE OR REPLACE FUNCTION metrics.collect_metric(
    p_metric_id INTEGER
) RETURNS TABLE (
    value NUMERIC,
    labels JSONB
) AS $$
DECLARE
    v_metric RECORD;
    v_query TEXT;
BEGIN
    -- Get metric definition
    SELECT * INTO v_metric
    FROM metrics.definitions
    WHERE id = p_metric_id;
    
    IF v_metric IS NULL THEN
        RAISE EXCEPTION 'Metric with ID % not found', p_metric_id;
    END IF;
    
    -- Execute metric query
    FOR value, labels IN EXECUTE v_metric.query
    LOOP
        -- Store metric value
        INSERT INTO metrics.values (metric_id, value, labels)
        VALUES (p_metric_id, value, labels);
        
        RETURN NEXT;
    END LOOP;
    
    RETURN;
END;
$$ LANGUAGE plpgsql;

-- Function to collect all metrics
CREATE OR REPLACE FUNCTION metrics.collect_all_metrics() RETURNS INTEGER AS $$
DECLARE
    v_metric RECORD;
    v_count INTEGER := 0;
BEGIN
    -- Loop through enabled metrics
    FOR v_metric IN
        SELECT * FROM metrics.definitions
        WHERE enabled = TRUE
    LOOP
        -- Collect metric
        PERFORM metrics.collect_metric(v_metric.id);
        v_count := v_count + 1;
    END LOOP;
    
    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

-- Function to get metric values
CREATE OR REPLACE FUNCTION metrics.get_metric_values(
    p_metric_name TEXT,
    p_start_time TIMESTAMPTZ DEFAULT NOW() - INTERVAL '1 hour',
    p_end_time TIMESTAMPTZ DEFAULT NOW()
) RETURNS TABLE (
    value NUMERIC,
    labels JSONB,
    collected_at TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        v.value,
        v.labels,
        v.collected_at
    FROM metrics.values v
    JOIN metrics.definitions d ON v.metric_id = d.id
    WHERE d.metric_name = p_metric_name
      AND v.collected_at BETWEEN p_start_time AND p_end_time
    ORDER BY v.collected_at;
END;
$$ LANGUAGE plpgsql;

-- Function to export metrics in Prometheus format
CREATE OR REPLACE FUNCTION metrics.export_prometheus() RETURNS TEXT AS $$
DECLARE
    v_metric RECORD;
    v_value RECORD;
    v_result TEXT := '';
    v_label_str TEXT;
BEGIN
    -- Loop through metrics
    FOR v_metric IN
        SELECT * FROM metrics.definitions
        WHERE enabled = TRUE
    LOOP
        -- Add metric header
        v_result := v_result || '# HELP ' || v_metric.metric_name || ' ' || v_metric.description || E'\n';
        v_result := v_result || '# TYPE ' || v_metric.metric_name || ' ' || v_metric.metric_type || E'\n';
        
        -- Get latest values
        FOR v_value IN
            SELECT v.value, v.labels
            FROM metrics.values v
            WHERE v.metric_id = v_metric.id
              AND v.collected_at > NOW() - INTERVAL '5 minutes'
            ORDER BY v.collected_at DESC
        LOOP
            -- Format labels
            IF v_value.labels IS NOT NULL AND jsonb_typeof(v_value.labels) = 'object' THEN
                v_label_str := '{';
                
                SELECT string_agg(format('%I="%s"', key, value), ',')
                INTO v_label_str
                FROM jsonb_each_text(v_value.labels);
                
                v_label_str := v_label_str || '}';
            ELSE
                v_label_str := '';
            END IF;
            
            -- Add metric value
            v_result := v_result || v_metric.metric_name || v_label_str || ' ' || v_value.value || E'\n';
        END LOOP;
        
        -- Add newline between metrics
        v_result := v_result || E'\n';
    END LOOP;
    
    RETURN v_result;
END;
$$ LANGUAGE plpgsql;

-- Function to clean up old metric values
CREATE OR REPLACE FUNCTION metrics.cleanup_old_values(
    p_retention_days INTEGER DEFAULT 7
) RETURNS INTEGER AS $$
DECLARE
    v_count INTEGER;
BEGIN
    -- Delete old values
    DELETE FROM metrics.values
    WHERE collected_at < NOW() - (p_retention_days || ' days')::INTERVAL
    RETURNING count(*) INTO v_count;
    
    -- Log cleanup
    IF v_count > 0 THEN
        INSERT INTO logs.notification_log (
            event_type, severity, username, message
        ) VALUES (
            'METRICS_CLEANUP', 'INFO', current_user, 
            format('Cleaned up %s old metric values', v_count)
        );
    END IF;
    
    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

-- Register security metrics
DO $$
BEGIN
    -- Failed login attempts
    PERFORM metrics.register_metric(
        'postgres_failed_logins_total',
        'counter',
        'Total number of failed login attempts',
        $$
        SELECT
            count(*) AS value,
            jsonb_build_object('severity', severity) AS labels
        FROM logs.notification_log
        WHERE event_type = 'LOGIN_FAILURE'
          AND logged_at > NOW() - INTERVAL '1 hour'
        GROUP BY severity
        $$,
        ARRAY['severity'],
        300  -- 5 minutes
    );
    
    -- Active sessions
    PERFORM metrics.register_metric(
        'postgres_active_sessions',
        'gauge',
        'Number of active database sessions',
        $$
        SELECT
            count(*) AS value,
            jsonb_build_object('state', state) AS labels
        FROM pg_stat_activity
        WHERE state IS NOT NULL
        GROUP BY state
        $$,
        ARRAY['state'],
        60  -- 1 minute
    );
    
    -- Query execution time
    PERFORM metrics.register_metric(
        'postgres_query_execution_time_seconds',
        'histogram',
        'Query execution time in seconds',
        $$
        SELECT
            EXTRACT(EPOCH FROM (NOW() - query_start)) AS value,
            jsonb_build_object(
                'username', usename,
                'database', datname
            ) AS labels
        FROM pg_stat_activity
        WHERE state = 'active'
          AND query_start IS NOT NULL
          AND query != '<IDLE>'
          AND pid != pg_backend_pid()
        $$,
        ARRAY['username', 'database'],
        30  -- 30 seconds
    );
    
    -- Row level security denials
    PERFORM metrics.register_metric(
        'postgres_rls_denials_total',
        'counter',
        'Total number of row level security policy denials',
        $$
        SELECT
            count(*) AS value,
            jsonb_build_object('username', username) AS labels
        FROM logs.notification_log
        WHERE event_type = 'PERMISSION_DENIED'
          AND message LIKE '%row level security%'
          AND logged_at > NOW() - INTERVAL '1 hour'
        GROUP BY username
        $$,
        ARRAY['username'],
        300  -- 5 minutes
    );
    
    -- Encryption operations
    PERFORM metrics.register_metric(
        'postgres_encryption_operations_total',
        'counter',
        'Total number of encryption/decryption operations',
        $$
        SELECT
            count(*) AS value,
            jsonb_build_object('operation', 
                CASE WHEN message LIKE '%encrypt%' THEN 'encrypt'
                     WHEN message LIKE '%decrypt%' THEN 'decrypt'
                     ELSE 'other'
                END
            ) AS labels
        FROM logs.notification_log
        WHERE event_type IN ('ENCRYPTION', 'KEY_USAGE')
          AND logged_at > NOW() - INTERVAL '1 hour'
        GROUP BY 
            CASE WHEN message LIKE '%encrypt%' THEN 'encrypt'
                 WHEN message LIKE '%decrypt%' THEN 'decrypt'
                 ELSE 'other'
            END
        $$,
        ARRAY['operation'],
        300  -- 5 minutes
    );
    
    -- Detected anomalies
    PERFORM metrics.register_metric(
        'postgres_detected_anomalies',
        'gauge',
        'Number of detected security anomalies',
        $$
        SELECT
            count(*) AS value,
            jsonb_build_object(
                'anomaly_type', anomaly_type,
                'severity', severity
            ) AS labels
        FROM analytics.anomalies
        WHERE detected_at > NOW() - INTERVAL '1 day'
          AND NOT resolved
        GROUP BY anomaly_type, severity
        $$,
        ARRAY['anomaly_type', 'severity'],
        300  -- 5 minutes
    );
    
    -- Cache hit ratio
    PERFORM metrics.register_metric(
        'postgres_cache_hit_ratio',
        'gauge',
        'Buffer cache hit ratio',
        $$
        SELECT
            sum(heap_blks_hit) / (sum(heap_blks_hit) + sum(heap_blks_read) + 0.001) AS value,
            jsonb_build_object('database', datname) AS labels
        FROM pg_statio_user_tables
        JOIN pg_database ON pg_database.oid = pg_statio_user_tables.relid
        GROUP BY datname
        $$,
        ARRAY['database'],
        60  -- 1 minute
    );
    
    -- Connection utilization
    PERFORM metrics.register_metric(
        'postgres_connection_utilization',
        'gauge',
        'Connection utilization percentage',
        $$
        SELECT
            (count(*) * 100.0 / current_setting('max_connections')::integer) AS value,
            jsonb_build_object('database', datname) AS labels
        FROM pg_stat_activity
        GROUP BY datname
        $$,
        ARRAY['database'],
        60  -- 1 minute
    );
END $$;

-- Grant permissions
GRANT USAGE ON SCHEMA metrics TO security_admin;
GRANT SELECT ON metrics.definitions TO security_admin;
GRANT SELECT ON metrics.values TO security_admin;
GRANT EXECUTE ON FUNCTION metrics.register_metric TO security_admin;
GRANT EXECUTE ON FUNCTION metrics.collect_metric TO security_admin;
GRANT EXECUTE ON FUNCTION metrics.collect_all_metrics TO security_admin;
GRANT EXECUTE ON FUNCTION metrics.get_metric_values TO security_admin;
GRANT EXECUTE ON FUNCTION metrics.export_prometheus TO security_admin;
GRANT EXECUTE ON FUNCTION metrics.cleanup_old_values TO security_admin;
