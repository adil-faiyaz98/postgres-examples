-- Distributed Tracing for PostgreSQL Security Framework
CREATE SCHEMA IF NOT EXISTS tracing;

-- Create extension for HTTP requests
CREATE EXTENSION IF NOT EXISTS http;

-- Table for storing trace spans
CREATE TABLE IF NOT EXISTS tracing.spans (
    id UUID PRIMARY KEY,
    trace_id UUID NOT NULL,
    parent_id UUID,
    operation_name TEXT NOT NULL,
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ,
    duration_ms INTEGER,
    status TEXT,
    tags JSONB,
    logs JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create index on trace_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_spans_trace_id ON tracing.spans (trace_id);

-- Function to start a new trace
CREATE OR REPLACE FUNCTION tracing.start_trace(
    p_operation_name TEXT,
    p_tags JSONB DEFAULT '{}'::jsonb
) RETURNS UUID AS $$
DECLARE
    v_trace_id UUID;
    v_span_id UUID;
BEGIN
    -- Generate trace ID and span ID
    v_trace_id := gen_random_uuid();
    v_span_id := gen_random_uuid();

    -- Store trace context in session
    PERFORM set_config('tracing.current_trace_id', v_trace_id::text, false);
    PERFORM set_config('tracing.current_span_id', v_span_id::text, false);

    -- Create root span
    INSERT INTO tracing.spans (
        id, trace_id, parent_id, operation_name, start_time, tags
    ) VALUES (
        v_span_id, v_trace_id, NULL, p_operation_name, NOW(), p_tags
    );

    RETURN v_trace_id;
END;
$$ LANGUAGE plpgsql;

-- Function to start a new span
CREATE OR REPLACE FUNCTION tracing.start_span(
    p_operation_name TEXT,
    p_tags JSONB DEFAULT '{}'::jsonb
) RETURNS UUID AS $$
DECLARE
    v_trace_id UUID;
    v_parent_id UUID;
    v_span_id UUID;
BEGIN
    -- Get current trace context
    v_trace_id := current_setting('tracing.current_trace_id', true)::UUID;
    v_parent_id := current_setting('tracing.current_span_id', true)::UUID;

    -- If no active trace, start a new one
    IF v_trace_id IS NULL THEN
        v_trace_id := tracing.start_trace(p_operation_name, p_tags);
        RETURN v_trace_id;
    END IF;

    -- Generate span ID
    v_span_id := gen_random_uuid();

    -- Update current span ID
    PERFORM set_config('tracing.current_span_id', v_span_id::text, false);

    -- Create span
    INSERT INTO tracing.spans (
        id, trace_id, parent_id, operation_name, start_time, tags
    ) VALUES (
        v_span_id, v_trace_id, v_parent_id, p_operation_name, NOW(), p_tags
    );

    RETURN v_span_id;
END;
$$ LANGUAGE plpgsql;

-- Function to end a span
CREATE OR REPLACE FUNCTION tracing.end_span(
    p_span_id UUID DEFAULT NULL,
    p_status TEXT DEFAULT 'ok',
    p_logs JSONB DEFAULT '{}'::jsonb
) RETURNS VOID AS $$
DECLARE
    v_span_id UUID;
    v_parent_id UUID;
BEGIN
    -- Get span ID to end
    IF p_span_id IS NULL THEN
        v_span_id := current_setting('tracing.current_span_id', true)::UUID;
    ELSE
        v_span_id := p_span_id;
    END IF;

    -- If no span ID, do nothing
    IF v_span_id IS NULL THEN
        RETURN;
    END IF;

    -- Update span
    UPDATE tracing.spans
    SET end_time = NOW(),
        duration_ms = EXTRACT(EPOCH FROM (NOW() - start_time)) * 1000,
        status = p_status,
        logs = p_logs
    WHERE id = v_span_id;

    -- If ending current span, restore parent span as current
    IF p_span_id IS NULL OR p_span_id = current_setting('tracing.current_span_id', true)::UUID THEN
        -- Get parent span ID
        SELECT parent_id INTO v_parent_id
        FROM tracing.spans
        WHERE id = v_span_id;

        -- Set parent as current span
        IF v_parent_id IS NOT NULL THEN
            PERFORM set_config('tracing.current_span_id', v_parent_id::text, false);
        ELSE
            PERFORM set_config('tracing.current_span_id', NULL, false);
            PERFORM set_config('tracing.current_trace_id', NULL, false);
        END IF;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Function to add a log to the current span
CREATE OR REPLACE FUNCTION tracing.add_log(
    p_key TEXT,
    p_value JSONB
) RETURNS VOID AS $$
DECLARE
    v_span_id UUID;
    v_logs JSONB;
BEGIN
    -- Get current span ID
    v_span_id := current_setting('tracing.current_span_id', true)::UUID;

    -- If no active span, do nothing
    IF v_span_id IS NULL THEN
        RETURN;
    END IF;

    -- Get current logs
    SELECT logs INTO v_logs
    FROM tracing.spans
    WHERE id = v_span_id;

    -- Add new log
    IF v_logs IS NULL THEN
        v_logs := jsonb_build_object(p_key, p_value);
    ELSE
        v_logs := v_logs || jsonb_build_object(p_key, p_value);
    END IF;

    -- Update span
    UPDATE tracing.spans
    SET logs = v_logs
    WHERE id = v_span_id;
END;
$$ LANGUAGE plpgsql;

-- Function to add a tag to the current span
CREATE OR REPLACE FUNCTION tracing.add_tag(
    p_key TEXT,
    p_value TEXT
) RETURNS VOID AS $$
DECLARE
    v_span_id UUID;
    v_tags JSONB;
BEGIN
    -- Get current span ID
    v_span_id := current_setting('tracing.current_span_id', true)::UUID;

    -- If no active span, do nothing
    IF v_span_id IS NULL THEN
        RETURN;
    END IF;

    -- Get current tags
    SELECT tags INTO v_tags
    FROM tracing.spans
    WHERE id = v_span_id;

    -- Add new tag
    IF v_tags IS NULL THEN
        v_tags := jsonb_build_object(p_key, p_value);
    ELSE
        v_tags := v_tags || jsonb_build_object(p_key, p_value);
    END IF;

    -- Update span
    UPDATE tracing.spans
    SET tags = v_tags
    WHERE id = v_span_id;
END;
$$ LANGUAGE plpgsql;

-- Function to export trace to Jaeger
CREATE OR REPLACE FUNCTION tracing.export_to_jaeger(
    p_trace_id UUID,
    p_jaeger_url TEXT DEFAULT 'http://jaeger-collector:14268/api/traces'
) RETURNS BOOLEAN AS $$
DECLARE
    v_spans JSONB;
    v_jaeger_spans JSONB := '[]'::jsonb;
    v_span RECORD;
    v_response RECORD;
BEGIN
    -- Get all spans for the trace
    FOR v_span IN
        SELECT * FROM tracing.spans
        WHERE trace_id = p_trace_id
    LOOP
        -- Convert to Jaeger format
        v_jaeger_spans := v_jaeger_spans || jsonb_build_object(
            'traceID', v_span.trace_id,
            'spanID', v_span.id,
            'parentSpanID', v_span.parent_id,
            'operationName', v_span.operation_name,
            'startTime', EXTRACT(EPOCH FROM v_span.start_time) * 1000000,
            'duration', COALESCE(v_span.duration_ms, 0) * 1000,
            'tags', COALESCE(v_span.tags, '{}'::jsonb),
            'logs', COALESCE(v_span.logs, '{}'::jsonb)
        );
    END LOOP;

    -- Build Jaeger payload
    v_spans := jsonb_build_object(
        'process', jsonb_build_object(
            'serviceName', 'postgres-security-framework',
            'tags', '{}'::jsonb
        ),
        'spans', v_jaeger_spans
    );

    -- Send to Jaeger
    SELECT * INTO v_response
    FROM http_post(
        p_jaeger_url,
        jsonb_build_array(v_spans)::text,
        'application/json'
    );

    -- Check response
    IF v_response.status = 200 THEN
        RETURN TRUE;
    ELSE
        RAISE WARNING 'Failed to export trace to Jaeger: %', v_response.content;
        RETURN FALSE;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Function to get trace details
CREATE OR REPLACE FUNCTION tracing.get_trace(
    p_trace_id UUID
) RETURNS TABLE (
    span_id UUID,
    parent_id UUID,
    operation_name TEXT,
    start_time TIMESTAMPTZ,
    end_time TIMESTAMPTZ,
    duration_ms INTEGER,
    status TEXT,
    tags JSONB,
    logs JSONB
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        s.id,
        s.parent_id,
        s.operation_name,
        s.start_time,
        s.end_time,
        s.duration_ms,
        s.status,
        s.tags,
        s.logs
    FROM tracing.spans s
    WHERE s.trace_id = p_trace_id
    ORDER BY s.start_time;
END;
$$ LANGUAGE plpgsql;

-- Create trigger function to automatically trace queries
CREATE OR REPLACE FUNCTION tracing.trace_query() RETURNS event_trigger AS $$
DECLARE
    v_query TEXT;
    v_span_id UUID;
BEGIN
    -- Get current query
    v_query := current_query();

    -- Start span for query
    v_span_id := tracing.start_span(
        'sql_query',
        jsonb_build_object('query', v_query)
    );

    -- End span when query completes
    PERFORM tracing.end_span(v_span_id);
EXCEPTION
    WHEN OTHERS THEN
        -- End span with error status
        PERFORM tracing.end_span(
            v_span_id,
            'error',
            jsonb_build_object('error', SQLERRM)
        );
        RAISE;
END;
$$ LANGUAGE plpgsql;

-- Function to export trace to Zipkin
CREATE OR REPLACE FUNCTION tracing.export_to_zipkin(
    p_trace_id UUID,
    p_zipkin_url TEXT DEFAULT 'http://zipkin:9411/api/v2/spans'
) RETURNS BOOLEAN AS $$
DECLARE
    v_zipkin_spans JSONB := '[]'::jsonb;
    v_span RECORD;
    v_response RECORD;
BEGIN
    -- Get all spans for the trace
    FOR v_span IN
        SELECT * FROM tracing.spans
        WHERE trace_id = p_trace_id
    LOOP
        -- Convert to Zipkin format
        v_zipkin_spans := v_zipkin_spans || jsonb_build_object(
            'id', v_span.id,
            'traceId', v_span.trace_id,
            'parentId', v_span.parent_id,
            'name', v_span.operation_name,
            'timestamp', EXTRACT(EPOCH FROM v_span.start_time) * 1000000,
            'duration', COALESCE(v_span.duration_ms, 0) * 1000,
            'tags', COALESCE(v_span.tags, '{}'::jsonb),
            'localEndpoint', jsonb_build_object(
                'serviceName', 'postgres-security-framework'
            )
        );
    END LOOP;

    -- Send to Zipkin
    SELECT * INTO v_response
    FROM http_post(
        p_zipkin_url,
        v_zipkin_spans::text,
        'application/json'
    );

    -- Check response
    IF v_response.status = 200 THEN
        RETURN TRUE;
    ELSE
        RAISE WARNING 'Failed to export trace to Zipkin: %', v_response.content;
        RETURN FALSE;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Function to trace a database operation
CREATE OR REPLACE FUNCTION tracing.trace_operation(
    p_operation_name TEXT,
    p_sql TEXT,
    p_params JSONB DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
    v_span_id UUID;
    v_result JSONB;
    v_start_time TIMESTAMPTZ;
    v_end_time TIMESTAMPTZ;
    v_duration_ms INTEGER;
BEGIN
    -- Start span
    v_span_id := tracing.start_span(
        p_operation_name,
        jsonb_build_object(
            'sql', p_sql,
            'params', p_params
        )
    );

    v_start_time := NOW();

    -- Execute SQL
    BEGIN
        EXECUTE p_sql INTO v_result;

        -- End span with success
        v_end_time := NOW();
        v_duration_ms := EXTRACT(EPOCH FROM (v_end_time - v_start_time)) * 1000;

        PERFORM tracing.end_span(
            v_span_id,
            'ok',
            jsonb_build_object(
                'duration_ms', v_duration_ms,
                'result_size', jsonb_array_length(v_result)
            )
        );
    EXCEPTION
        WHEN OTHERS THEN
            -- End span with error
            v_end_time := NOW();
            v_duration_ms := EXTRACT(EPOCH FROM (v_end_time - v_start_time)) * 1000;

            PERFORM tracing.end_span(
                v_span_id,
                'error',
                jsonb_build_object(
                    'duration_ms', v_duration_ms,
                    'error', SQLERRM,
                    'error_code', SQLSTATE
                )
            );

            RAISE;
    END;

    RETURN v_result;
END;
$$ LANGUAGE plpgsql;

-- Function to clean up old traces
CREATE OR REPLACE FUNCTION tracing.cleanup_old_traces(
    p_days INTEGER DEFAULT 7
) RETURNS INTEGER AS $$
DECLARE
    v_count INTEGER;
BEGIN
    DELETE FROM tracing.spans
    WHERE created_at < NOW() - (p_days || ' days')::INTERVAL
    RETURNING count(*) INTO v_count;

    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

-- Create view for trace summary
CREATE OR REPLACE VIEW tracing.trace_summary AS
SELECT
    s.trace_id,
    min(s.start_time) AS trace_start_time,
    max(s.end_time) AS trace_end_time,
    sum(s.duration_ms) AS total_duration_ms,
    count(*) AS span_count,
    count(*) FILTER (WHERE s.status = 'error') AS error_count,
    array_agg(DISTINCT s.operation_name) AS operations
FROM tracing.spans s
GROUP BY s.trace_id
ORDER BY min(s.start_time) DESC;

-- Grant permissions
GRANT USAGE ON SCHEMA tracing TO app_user, security_admin;
GRANT SELECT ON tracing.spans TO app_user, security_admin;
GRANT SELECT ON tracing.trace_summary TO app_user, security_admin;
GRANT EXECUTE ON FUNCTION tracing.start_trace TO app_user, security_admin;
GRANT EXECUTE ON FUNCTION tracing.start_span TO app_user, security_admin;
GRANT EXECUTE ON FUNCTION tracing.end_span TO app_user, security_admin;
GRANT EXECUTE ON FUNCTION tracing.add_log TO app_user, security_admin;
GRANT EXECUTE ON FUNCTION tracing.add_tag TO app_user, security_admin;
GRANT EXECUTE ON FUNCTION tracing.get_trace TO app_user, security_admin;
GRANT EXECUTE ON FUNCTION tracing.trace_operation TO app_user, security_admin;
GRANT EXECUTE ON FUNCTION tracing.export_to_jaeger TO security_admin;
GRANT EXECUTE ON FUNCTION tracing.export_to_zipkin TO security_admin;
GRANT EXECUTE ON FUNCTION tracing.cleanup_old_traces TO security_admin;
