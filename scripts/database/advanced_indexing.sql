-- Advanced Indexing Strategies for PostgreSQL Security Framework
CREATE SCHEMA IF NOT EXISTS indexing;

-- Table for storing index recommendations
CREATE TABLE IF NOT EXISTS indexing.recommendations (
    id SERIAL PRIMARY KEY,
    schema_name TEXT NOT NULL,
    table_name TEXT NOT NULL,
    column_names TEXT[] NOT NULL,
    index_type TEXT NOT NULL,
    estimated_improvement NUMERIC(5,2),
    query_pattern TEXT,
    is_implemented BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    implemented_at TIMESTAMPTZ
);

-- Function to analyze a table and recommend indexes
CREATE OR REPLACE FUNCTION indexing.analyze_table(
    p_schema_name TEXT,
    p_table_name TEXT
) RETURNS SETOF indexing.recommendations AS $$
DECLARE
    v_query TEXT;
    v_result RECORD;
    v_recommendation_id INTEGER;
BEGIN
    -- Get missing indexes from pg_stat_statements
    FOR v_result IN
        SELECT 
            array_agg(attname) AS columns,
            'btree' AS index_type,
            100.0 * (sum(s.total_cost) - sum(s.total_cost * s.startup_cost / (s.total_cost + 1))) / sum(s.total_cost) AS benefit,
            substring(s.query, 1, 200) AS query_sample
        FROM pg_stat_statements s
        JOIN pg_stat_user_tables t ON s.userid = t.relid
        JOIN pg_attribute a ON t.relid = a.attrelid
        WHERE t.schemaname = p_schema_name
          AND t.relname = p_table_name
          AND s.query ILIKE '%WHERE%'
          AND s.query ILIKE '%' || a.attname || '%'
          AND NOT EXISTS (
            SELECT 1 FROM pg_index i
            WHERE i.indrelid = t.relid
              AND a.attnum = ANY(i.indkey)
          )
        GROUP BY a.attname, s.query
        HAVING sum(s.total_cost) > 1000
        ORDER BY benefit DESC
        LIMIT 5
    LOOP
        -- Insert recommendation
        INSERT INTO indexing.recommendations (
            schema_name, table_name, column_names, index_type, 
            estimated_improvement, query_pattern
        ) VALUES (
            p_schema_name, p_table_name, v_result.columns, v_result.index_type,
            v_result.benefit, v_result.query_sample
        ) RETURNING id INTO v_recommendation_id;
        
        RETURN QUERY
        SELECT * FROM indexing.recommendations
        WHERE id = v_recommendation_id;
    END LOOP;
    
    -- Check for partial index opportunities
    FOR v_result IN
        SELECT 
            array_agg(attname) AS columns,
            'partial_btree' AS index_type,
            100.0 * (sum(s.total_cost) - sum(s.total_cost * s.startup_cost / (s.total_cost + 1))) / sum(s.total_cost) AS benefit,
            substring(s.query, 1, 200) AS query_sample,
            substring(s.query FROM 'WHERE\s+([^;]+)') AS where_clause
        FROM pg_stat_statements s
        JOIN pg_stat_user_tables t ON s.userid = t.relid
        JOIN pg_attribute a ON t.relid = a.attrelid
        WHERE t.schemaname = p_schema_name
          AND t.relname = p_table_name
          AND s.query ILIKE '%WHERE%'
          AND s.query ILIKE '%' || a.attname || '%'
          AND s.query ~* 'WHERE\s+[^;]+\s+(=|>|<|>=|<=|IN)\s+'
          AND NOT EXISTS (
            SELECT 1 FROM pg_index i
            JOIN pg_class c ON i.indexrelid = c.oid
            WHERE i.indrelid = t.relid
              AND a.attnum = ANY(i.indkey)
              AND c.relname LIKE '%partial%'
          )
        GROUP BY a.attname, s.query
        HAVING sum(s.total_cost) > 1000
        ORDER BY benefit DESC
        LIMIT 5
    LOOP
        -- Insert recommendation
        INSERT INTO indexing.recommendations (
            schema_name, table_name, column_names, index_type, 
            estimated_improvement, query_pattern
        ) VALUES (
            p_schema_name, p_table_name, v_result.columns, v_result.index_type,
            v_result.benefit, v_result.query_sample
        ) RETURNING id INTO v_recommendation_id;
        
        RETURN QUERY
        SELECT * FROM indexing.recommendations
        WHERE id = v_recommendation_id;
    END LOOP;
    
    -- Check for covering index opportunities
    FOR v_result IN
        SELECT 
            array_agg(DISTINCT a.attname) AS columns,
            'covering_btree' AS index_type,
            100.0 * (sum(s.total_cost) - sum(s.total_cost * s.startup_cost / (s.total_cost + 1))) / sum(s.total_cost) AS benefit,
            substring(s.query, 1, 200) AS query_sample
        FROM pg_stat_statements s
        JOIN pg_stat_user_tables t ON s.userid = t.relid
        JOIN pg_attribute a ON t.relid = a.attrelid
        WHERE t.schemaname = p_schema_name
          AND t.relname = p_table_name
          AND s.query ILIKE '%SELECT%'
          AND s.query ILIKE '%WHERE%'
          AND s.query ILIKE '%' || a.attname || '%'
          AND NOT EXISTS (
            SELECT 1 FROM pg_index i
            WHERE i.indrelid = t.relid
              AND array_length(i.indkey, 1) >= 2
              AND a.attnum = ANY(i.indkey)
          )
        GROUP BY s.query
        HAVING count(DISTINCT a.attname) >= 2
        AND sum(s.total_cost) > 1000
        ORDER BY benefit DESC
        LIMIT 5
    LOOP
        -- Insert recommendation
        INSERT INTO indexing.recommendations (
            schema_name, table_name, column_names, index_type, 
            estimated_improvement, query_pattern
        ) VALUES (
            p_schema_name, p_table_name, v_result.columns, v_result.index_type,
            v_result.benefit, v_result.query_sample
        ) RETURNING id INTO v_recommendation_id;
        
        RETURN QUERY
        SELECT * FROM indexing.recommendations
        WHERE id = v_recommendation_id;
    END LOOP;
    
    RETURN;
END;
$$ LANGUAGE plpgsql;

-- Function to implement a recommended index
CREATE OR REPLACE FUNCTION indexing.implement_recommendation(
    p_recommendation_id INTEGER
) RETURNS TEXT AS $$
DECLARE
    v_rec RECORD;
    v_index_name TEXT;
    v_sql TEXT;
BEGIN
    -- Get recommendation
    SELECT * INTO v_rec
    FROM indexing.recommendations
    WHERE id = p_recommendation_id;
    
    IF v_rec IS NULL THEN
        RAISE EXCEPTION 'Recommendation with ID % not found', p_recommendation_id;
    END IF;
    
    IF v_rec.is_implemented THEN
        RETURN 'Index already implemented';
    END IF;
    
    -- Generate index name
    v_index_name := format(
        'idx_%s_%s_%s',
        v_rec.table_name,
        array_to_string(v_rec.column_names, '_'),
        v_rec.index_type
    );
    
    -- Generate SQL based on index type
    CASE v_rec.index_type
        WHEN 'btree' THEN
            v_sql := format(
                'CREATE INDEX %I ON %I.%I (%s)',
                v_index_name,
                v_rec.schema_name,
                v_rec.table_name,
                array_to_string(v_rec.column_names, ', ')
            );
        
        WHEN 'partial_btree' THEN
            v_sql := format(
                'CREATE INDEX %I ON %I.%I (%s) WHERE %s',
                v_index_name,
                v_rec.schema_name,
                v_rec.table_name,
                array_to_string(v_rec.column_names, ', '),
                -- Extract WHERE clause from query pattern
                substring(v_rec.query_pattern FROM 'WHERE\s+([^;]+)')
            );
        
        WHEN 'covering_btree' THEN
            v_sql := format(
                'CREATE INDEX %I ON %I.%I (%s) INCLUDE (%s)',
                v_index_name,
                v_rec.schema_name,
                v_rec.table_name,
                array_to_string(v_rec.column_names[1:1], ', '),
                array_to_string(v_rec.column_names[2:], ', ')
            );
        
        WHEN 'hash' THEN
            v_sql := format(
                'CREATE INDEX %I ON %I.%I USING hash (%s)',
                v_index_name,
                v_rec.schema_name,
                v_rec.table_name,
                array_to_string(v_rec.column_names, ', ')
            );
        
        WHEN 'gin' THEN
            v_sql := format(
                'CREATE INDEX %I ON %I.%I USING gin (%s)',
                v_index_name,
                v_rec.schema_name,
                v_rec.table_name,
                array_to_string(v_rec.column_names, ', ')
            );
        
        WHEN 'gist' THEN
            v_sql := format(
                'CREATE INDEX %I ON %I.%I USING gist (%s)',
                v_index_name,
                v_rec.schema_name,
                v_rec.table_name,
                array_to_string(v_rec.column_names, ', ')
            );
        
        ELSE
            RAISE EXCEPTION 'Unsupported index type: %', v_rec.index_type;
    END CASE;
    
    -- Create index
    EXECUTE v_sql;
    
    -- Update recommendation
    UPDATE indexing.recommendations
    SET is_implemented = TRUE,
        implemented_at = NOW()
    WHERE id = p_recommendation_id;
    
    -- Log index creation
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'INDEX_CREATED', 'INFO', current_user, 
        format('Created %s index %I on %I.%I (%s)',
               v_rec.index_type, v_index_name, v_rec.schema_name, 
               v_rec.table_name, array_to_string(v_rec.column_names, ', '))
    );
    
    RETURN v_sql;
END;
$$ LANGUAGE plpgsql;

-- Function to analyze index usage
CREATE OR REPLACE FUNCTION indexing.analyze_index_usage(
    p_schema_name TEXT DEFAULT NULL
) RETURNS TABLE (
    schema_name TEXT,
    table_name TEXT,
    index_name TEXT,
    index_size TEXT,
    index_scans BIGINT,
    rows_fetched BIGINT,
    rows_inserted BIGINT,
    efficiency NUMERIC(5,2),
    recommendation TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        s.schemaname,
        s.relname,
        s.indexrelname,
        pg_size_pretty(pg_relation_size(i.indexrelid)),
        s.idx_scan,
        s.idx_tup_fetch,
        s.idx_tup_insert,
        CASE
            WHEN s.idx_scan = 0 THEN 0
            ELSE (s.idx_tup_fetch::numeric / s.idx_scan)
        END AS efficiency,
        CASE
            WHEN s.idx_scan = 0 AND pg_relation_size(i.indexrelid) > 10 * 1024 * 1024 THEN 'Consider dropping (unused)'
            WHEN s.idx_scan < 100 AND pg_relation_size(i.indexrelid) > 100 * 1024 * 1024 THEN 'Consider dropping (low usage, large size)'
            WHEN s.idx_scan > 1000 AND (s.idx_tup_fetch::numeric / s.idx_scan) < 1 THEN 'Consider restructuring (low efficiency)'
            ELSE 'Keep'
        END AS recommendation
    FROM pg_stat_user_indexes s
    JOIN pg_index i ON s.indexrelid = i.indexrelid
    WHERE (p_schema_name IS NULL OR s.schemaname = p_schema_name)
    ORDER BY 
        CASE WHEN s.idx_scan = 0 THEN 0 ELSE 1 END,
        pg_relation_size(i.indexrelid) DESC;
END;
$$ LANGUAGE plpgsql;

-- Function to create a BRIN index for time-series data
CREATE OR REPLACE FUNCTION indexing.create_brin_index(
    p_schema_name TEXT,
    p_table_name TEXT,
    p_timestamp_column TEXT,
    p_pages_per_range INTEGER DEFAULT 128
) RETURNS TEXT AS $$
DECLARE
    v_index_name TEXT;
    v_sql TEXT;
BEGIN
    -- Generate index name
    v_index_name := format(
        'idx_%s_%s_brin',
        p_table_name,
        p_timestamp_column
    );
    
    -- Create BRIN index
    v_sql := format(
        'CREATE INDEX %I ON %I.%I USING brin (%I) WITH (pages_per_range = %s)',
        v_index_name,
        p_schema_name,
        p_table_name,
        p_timestamp_column,
        p_pages_per_range
    );
    
    EXECUTE v_sql;
    
    -- Log index creation
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'INDEX_CREATED', 'INFO', current_user, 
        format('Created BRIN index %I on %I.%I (%I)',
               v_index_name, p_schema_name, p_table_name, p_timestamp_column)
    );
    
    RETURN v_sql;
END;
$$ LANGUAGE plpgsql;

-- Function to create a GIN index for full-text search
CREATE OR REPLACE FUNCTION indexing.create_fulltext_index(
    p_schema_name TEXT,
    p_table_name TEXT,
    p_text_column TEXT,
    p_language TEXT DEFAULT 'english'
) RETURNS TEXT AS $$
DECLARE
    v_index_name TEXT;
    v_sql TEXT;
BEGIN
    -- Generate index name
    v_index_name := format(
        'idx_%s_%s_fulltext',
        p_table_name,
        p_text_column
    );
    
    -- Create GIN index for full-text search
    v_sql := format(
        'CREATE INDEX %I ON %I.%I USING gin (to_tsvector(%L, %I))',
        v_index_name,
        p_schema_name,
        p_table_name,
        p_language,
        p_text_column
    );
    
    EXECUTE v_sql;
    
    -- Log index creation
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'INDEX_CREATED', 'INFO', current_user, 
        format('Created full-text search index %I on %I.%I (%I)',
               v_index_name, p_schema_name, p_table_name, p_text_column)
    );
    
    RETURN v_sql;
END;
$$ LANGUAGE plpgsql;

-- Grant permissions
GRANT USAGE ON SCHEMA indexing TO security_admin;
GRANT SELECT ON indexing.recommendations TO security_admin;
GRANT EXECUTE ON FUNCTION indexing.analyze_table TO security_admin;
GRANT EXECUTE ON FUNCTION indexing.implement_recommendation TO security_admin;
GRANT EXECUTE ON FUNCTION indexing.analyze_index_usage TO security_admin;
GRANT EXECUTE ON FUNCTION indexing.create_brin_index TO security_admin;
GRANT EXECUTE ON FUNCTION indexing.create_fulltext_index TO security_admin;
