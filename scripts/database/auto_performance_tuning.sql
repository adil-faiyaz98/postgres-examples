-- Automated Database Performance Tuning for PostgreSQL Security Framework
CREATE SCHEMA IF NOT EXISTS auto_tuning;

-- Create extension for machine learning
CREATE EXTENSION IF NOT EXISTS plpython3u;

-- Table for storing parameter tuning history
CREATE TABLE IF NOT EXISTS auto_tuning.parameter_history (
    id SERIAL PRIMARY KEY,
    parameter_name TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason TEXT NOT NULL,
    performance_impact JSONB,
    reverted BOOLEAN NOT NULL DEFAULT FALSE
);

-- Table for storing index recommendations
CREATE TABLE IF NOT EXISTS auto_tuning.index_recommendations (
    id SERIAL PRIMARY KEY,
    schema_name TEXT NOT NULL,
    table_name TEXT NOT NULL,
    column_names TEXT[] NOT NULL,
    index_type TEXT NOT NULL,
    estimated_improvement NUMERIC(5,2),
    creation_cost TEXT,
    maintenance_cost TEXT,
    recommended_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    implemented BOOLEAN NOT NULL DEFAULT FALSE,
    implemented_at TIMESTAMPTZ
);

-- Table for storing query optimizations
CREATE TABLE IF NOT EXISTS auto_tuning.query_optimizations (
    id SERIAL PRIMARY KEY,
    query_hash TEXT NOT NULL,
    original_query TEXT NOT NULL,
    optimized_query TEXT NOT NULL,
    optimization_type TEXT NOT NULL,
    performance_improvement_percent NUMERIC(5,2),
    recommended_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    implemented BOOLEAN NOT NULL DEFAULT FALSE,
    implemented_at TIMESTAMPTZ
);

-- Function to analyze workload and recommend indexes
CREATE OR REPLACE FUNCTION auto_tuning.recommend_indexes() RETURNS SETOF auto_tuning.index_recommendations AS $$
import numpy as np
from sklearn.cluster import KMeans
import json

# Get query patterns from analytics
query_patterns = plpy.execute("""
    SELECT query_pattern, frequency, avg_duration
    FROM analytics.query_patterns
    WHERE frequency > 10
    ORDER BY frequency * avg_duration DESC
    LIMIT 100
""")

# Get existing indexes
existing_indexes = plpy.execute("""
    SELECT
        schemaname AS schema_name,
        tablename AS table_name,
        indexname AS index_name,
        indexdef AS index_definition
    FROM pg_indexes
    WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
""")

# Extract tables and columns from query patterns
tables_columns = []
for pattern in query_patterns:
    # Simple parsing to extract tables and columns
    # In a real implementation, this would use a proper SQL parser
    query = pattern['query_pattern'].lower()
    
    # Extract tables
    from_pos = query.find('from ')
    where_pos = query.find('where ')
    
    if from_pos > 0:
        tables_section = query[from_pos+5:where_pos if where_pos > 0 else len(query)]
        tables = [t.strip() for t in tables_section.split(',')]
        
        # Extract columns from WHERE clause
        columns = []
        if where_pos > 0:
            where_clause = query[where_pos+6:]
            # Simple extraction of column names
            for part in where_clause.split('and'):
                if '=' in part:
                    col = part.split('=')[0].strip()
                    columns.append(col)
        
        for table in tables:
            if '.' in table:
                schema, table_name = table.split('.')
            else:
                schema = 'public'
                table_name = table
            
            tables_columns.append({
                'schema': schema,
                'table': table_name,
                'columns': columns,
                'frequency': pattern['frequency'],
                'duration': pattern['avg_duration']
            })

# Cluster similar queries
if len(tables_columns) > 0:
    # Create feature matrix (very simplified)
    # In a real implementation, this would use more sophisticated features
    table_dict = {}
    for i, tc in enumerate(tables_columns):
        key = f"{tc['schema']}.{tc['table']}"
        if key not in table_dict:
            table_dict[key] = len(table_dict)
    
    # Create recommendations
    for table_key, _ in table_dict.items():
        schema, table = table_key.split('.')
        
        # Get columns for this table
        table_data = [tc for tc in tables_columns if f"{tc['schema']}.{tc['table']}" == table_key]
        if not table_data:
            continue
            
        # Count column occurrences
        column_counts = {}
        for td in table_data:
            for col in td['columns']:
                if col in column_counts:
                    column_counts[col] += 1
                else:
                    column_counts[col] = 1
        
        # Find most frequently used columns
        sorted_columns = sorted(column_counts.items(), key=lambda x: x[1], reverse=True)
        
        # Check if index already exists
        for col_name, count in sorted_columns[:3]:  # Consider top 3 columns
            # Skip if column name looks like a function or expression
            if '(' in col_name or ')' in col_name:
                continue
                
            # Check if index already exists
            index_exists = False
            for idx in existing_indexes:
                if (idx['schema_name'] == schema and 
                    idx['table_name'] == table and 
                    col_name in idx['index_definition']):
                    index_exists = True
                    break
            
            if not index_exists:
                # Calculate estimated improvement
                # In a real implementation, this would use more sophisticated estimation
                improvement = min(95, count * 5)  # Simple heuristic
                
                # Insert recommendation
                result = plpy.execute(f"""
                    INSERT INTO auto_tuning.index_recommendations (
                        schema_name, table_name, column_names, index_type,
                        estimated_improvement, creation_cost, maintenance_cost
                    ) VALUES (
                        '{schema}', '{table}', ARRAY['{col_name}'], 'btree',
                        {improvement}, 'Medium', 'Low'
                    ) RETURNING *
                """)
                
                # Yield the recommendation
                for r in result:
                    yield r

$$ LANGUAGE plpython3u;

-- Function to optimize a query
CREATE OR REPLACE FUNCTION auto_tuning.optimize_query(
    p_query TEXT
) RETURNS TEXT AS $$
import re

def optimize_query(query):
    # Convert to lowercase for easier processing
    query_lower = query.lower()
    optimized = query
    
    # Check for common optimization opportunities
    
    # 1. Replace SELECT * with specific columns
    if re.search(r'select\s+\*\s+from', query_lower):
        # In a real implementation, this would analyze the query execution plan
        # and determine which columns are actually needed
        return "-- Consider replacing SELECT * with specific columns needed"
    
    # 2. Check for missing WHERE clause
    if 'where' not in query_lower and ('select' in query_lower and 'from' in query_lower):
        return "-- Consider adding a WHERE clause to limit results"
    
    # 3. Check for LIKE with leading wildcard
    if re.search(r'like\s+[\'"]%', query_lower):
        return "-- LIKE with leading wildcard ('%...') prevents index usage"
    
    # 4. Check for functions on indexed columns
    function_pattern = r'(where|and|or)\s+\w+\(\s*(\w+)\s*\)'
    function_matches = re.findall(function_pattern, query_lower)
    if function_matches:
        return "-- Functions on columns in WHERE clause prevent index usage"
    
    # 5. Check for OR conditions that could use UNION
    if ' or ' in query_lower and ' where ' in query_lower:
        return "-- Consider replacing OR conditions with UNION for better index usage"
    
    # 6. Check for missing JOINs (implicit joins)
    if re.search(r'from\s+\w+\s*,\s*\w+', query_lower):
        return "-- Consider using explicit JOIN syntax instead of implicit joins"
    
    # 7. Check for missing ORDER BY with LIMIT
    if 'limit' in query_lower and 'order by' not in query_lower:
        return "-- Consider adding ORDER BY when using LIMIT for consistent results"
    
    # No obvious optimizations found
    return "-- No obvious optimizations identified"

return optimize_query(p_query)
$$ LANGUAGE plpython3u;

-- Function to recommend database parameter changes
CREATE OR REPLACE FUNCTION auto_tuning.recommend_parameters() RETURNS TABLE (
    parameter_name TEXT,
    current_value TEXT,
    recommended_value TEXT,
    reason TEXT
) AS $$
DECLARE
    v_total_memory_mb INTEGER;
    v_shared_buffers_current TEXT;
    v_work_mem_current TEXT;
    v_maintenance_work_mem_current TEXT;
    v_effective_cache_size_current TEXT;
    v_max_connections_current TEXT;
    v_shared_buffers_mb INTEGER;
    v_work_mem_mb INTEGER;
    v_maintenance_work_mem_mb INTEGER;
    v_effective_cache_size_mb INTEGER;
    v_max_connections INTEGER;
BEGIN
    -- Get total system memory (simplified - in a real implementation, this would use OS-level info)
    SELECT setting::INTEGER INTO v_total_memory_mb
    FROM pg_settings
    WHERE name = 'shared_buffers'
    LIMIT 1;
    
    -- Estimate total memory as 4x shared_buffers (very rough estimate)
    v_total_memory_mb := v_total_memory_mb * 4;
    
    -- Get current parameter values
    SELECT setting INTO v_shared_buffers_current FROM pg_settings WHERE name = 'shared_buffers';
    SELECT setting INTO v_work_mem_current FROM pg_settings WHERE name = 'work_mem';
    SELECT setting INTO v_maintenance_work_mem_current FROM pg_settings WHERE name = 'maintenance_work_mem';
    SELECT setting INTO v_effective_cache_size_current FROM pg_settings WHERE name = 'effective_cache_size';
    SELECT setting INTO v_max_connections_current FROM pg_settings WHERE name = 'max_connections';
    
    -- Convert to MB for easier calculation
    v_shared_buffers_mb := v_shared_buffers_current::INTEGER / 1024;
    v_work_mem_mb := v_work_mem_current::INTEGER / 1024;
    v_maintenance_work_mem_mb := v_maintenance_work_mem_current::INTEGER / 1024;
    v_effective_cache_size_mb := v_effective_cache_size_current::INTEGER / 1024;
    v_max_connections := v_max_connections_current::INTEGER;
    
    -- Check shared_buffers (should be ~25% of total memory)
    IF v_shared_buffers_mb < v_total_memory_mb * 0.25 THEN
        parameter_name := 'shared_buffers';
        current_value := v_shared_buffers_current;
        recommended_value := (v_total_memory_mb * 0.25)::INTEGER || 'MB';
        reason := 'Increase to 25% of total memory for better caching';
        RETURN NEXT;
    END IF;
    
    -- Check work_mem (depends on max_connections and query complexity)
    IF v_work_mem_mb < 4 THEN
        parameter_name := 'work_mem';
        current_value := v_work_mem_current;
        recommended_value := '4MB';
        reason := 'Increase for better query performance, especially for sorts and hashes';
        RETURN NEXT;
    END IF;
    
    -- Check maintenance_work_mem
    IF v_maintenance_work_mem_mb < 64 THEN
        parameter_name := 'maintenance_work_mem';
        current_value := v_maintenance_work_mem_current;
        recommended_value := '64MB';
        reason := 'Increase for faster vacuum, index, and foreign key operations';
        RETURN NEXT;
    END IF;
    
    -- Check effective_cache_size (should be ~75% of total memory)
    IF v_effective_cache_size_mb < v_total_memory_mb * 0.75 THEN
        parameter_name := 'effective_cache_size';
        current_value := v_effective_cache_size_current;
        recommended_value := (v_total_memory_mb * 0.75)::INTEGER || 'MB';
        reason := 'Increase to 75% of total memory for better query planning';
        RETURN NEXT;
    END IF;
    
    -- Check max_connections based on workload
    -- In a real implementation, this would analyze connection usage patterns
    IF v_max_connections > 100 AND v_work_mem_mb < 4 THEN
        parameter_name := 'max_connections';
        current_value := v_max_connections_current;
        recommended_value := '100';
        reason := 'Reduce to allow for higher work_mem per connection';
        RETURN NEXT;
    END IF;
    
    RETURN;
END;
$$ LANGUAGE plpgsql;

-- Function to implement an index recommendation
CREATE OR REPLACE FUNCTION auto_tuning.implement_index_recommendation(
    p_recommendation_id INTEGER
) RETURNS TEXT AS $$
DECLARE
    v_rec RECORD;
    v_index_name TEXT;
    v_sql TEXT;
BEGIN
    -- Get recommendation
    SELECT * INTO v_rec
    FROM auto_tuning.index_recommendations
    WHERE id = p_recommendation_id;
    
    IF v_rec IS NULL THEN
        RAISE EXCEPTION 'Index recommendation with ID % not found', p_recommendation_id;
    END IF;
    
    IF v_rec.implemented THEN
        RETURN 'Index already implemented';
    END IF;
    
    -- Generate index name
    v_index_name := format(
        'idx_%s_%s',
        v_rec.table_name,
        array_to_string(v_rec.column_names, '_')
    );
    
    -- Create index concurrently to avoid blocking operations
    v_sql := format(
        'CREATE INDEX CONCURRENTLY %I ON %I.%I USING %s (%s)',
        v_index_name,
        v_rec.schema_name,
        v_rec.table_name,
        v_rec.index_type,
        array_to_string(v_rec.column_names, ', ')
    );
    
    -- Execute SQL
    EXECUTE v_sql;
    
    -- Update recommendation
    UPDATE auto_tuning.index_recommendations
    SET implemented = TRUE,
        implemented_at = NOW()
    WHERE id = p_recommendation_id;
    
    -- Log index creation
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'AUTO_INDEX_CREATED', 'INFO', current_user, 
        format('Created index %I on %I.%I(%s) based on recommendation %s',
               v_index_name, v_rec.schema_name, v_rec.table_name, 
               array_to_string(v_rec.column_names, ', '), p_recommendation_id)
    );
    
    RETURN v_sql;
END;
$$ LANGUAGE plpgsql;

-- Function to apply a parameter recommendation
CREATE OR REPLACE FUNCTION auto_tuning.apply_parameter_recommendation(
    p_parameter_name TEXT,
    p_new_value TEXT
) RETURNS BOOLEAN AS $$
DECLARE
    v_old_value TEXT;
    v_sql TEXT;
BEGIN
    -- Get current value
    SELECT setting INTO v_old_value
    FROM pg_settings
    WHERE name = p_parameter_name;
    
    -- Apply new value
    v_sql := format('ALTER SYSTEM SET %I = %L', p_parameter_name, p_new_value);
    EXECUTE v_sql;
    
    -- Reload configuration
    PERFORM pg_reload_conf();
    
    -- Record change
    INSERT INTO auto_tuning.parameter_history (
        parameter_name, old_value, new_value, reason
    ) VALUES (
        p_parameter_name, v_old_value, p_new_value, 'Auto-tuning recommendation'
    );
    
    -- Log parameter change
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'AUTO_PARAMETER_CHANGED', 'INFO', current_user, 
        format('Changed parameter %s from %s to %s',
               p_parameter_name, v_old_value, p_new_value)
    );
    
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- Grant permissions
GRANT USAGE ON SCHEMA auto_tuning TO security_admin;
GRANT SELECT ON ALL TABLES IN SCHEMA auto_tuning TO security_admin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA auto_tuning TO security_admin;
