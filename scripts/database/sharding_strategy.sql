-- Sharding Strategy for PostgreSQL Security Framework
CREATE SCHEMA IF NOT EXISTS sharding;

-- Function to create sharded tables
CREATE OR REPLACE FUNCTION sharding.create_sharded_table(
    p_base_table TEXT,
    p_schema TEXT DEFAULT 'public',
    p_shard_key TEXT,
    p_shard_count INTEGER DEFAULT 16
) RETURNS VOID AS $$
DECLARE
    v_sql TEXT;
    i INTEGER;
BEGIN
    -- Create parent table
    v_sql := format('
        CREATE TABLE IF NOT EXISTS %I.%I (
            %s_shard_id INTEGER NOT NULL,
            CHECK (%s_shard_id >= 0 AND %s_shard_id < %s)
        ) PARTITION BY LIST (%s_shard_id)
    ', p_schema, p_base_table, p_shard_key, p_shard_key, p_shard_key, p_shard_count, p_shard_key);

    EXECUTE v_sql;

    -- Create shards
    FOR i IN 0..(p_shard_count-1) LOOP
        v_sql := format('
            CREATE TABLE IF NOT EXISTS %I.%I_%s PARTITION OF %I.%I
            FOR VALUES IN (%s)
        ', p_schema, p_base_table, i, p_schema, p_base_table, i);

        EXECUTE v_sql;
    END LOOP;

    -- Create shard routing function
    v_sql := format('
        CREATE OR REPLACE FUNCTION %I.%I_shard_id(%s %s)
        RETURNS INTEGER AS $FUNC$
        BEGIN
            RETURN abs(hashtext(%L::text)) %% %s;
        END;
        $FUNC$ LANGUAGE plpgsql IMMUTABLE
    ', p_schema, p_base_table, p_shard_key, 'TEXT', p_shard_key, p_shard_count);

    EXECUTE v_sql;

    -- Create insert function
    v_sql := format('
        CREATE OR REPLACE FUNCTION %I.insert_%I(
            %s %s,
            OUT shard_id INTEGER
        ) RETURNS INTEGER AS $FUNC$
        DECLARE
            v_shard_id INTEGER;
        BEGIN
            -- Calculate shard ID
            v_shard_id := %I.%I_shard_id(%s);

            -- Set output parameter
            shard_id := v_shard_id;

            -- Insert with shard ID
            EXECUTE format(''INSERT INTO %I.%I (%s_shard_id, %s) VALUES ($1, $2)'')
            USING v_shard_id, %s;

            RETURN;
        END;
        $FUNC$ LANGUAGE plpgsql
    ', p_schema, p_base_table, p_shard_key, 'TEXT',
       p_schema, p_base_table, p_shard_key,
       p_schema, p_base_table, p_shard_key, p_shard_key,
       p_shard_key);

    EXECUTE v_sql;

    -- Log sharded table creation
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'SHARDED_TABLE_CREATED', 'INFO', current_user,
        format('Created sharded table %I.%I with %s shards',
               p_schema, p_base_table, p_shard_count)
    );
END;
$$ LANGUAGE plpgsql;

-- Function to add a column to a sharded table
CREATE OR REPLACE FUNCTION sharding.add_column_to_sharded_table(
    p_base_table TEXT,
    p_schema TEXT DEFAULT 'public',
    p_column_name TEXT,
    p_column_type TEXT,
    p_column_constraint TEXT DEFAULT NULL
) RETURNS VOID AS $$
DECLARE
    v_sql TEXT;
BEGIN
    -- Add column to parent table
    v_sql := format('
        ALTER TABLE %I.%I ADD COLUMN %I %s %s
    ', p_schema, p_base_table, p_column_name, p_column_type,
       COALESCE(p_column_constraint, ''));

    EXECUTE v_sql;

    -- Log column addition
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'SHARDED_TABLE_MODIFIED', 'INFO', current_user,
        format('Added column %I to sharded table %I.%I',
               p_column_name, p_schema, p_base_table)
    );
END;
$$ LANGUAGE plpgsql;

-- Function to query across shards
CREATE OR REPLACE FUNCTION sharding.query_shards(
    p_base_table TEXT,
    p_schema TEXT DEFAULT 'public',
    p_where_clause TEXT DEFAULT NULL,
    p_order_by TEXT DEFAULT NULL,
    p_limit INTEGER DEFAULT NULL
) RETURNS SETOF RECORD AS $$
DECLARE
    v_sql TEXT;
BEGIN
    -- Build query
    v_sql := format('SELECT * FROM %I.%I', p_schema, p_base_table);

    IF p_where_clause IS NOT NULL THEN
        v_sql := v_sql || ' WHERE ' || p_where_clause;
    END IF;

    IF p_order_by IS NOT NULL THEN
        v_sql := v_sql || ' ORDER BY ' || p_order_by;
    END IF;

    IF p_limit IS NOT NULL THEN
        v_sql := v_sql || ' LIMIT ' || p_limit;
    END IF;

    -- Execute query
    RETURN QUERY EXECUTE v_sql;
END;
$$ LANGUAGE plpgsql;

-- Function to get shard distribution statistics
CREATE OR REPLACE FUNCTION sharding.get_shard_stats(
    p_base_table TEXT,
    p_schema TEXT DEFAULT 'public'
) RETURNS TABLE (
    shard_id INTEGER,
    row_count BIGINT,
    percent_of_total NUMERIC(5,2)
) AS $$
DECLARE
    v_total_rows BIGINT := 0;
    v_sql TEXT;
    v_shard_count INTEGER;
BEGIN
    -- Get shard count
    EXECUTE format('
        SELECT count(*) FROM pg_inherits i
        JOIN pg_class c ON i.inhrelid = c.oid
        JOIN pg_namespace n ON c.relnamespace = n.oid
        WHERE n.nspname = %L AND c.relname LIKE %L
    ', p_schema, p_base_table || '_%') INTO v_shard_count;

    -- Get total rows
    EXECUTE format('
        SELECT count(*) FROM %I.%I
    ', p_schema, p_base_table) INTO v_total_rows;

    -- Return stats for each shard
    FOR shard_id IN 0..(v_shard_count-1) LOOP
        EXECUTE format('
            SELECT count(*) FROM %I.%I_%s
        ', p_schema, p_base_table, shard_id) INTO row_count;

        percent_of_total := CASE
            WHEN v_total_rows > 0 THEN
                ROUND((row_count::NUMERIC / v_total_rows) * 100, 2)
            ELSE 0
        END;

        RETURN NEXT;
    END LOOP;

    RETURN;
END;
$$ LANGUAGE plpgsql;

-- Function to rebalance shards
CREATE OR REPLACE FUNCTION sharding.rebalance_shards(
    p_base_table TEXT,
    p_schema TEXT DEFAULT 'public',
    p_target_variance NUMERIC DEFAULT 10.0  -- Maximum allowed variance in percent
) RETURNS TABLE (
    shard_id INTEGER,
    rows_moved INTEGER,
    new_row_count BIGINT
) AS $$
DECLARE
    v_stats RECORD;
    v_avg_rows_per_shard NUMERIC;
    v_source_shard INTEGER;
    v_target_shard INTEGER;
    v_rows_to_move INTEGER;
    v_shard_key TEXT;
    v_sql TEXT;
    v_rows_moved INTEGER;
BEGIN
    -- Get shard key
    EXECUTE format('
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = %L
          AND table_name = %L
          AND column_name LIKE ''%%_shard_id''
    ', p_schema, p_base_table) INTO v_shard_key;

    IF v_shard_key IS NULL THEN
        RAISE EXCEPTION 'Could not determine shard key for table %', p_base_table;
    END IF;

    -- Calculate average rows per shard
    SELECT avg(row_count) INTO v_avg_rows_per_shard
    FROM sharding.get_shard_stats(p_base_table, p_schema);

    -- Find overloaded and underloaded shards
    FOR v_stats IN
        SELECT shard_id, row_count, percent_of_total
        FROM sharding.get_shard_stats(p_base_table, p_schema)
        WHERE ABS(row_count - v_avg_rows_per_shard) / v_avg_rows_per_shard * 100 > p_target_variance
        ORDER BY row_count DESC
    LOOP
        IF v_stats.row_count > v_avg_rows_per_shard THEN
            -- This is an overloaded shard
            v_source_shard := v_stats.shard_id;

            -- Find an underloaded shard
            SELECT shard_id INTO v_target_shard
            FROM sharding.get_shard_stats(p_base_table, p_schema)
            WHERE row_count < v_avg_rows_per_shard
            ORDER BY row_count ASC
            LIMIT 1;

            IF v_target_shard IS NOT NULL THEN
                -- Calculate how many rows to move
                v_rows_to_move := CEIL((v_stats.row_count - v_avg_rows_per_shard) / 2);

                -- Move rows from source to target shard
                v_sql := format('
                    WITH rows_to_move AS (
                        SELECT * FROM %I.%I_%s
                        LIMIT %s
                    )
                    INSERT INTO %I.%I_%s
                    SELECT * FROM rows_to_move
                    RETURNING 1
                ', p_schema, p_base_table, v_source_shard, v_rows_to_move,
                   p_schema, p_base_table, v_target_shard);

                EXECUTE v_sql;
                GET DIAGNOSTICS v_rows_moved = ROW_COUNT;

                -- Delete moved rows from source shard
                v_sql := format('
                    DELETE FROM %I.%I_%s
                    WHERE ctid IN (
                        SELECT ctid FROM %I.%I_%s
                        LIMIT %s
                    )
                ', p_schema, p_base_table, v_source_shard,
                   p_schema, p_base_table, v_source_shard, v_rows_to_move);

                EXECUTE v_sql;

                -- Return results
                shard_id := v_source_shard;
                rows_moved := v_rows_moved;

                -- Get new row count
                EXECUTE format('
                    SELECT count(*) FROM %I.%I_%s
                ', p_schema, p_base_table, v_source_shard) INTO new_row_count;

                RETURN NEXT;

                -- Also return target shard info
                shard_id := v_target_shard;
                rows_moved := v_rows_moved;

                -- Get new row count
                EXECUTE format('
                    SELECT count(*) FROM %I.%I_%s
                ', p_schema, p_base_table, v_target_shard) INTO new_row_count;

                RETURN NEXT;
            END IF;
        END IF;
    END LOOP;

    RETURN;
END;
$$ LANGUAGE plpgsql;

-- Function to create a global index on a sharded table
CREATE OR REPLACE FUNCTION sharding.create_global_index(
    p_base_table TEXT,
    p_schema TEXT DEFAULT 'public',
    p_column_name TEXT,
    p_index_type TEXT DEFAULT 'btree'
) RETURNS VOID AS $$
DECLARE
    v_sql TEXT;
    v_index_name TEXT;
    i INTEGER;
    v_shard_count INTEGER;
BEGIN
    -- Get shard count
    EXECUTE format('
        SELECT count(*) FROM pg_inherits i
        JOIN pg_class c ON i.inhrelid = c.oid
        JOIN pg_namespace n ON c.relnamespace = n.oid
        WHERE n.nspname = %L AND c.relname LIKE %L
    ', p_schema, p_base_table || '_%') INTO v_shard_count;

    -- Create index on each shard
    FOR i IN 0..(v_shard_count-1) LOOP
        v_index_name := format('%s_%s_%s_idx', p_base_table, i, p_column_name);

        v_sql := format('
            CREATE INDEX IF NOT EXISTS %I ON %I.%I_%s USING %s (%I)
        ', v_index_name, p_schema, p_base_table, i, p_index_type, p_column_name);

        EXECUTE v_sql;
    END LOOP;

    -- Log index creation
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'GLOBAL_INDEX_CREATED', 'INFO', current_user,
        format('Created global %s index on %I.%I(%I)',
               p_index_type, p_schema, p_base_table, p_column_name)
    );
END;
$$ LANGUAGE plpgsql;

-- Grant permissions
GRANT USAGE ON SCHEMA sharding TO app_user, security_admin;
GRANT EXECUTE ON FUNCTION sharding.create_sharded_table TO security_admin;
GRANT EXECUTE ON FUNCTION sharding.add_column_to_sharded_table TO security_admin;
GRANT EXECUTE ON FUNCTION sharding.query_shards TO app_user, security_admin;
GRANT EXECUTE ON FUNCTION sharding.get_shard_stats TO app_user, security_admin;
GRANT EXECUTE ON FUNCTION sharding.rebalance_shards TO security_admin;
GRANT EXECUTE ON FUNCTION sharding.create_global_index TO security_admin;
