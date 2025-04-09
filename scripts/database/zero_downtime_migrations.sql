-- Zero-Downtime Schema Migration Framework for PostgreSQL Security Framework
CREATE SCHEMA IF NOT EXISTS schema_migrations;

-- Table to track migrations
CREATE TABLE IF NOT EXISTS schema_migrations.migrations (
    id SERIAL PRIMARY KEY,
    version TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    applied_by TEXT NOT NULL,
    execution_time_ms INTEGER,
    is_rollback BOOLEAN NOT NULL DEFAULT FALSE,
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed', 'rolled_back'))
);

-- Table to track individual migration steps
CREATE TABLE IF NOT EXISTS schema_migrations.steps (
    id SERIAL PRIMARY KEY,
    migration_id INTEGER REFERENCES schema_migrations.migrations(id),
    step_number INTEGER NOT NULL,
    operation TEXT NOT NULL,
    sql_up TEXT NOT NULL,
    sql_down TEXT NOT NULL,
    is_online BOOLEAN NOT NULL DEFAULT TRUE,
    estimated_duration_ms INTEGER,
    actual_duration_ms INTEGER,
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed', 'rolled_back'))
);

-- Table to track locks during migrations
CREATE TABLE IF NOT EXISTS schema_migrations.locks (
    id SERIAL PRIMARY KEY,
    migration_id INTEGER REFERENCES schema_migrations.migrations(id),
    lock_id TEXT NOT NULL UNIQUE,
    acquired_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    released_at TIMESTAMPTZ,
    status TEXT NOT NULL CHECK (status IN ('acquired', 'released', 'failed'))
);

-- Table to track migration dependencies
CREATE TABLE IF NOT EXISTS schema_migrations.dependencies (
    id SERIAL PRIMARY KEY,
    migration_id INTEGER REFERENCES schema_migrations.migrations(id),
    depends_on TEXT NOT NULL,
    is_required BOOLEAN NOT NULL DEFAULT TRUE
);

-- Function to register a new migration
CREATE OR REPLACE FUNCTION schema_migrations.register_migration(
    p_version TEXT,
    p_description TEXT,
    p_dependencies TEXT[] DEFAULT NULL
) RETURNS INTEGER AS $$
DECLARE
    v_migration_id INTEGER;
BEGIN
    -- Insert migration record
    INSERT INTO schema_migrations.migrations (
        version, description, applied_by, status
    ) VALUES (
        p_version, p_description, current_user, 'pending'
    ) RETURNING id INTO v_migration_id;
    
    -- Register dependencies if provided
    IF p_dependencies IS NOT NULL THEN
        FOREACH v_dependency IN ARRAY p_dependencies LOOP
            INSERT INTO schema_migrations.dependencies (
                migration_id, depends_on
            ) VALUES (
                v_migration_id, v_dependency
            );
        END LOOP;
    END IF;
    
    -- Log migration registration
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'MIGRATION_REGISTERED', 'INFO', current_user, 
        format('Registered migration %s: %s', p_version, p_description)
    );
    
    RETURN v_migration_id;
END;
$$ LANGUAGE plpgsql;

-- Function to add a migration step
CREATE OR REPLACE FUNCTION schema_migrations.add_step(
    p_migration_id INTEGER,
    p_step_number INTEGER,
    p_operation TEXT,
    p_sql_up TEXT,
    p_sql_down TEXT,
    p_is_online BOOLEAN DEFAULT TRUE,
    p_estimated_duration_ms INTEGER DEFAULT NULL
) RETURNS INTEGER AS $$
DECLARE
    v_step_id INTEGER;
BEGIN
    -- Insert step record
    INSERT INTO schema_migrations.steps (
        migration_id, step_number, operation, sql_up, sql_down, 
        is_online, estimated_duration_ms, status
    ) VALUES (
        p_migration_id, p_step_number, p_operation, p_sql_up, p_sql_down, 
        p_is_online, p_estimated_duration_ms, 'pending'
    ) RETURNING id INTO v_step_id;
    
    RETURN v_step_id;
END;
$$ LANGUAGE plpgsql;

-- Function to check if a migration can be executed
CREATE OR REPLACE FUNCTION schema_migrations.can_execute_migration(
    p_migration_id INTEGER
) RETURNS BOOLEAN AS $$
DECLARE
    v_can_execute BOOLEAN := TRUE;
    v_dependency RECORD;
    v_migration_status TEXT;
BEGIN
    -- Check if migration exists and is in pending status
    SELECT status INTO v_migration_status
    FROM schema_migrations.migrations
    WHERE id = p_migration_id;
    
    IF v_migration_status IS NULL THEN
        RAISE EXCEPTION 'Migration with ID % does not exist', p_migration_id;
    ELSIF v_migration_status <> 'pending' THEN
        RAISE EXCEPTION 'Migration with ID % is not in pending status (current status: %)', 
                        p_migration_id, v_migration_status;
    END IF;
    
    -- Check dependencies
    FOR v_dependency IN
        SELECT d.depends_on, m.status
        FROM schema_migrations.dependencies d
        LEFT JOIN schema_migrations.migrations m ON m.version = d.depends_on
        WHERE d.migration_id = p_migration_id AND d.is_required = TRUE
    LOOP
        IF v_dependency.status IS NULL THEN
            RAISE EXCEPTION 'Required dependency % not found', v_dependency.depends_on;
            v_can_execute := FALSE;
        ELSIF v_dependency.status <> 'completed' THEN
            RAISE EXCEPTION 'Required dependency % is not completed (status: %)', 
                            v_dependency.depends_on, v_dependency.status;
            v_can_execute := FALSE;
        END IF;
    END LOOP;
    
    RETURN v_can_execute;
END;
$$ LANGUAGE plpgsql;

-- Function to acquire a migration lock
CREATE OR REPLACE FUNCTION schema_migrations.acquire_lock(
    p_migration_id INTEGER
) RETURNS TEXT AS $$
DECLARE
    v_lock_id TEXT;
    v_acquired BOOLEAN;
BEGIN
    -- Generate lock ID
    v_lock_id := 'migration_' || p_migration_id || '_' || gen_random_uuid();
    
    -- Try to acquire advisory lock
    SELECT pg_try_advisory_lock(p_migration_id) INTO v_acquired;
    
    IF NOT v_acquired THEN
        RAISE EXCEPTION 'Could not acquire lock for migration %', p_migration_id;
    END IF;
    
    -- Record lock acquisition
    INSERT INTO schema_migrations.locks (
        migration_id, lock_id, status
    ) VALUES (
        p_migration_id, v_lock_id, 'acquired'
    );
    
    -- Log lock acquisition
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'MIGRATION_LOCK_ACQUIRED', 'INFO', current_user, 
        format('Acquired lock %s for migration %s', v_lock_id, p_migration_id)
    );
    
    RETURN v_lock_id;
END;
$$ LANGUAGE plpgsql;

-- Function to release a migration lock
CREATE OR REPLACE FUNCTION schema_migrations.release_lock(
    p_lock_id TEXT
) RETURNS VOID AS $$
DECLARE
    v_migration_id INTEGER;
BEGIN
    -- Get migration ID from lock
    SELECT migration_id INTO v_migration_id
    FROM schema_migrations.locks
    WHERE lock_id = p_lock_id AND status = 'acquired';
    
    IF v_migration_id IS NULL THEN
        RAISE EXCEPTION 'Lock % not found or not acquired', p_lock_id;
    END IF;
    
    -- Release advisory lock
    PERFORM pg_advisory_unlock(v_migration_id);
    
    -- Update lock status
    UPDATE schema_migrations.locks
    SET status = 'released',
        released_at = NOW()
    WHERE lock_id = p_lock_id;
    
    -- Log lock release
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'MIGRATION_LOCK_RELEASED', 'INFO', current_user, 
        format('Released lock %s for migration %s', p_lock_id, v_migration_id)
    );
END;
$$ LANGUAGE plpgsql;

-- Function to execute a migration
CREATE OR REPLACE FUNCTION schema_migrations.execute_migration(
    p_migration_id INTEGER
) RETURNS BOOLEAN AS $$
DECLARE
    v_lock_id TEXT;
    v_step RECORD;
    v_start_time TIMESTAMPTZ;
    v_end_time TIMESTAMPTZ;
    v_execution_time_ms INTEGER;
    v_success BOOLEAN := TRUE;
BEGIN
    -- Check if migration can be executed
    IF NOT schema_migrations.can_execute_migration(p_migration_id) THEN
        RETURN FALSE;
    END IF;
    
    -- Acquire lock
    v_lock_id := schema_migrations.acquire_lock(p_migration_id);
    
    -- Update migration status
    UPDATE schema_migrations.migrations
    SET status = 'running'
    WHERE id = p_migration_id;
    
    -- Record start time
    v_start_time := NOW();
    
    -- Execute each step
    BEGIN
        FOR v_step IN
            SELECT * FROM schema_migrations.steps
            WHERE migration_id = p_migration_id
            ORDER BY step_number
        LOOP
            -- Update step status
            UPDATE schema_migrations.steps
            SET status = 'running'
            WHERE id = v_step.id;
            
            -- Execute step
            BEGIN
                EXECUTE v_step.sql_up;
                
                -- Update step status
                UPDATE schema_migrations.steps
                SET status = 'completed',
                    actual_duration_ms = EXTRACT(EPOCH FROM (NOW() - v_start_time)) * 1000
                WHERE id = v_step.id;
            EXCEPTION
                WHEN OTHERS THEN
                    -- Update step status
                    UPDATE schema_migrations.steps
                    SET status = 'failed'
                    WHERE id = v_step.id;
                    
                    -- Log error
                    INSERT INTO logs.notification_log (
                        event_type, severity, username, message
                    ) VALUES (
                        'MIGRATION_STEP_FAILED', 'ERROR', current_user, 
                        format('Migration step %s failed: %s', v_step.id, SQLERRM)
                    );
                    
                    v_success := FALSE;
                    RAISE;
            END;
        END LOOP;
        
        -- Record end time
        v_end_time := NOW();
        v_execution_time_ms := EXTRACT(EPOCH FROM (v_end_time - v_start_time)) * 1000;
        
        -- Update migration status
        UPDATE schema_migrations.migrations
        SET status = 'completed',
            execution_time_ms = v_execution_time_ms
        WHERE id = p_migration_id;
        
        -- Log successful migration
        INSERT INTO logs.notification_log (
            event_type, severity, username, message
        ) VALUES (
            'MIGRATION_COMPLETED', 'INFO', current_user, 
            format('Migration %s completed successfully in %s ms', p_migration_id, v_execution_time_ms)
        );
    EXCEPTION
        WHEN OTHERS THEN
            -- Update migration status
            UPDATE schema_migrations.migrations
            SET status = 'failed'
            WHERE id = p_migration_id;
            
            -- Log failed migration
            INSERT INTO logs.notification_log (
                event_type, severity, username, message
            ) VALUES (
                'MIGRATION_FAILED', 'ERROR', current_user, 
                format('Migration %s failed: %s', p_migration_id, SQLERRM)
            );
            
            v_success := FALSE;
    END;
    
    -- Release lock
    PERFORM schema_migrations.release_lock(v_lock_id);
    
    RETURN v_success;
END;
$$ LANGUAGE plpgsql;

-- Function to rollback a migration
CREATE OR REPLACE FUNCTION schema_migrations.rollback_migration(
    p_migration_id INTEGER
) RETURNS BOOLEAN AS $$
DECLARE
    v_lock_id TEXT;
    v_step RECORD;
    v_start_time TIMESTAMPTZ;
    v_end_time TIMESTAMPTZ;
    v_execution_time_ms INTEGER;
    v_success BOOLEAN := TRUE;
    v_migration_status TEXT;
BEGIN
    -- Check migration status
    SELECT status INTO v_migration_status
    FROM schema_migrations.migrations
    WHERE id = p_migration_id;
    
    IF v_migration_status IS NULL THEN
        RAISE EXCEPTION 'Migration with ID % does not exist', p_migration_id;
    ELSIF v_migration_status NOT IN ('completed', 'failed') THEN
        RAISE EXCEPTION 'Migration with ID % cannot be rolled back (status: %)', 
                        p_migration_id, v_migration_status;
    END IF;
    
    -- Acquire lock
    v_lock_id := schema_migrations.acquire_lock(p_migration_id);
    
    -- Update migration status
    UPDATE schema_migrations.migrations
    SET status = 'running',
        is_rollback = TRUE
    WHERE id = p_migration_id;
    
    -- Record start time
    v_start_time := NOW();
    
    -- Execute each step in reverse order
    BEGIN
        FOR v_step IN
            SELECT * FROM schema_migrations.steps
            WHERE migration_id = p_migration_id
            ORDER BY step_number DESC
        LOOP
            -- Skip steps that were not completed
            IF v_step.status <> 'completed' THEN
                CONTINUE;
            END IF;
            
            -- Update step status
            UPDATE schema_migrations.steps
            SET status = 'running'
            WHERE id = v_step.id;
            
            -- Execute rollback
            BEGIN
                EXECUTE v_step.sql_down;
                
                -- Update step status
                UPDATE schema_migrations.steps
                SET status = 'rolled_back'
                WHERE id = v_step.id;
            EXCEPTION
                WHEN OTHERS THEN
                    -- Update step status
                    UPDATE schema_migrations.steps
                    SET status = 'failed'
                    WHERE id = v_step.id;
                    
                    -- Log error
                    INSERT INTO logs.notification_log (
                        event_type, severity, username, message
                    ) VALUES (
                        'MIGRATION_ROLLBACK_STEP_FAILED', 'ERROR', current_user, 
                        format('Migration rollback step %s failed: %s', v_step.id, SQLERRM)
                    );
                    
                    v_success := FALSE;
                    RAISE;
            END;
        END LOOP;
        
        -- Record end time
        v_end_time := NOW();
        v_execution_time_ms := EXTRACT(EPOCH FROM (v_end_time - v_start_time)) * 1000;
        
        -- Update migration status
        UPDATE schema_migrations.migrations
        SET status = 'rolled_back',
            execution_time_ms = v_execution_time_ms
        WHERE id = p_migration_id;
        
        -- Log successful rollback
        INSERT INTO logs.notification_log (
            event_type, severity, username, message
        ) VALUES (
            'MIGRATION_ROLLED_BACK', 'INFO', current_user, 
            format('Migration %s rolled back successfully in %s ms', p_migration_id, v_execution_time_ms)
        );
    EXCEPTION
        WHEN OTHERS THEN
            -- Update migration status
            UPDATE schema_migrations.migrations
            SET status = 'failed'
            WHERE id = p_migration_id;
            
            -- Log failed rollback
            INSERT INTO logs.notification_log (
                event_type, severity, username, message
            ) VALUES (
                'MIGRATION_ROLLBACK_FAILED', 'ERROR', current_user, 
                format('Migration rollback %s failed: %s', p_migration_id, SQLERRM)
            );
            
            v_success := FALSE;
    END;
    
    -- Release lock
    PERFORM schema_migrations.release_lock(v_lock_id);
    
    RETURN v_success;
END;
$$ LANGUAGE plpgsql;

-- Function to generate online ALTER TABLE statement
CREATE OR REPLACE FUNCTION schema_migrations.generate_online_alter_table(
    p_schema_name TEXT,
    p_table_name TEXT,
    p_alter_statement TEXT
) RETURNS TEXT AS $$
DECLARE
    v_sql TEXT;
BEGIN
    -- Check if pg_background extension is available
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_background') THEN
        -- Use pg_background for non-blocking operation
        v_sql := format('SELECT pg_background_result(pg_background_launch($$ ALTER TABLE %I.%I %s $$))',
                        p_schema_name, p_table_name, p_alter_statement);
    ELSE
        -- Use regular ALTER TABLE with timeout to avoid long locks
        v_sql := format('SET LOCAL statement_timeout = ''30s''; ALTER TABLE %I.%I %s',
                        p_schema_name, p_table_name, p_alter_statement);
    END IF;
    
    RETURN v_sql;
END;
$$ LANGUAGE plpgsql;

-- Function to generate online index creation
CREATE OR REPLACE FUNCTION schema_migrations.generate_online_index_creation(
    p_schema_name TEXT,
    p_table_name TEXT,
    p_index_name TEXT,
    p_index_columns TEXT,
    p_index_type TEXT DEFAULT NULL,
    p_index_predicate TEXT DEFAULT NULL
) RETURNS TEXT AS $$
DECLARE
    v_sql TEXT;
BEGIN
    -- Build CREATE INDEX statement with CONCURRENTLY option
    v_sql := format('CREATE INDEX CONCURRENTLY IF NOT EXISTS %I ON %I.%I',
                    p_index_name, p_schema_name, p_table_name);
    
    -- Add index type if specified
    IF p_index_type IS NOT NULL THEN
        v_sql := v_sql || format(' USING %s', p_index_type);
    END IF;
    
    -- Add index columns
    v_sql := v_sql || format(' (%s)', p_index_columns);
    
    -- Add index predicate if specified
    IF p_index_predicate IS NOT NULL THEN
        v_sql := v_sql || format(' WHERE %s', p_index_predicate);
    END IF;
    
    RETURN v_sql;
END;
$$ LANGUAGE plpgsql;

-- Function to generate online column addition
CREATE OR REPLACE FUNCTION schema_migrations.generate_online_add_column(
    p_schema_name TEXT,
    p_table_name TEXT,
    p_column_name TEXT,
    p_column_type TEXT,
    p_column_constraint TEXT DEFAULT NULL
) RETURNS TEXT AS $$
DECLARE
    v_sql TEXT;
BEGIN
    -- Build ADD COLUMN statement
    v_sql := format('ADD COLUMN IF NOT EXISTS %I %s',
                    p_column_name, p_column_type);
    
    -- Add column constraint if specified
    IF p_column_constraint IS NOT NULL THEN
        v_sql := v_sql || format(' %s', p_column_constraint);
    END IF;
    
    -- Use the online alter table function
    RETURN schema_migrations.generate_online_alter_table(
        p_schema_name, p_table_name, v_sql
    );
END;
$$ LANGUAGE plpgsql;

-- Function to generate online column drop
CREATE OR REPLACE FUNCTION schema_migrations.generate_online_drop_column(
    p_schema_name TEXT,
    p_table_name TEXT,
    p_column_name TEXT
) RETURNS TEXT AS $$
BEGIN
    -- Use the online alter table function
    RETURN schema_migrations.generate_online_alter_table(
        p_schema_name, p_table_name, 
        format('DROP COLUMN IF EXISTS %I', p_column_name)
    );
END;
$$ LANGUAGE plpgsql;

-- Function to get migration status
CREATE OR REPLACE FUNCTION schema_migrations.get_migration_status(
    p_version TEXT DEFAULT NULL
) RETURNS TABLE (
    id INTEGER,
    version TEXT,
    description TEXT,
    status TEXT,
    applied_at TIMESTAMPTZ,
    applied_by TEXT,
    execution_time_ms INTEGER,
    is_rollback BOOLEAN
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        m.id,
        m.version,
        m.description,
        m.status,
        m.applied_at,
        m.applied_by,
        m.execution_time_ms,
        m.is_rollback
    FROM schema_migrations.migrations m
    WHERE p_version IS NULL OR m.version = p_version
    ORDER BY m.applied_at DESC;
END;
$$ LANGUAGE plpgsql;

-- Function to get migration steps
CREATE OR REPLACE FUNCTION schema_migrations.get_migration_steps(
    p_migration_id INTEGER
) RETURNS TABLE (
    step_id INTEGER,
    step_number INTEGER,
    operation TEXT,
    sql_up TEXT,
    sql_down TEXT,
    is_online BOOLEAN,
    status TEXT,
    estimated_duration_ms INTEGER,
    actual_duration_ms INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        s.id,
        s.step_number,
        s.operation,
        s.sql_up,
        s.sql_down,
        s.is_online,
        s.status,
        s.estimated_duration_ms,
        s.actual_duration_ms
    FROM schema_migrations.steps s
    WHERE s.migration_id = p_migration_id
    ORDER BY s.step_number;
END;
$$ LANGUAGE plpgsql;

-- Grant permissions
GRANT USAGE ON SCHEMA schema_migrations TO security_admin;
GRANT SELECT ON ALL TABLES IN SCHEMA schema_migrations TO security_admin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA schema_migrations TO security_admin;

-- Example usage:
/*
-- Register a new migration
SELECT schema_migrations.register_migration(
    '20230501000001',
    'Add email verification to users table'
);

-- Add migration steps
SELECT schema_migrations.add_step(
    1,  -- migration_id
    1,  -- step_number
    'Add column',
    schema_migrations.generate_online_add_column(
        'public', 'users', 'email_verified', 'boolean', 'DEFAULT false NOT NULL'
    ),
    'ALTER TABLE public.users DROP COLUMN IF EXISTS email_verified',
    TRUE,  -- is_online
    5000   -- estimated_duration_ms
);

SELECT schema_migrations.add_step(
    1,  -- migration_id
    2,  -- step_number
    'Add index',
    schema_migrations.generate_online_index_creation(
        'public', 'users', 'idx_users_email_verified', 'email_verified'
    ),
    'DROP INDEX IF EXISTS public.idx_users_email_verified',
    TRUE,  -- is_online
    10000  -- estimated_duration_ms
);

-- Execute the migration
SELECT schema_migrations.execute_migration(1);

-- Check migration status
SELECT * FROM schema_migrations.get_migration_status('20230501000001');

-- Rollback the migration if needed
SELECT schema_migrations.rollback_migration(1);
*/
