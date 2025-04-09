-- Multi-Tenant Isolation Framework for PostgreSQL Security Framework
CREATE SCHEMA IF NOT EXISTS multi_tenant;

-- Table for storing tenant information
CREATE TABLE IF NOT EXISTS multi_tenant.tenants (
    id SERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL UNIQUE,
    tenant_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL DEFAULT 'active',
    tier TEXT NOT NULL,
    max_connections INTEGER NOT NULL,
    max_storage_gb INTEGER NOT NULL,
    max_cpu_percent INTEGER NOT NULL
);

-- Table for storing tenant resource usage
CREATE TABLE IF NOT EXISTS multi_tenant.resource_usage (
    id SERIAL PRIMARY KEY,
    tenant_id UUID REFERENCES multi_tenant.tenants(tenant_id),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    connection_count INTEGER NOT NULL,
    storage_used_gb NUMERIC(10,2) NOT NULL,
    cpu_percent NUMERIC(5,2) NOT NULL,
    query_count INTEGER NOT NULL,
    avg_query_time_ms NUMERIC(10,2) NOT NULL
);

-- Table for storing tenant-specific database objects
CREATE TABLE IF NOT EXISTS multi_tenant.tenant_objects (
    id SERIAL PRIMARY KEY,
    tenant_id UUID REFERENCES multi_tenant.tenants(tenant_id),
    object_type TEXT NOT NULL,
    schema_name TEXT NOT NULL,
    object_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, object_type, schema_name, object_name)
);

-- Table for storing tenant connection pools
CREATE TABLE IF NOT EXISTS multi_tenant.connection_pools (
    id SERIAL PRIMARY KEY,
    tenant_id UUID REFERENCES multi_tenant.tenants(tenant_id),
    pool_name TEXT NOT NULL,
    min_size INTEGER NOT NULL,
    max_size INTEGER NOT NULL,
    idle_timeout_seconds INTEGER NOT NULL,
    max_client_lifetime_seconds INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, pool_name)
);

-- Table for storing cross-tenant access rules
CREATE TABLE IF NOT EXISTS multi_tenant.cross_tenant_access (
    id SERIAL PRIMARY KEY,
    source_tenant_id UUID REFERENCES multi_tenant.tenants(tenant_id),
    target_tenant_id UUID REFERENCES multi_tenant.tenants(tenant_id),
    access_type TEXT NOT NULL,
    object_type TEXT,
    object_name TEXT,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by TEXT NOT NULL,
    expires_at TIMESTAMPTZ,
    CHECK (source_tenant_id <> target_tenant_id)
);

-- Function to register a new tenant
CREATE OR REPLACE FUNCTION multi_tenant.register_tenant(
    p_tenant_name TEXT,
    p_tier TEXT DEFAULT 'standard',
    p_max_connections INTEGER DEFAULT 50,
    p_max_storage_gb INTEGER DEFAULT 10,
    p_max_cpu_percent INTEGER DEFAULT 20
) RETURNS UUID AS $$
DECLARE
    v_tenant_id UUID;
    v_schema_name TEXT;
BEGIN
    -- Generate tenant ID
    v_tenant_id := gen_random_uuid();
    
    -- Generate schema name
    v_schema_name := 'tenant_' || replace(v_tenant_id::text, '-', '_');
    
    -- Register tenant
    INSERT INTO multi_tenant.tenants (
        tenant_id, tenant_name, tier, max_connections, max_storage_gb, max_cpu_percent
    ) VALUES (
        v_tenant_id, p_tenant_name, p_tier, p_max_connections, p_max_storage_gb, p_max_cpu_percent
    );
    
    -- Create tenant schema
    EXECUTE format('CREATE SCHEMA IF NOT EXISTS %I', v_schema_name);
    
    -- Register schema as tenant object
    INSERT INTO multi_tenant.tenant_objects (
        tenant_id, object_type, schema_name, object_name
    ) VALUES (
        v_tenant_id, 'SCHEMA', v_schema_name, v_schema_name
    );
    
    -- Create tenant role
    EXECUTE format('CREATE ROLE %I', 'tenant_' || v_tenant_id);
    
    -- Grant usage on tenant schema
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', v_schema_name, 'tenant_' || v_tenant_id);
    
    -- Create connection pool
    INSERT INTO multi_tenant.connection_pools (
        tenant_id, pool_name, min_size, max_size, 
        idle_timeout_seconds, max_client_lifetime_seconds
    ) VALUES (
        v_tenant_id, 'default', 5, p_max_connections, 300, 3600
    );
    
    -- Log tenant registration
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'TENANT_REGISTERED', 'INFO', current_user, 
        format('Registered tenant %s with ID %s', p_tenant_name, v_tenant_id)
    );
    
    RETURN v_tenant_id;
END;
$$ LANGUAGE plpgsql;

-- Function to create a tenant-specific table
CREATE OR REPLACE FUNCTION multi_tenant.create_tenant_table(
    p_tenant_id UUID,
    p_table_name TEXT,
    p_columns TEXT
) RETURNS VOID AS $$
DECLARE
    v_schema_name TEXT;
    v_sql TEXT;
BEGIN
    -- Get tenant schema
    SELECT schema_name INTO v_schema_name
    FROM multi_tenant.tenant_objects
    WHERE tenant_id = p_tenant_id
      AND object_type = 'SCHEMA'
    LIMIT 1;
    
    IF v_schema_name IS NULL THEN
        RAISE EXCEPTION 'Tenant with ID % not found', p_tenant_id;
    END IF;
    
    -- Create table
    v_sql := format('
        CREATE TABLE IF NOT EXISTS %I.%I (
            %s,
            tenant_id UUID NOT NULL DEFAULT %L,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CHECK (tenant_id = %L)
        )
    ', v_schema_name, p_table_name, p_columns, p_tenant_id, p_tenant_id);
    
    EXECUTE v_sql;
    
    -- Register table as tenant object
    INSERT INTO multi_tenant.tenant_objects (
        tenant_id, object_type, schema_name, object_name
    ) VALUES (
        p_tenant_id, 'TABLE', v_schema_name, p_table_name
    );
    
    -- Grant privileges to tenant role
    EXECUTE format('
        GRANT SELECT, INSERT, UPDATE, DELETE ON %I.%I TO %I
    ', v_schema_name, p_table_name, 'tenant_' || p_tenant_id);
    
    -- Create RLS policy
    EXECUTE format('
        ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY
    ', v_schema_name, p_table_name);
    
    EXECUTE format('
        CREATE POLICY tenant_isolation ON %I.%I
            USING (tenant_id = %L)
    ', v_schema_name, p_table_name, p_tenant_id);
    
    -- Log table creation
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'TENANT_TABLE_CREATED', 'INFO', current_user, 
        format('Created table %I.%I for tenant %s', v_schema_name, p_table_name, p_tenant_id)
    );
END;
$$ LANGUAGE plpgsql;

-- Function to set tenant context
CREATE OR REPLACE FUNCTION multi_tenant.set_tenant_context(
    p_tenant_id UUID
) RETURNS VOID AS $$
BEGIN
    -- Set tenant ID in session
    PERFORM set_config('multi_tenant.current_tenant_id', p_tenant_id::text, false);
    
    -- Log context switch
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'TENANT_CONTEXT_SET', 'INFO', current_user, 
        format('Set tenant context to %s', p_tenant_id)
    );
END;
$$ LANGUAGE plpgsql;

-- Function to get current tenant ID
CREATE OR REPLACE FUNCTION multi_tenant.get_current_tenant_id() RETURNS UUID AS $$
DECLARE
    v_tenant_id UUID;
BEGIN
    -- Get tenant ID from session
    v_tenant_id := current_setting('multi_tenant.current_tenant_id', true)::UUID;
    
    IF v_tenant_id IS NULL THEN
        RAISE EXCEPTION 'No tenant context set';
    END IF;
    
    RETURN v_tenant_id;
END;
$$ LANGUAGE plpgsql;

-- Function to enforce resource limits
CREATE OR REPLACE FUNCTION multi_tenant.enforce_resource_limits() RETURNS TRIGGER AS $$
DECLARE
    v_tenant RECORD;
    v_current_connections INTEGER;
    v_current_storage_gb NUMERIC;
BEGIN
    -- Get tenant limits
    SELECT * INTO v_tenant
    FROM multi_tenant.tenants
    WHERE tenant_id = NEW.tenant_id;
    
    -- Check connection limit
    SELECT count(*) INTO v_current_connections
    FROM pg_stat_activity
    WHERE application_name LIKE 'tenant_' || NEW.tenant_id || '%';
    
    IF v_current_connections >= v_tenant.max_connections THEN
        RAISE EXCEPTION 'Tenant % has reached maximum connection limit of %', 
                        NEW.tenant_id, v_tenant.max_connections;
    END IF;
    
    -- Check storage limit
    SELECT COALESCE(sum(pg_total_relation_size(c.oid)) / (1024^3), 0) INTO v_current_storage_gb
    FROM pg_class c
    JOIN pg_namespace n ON c.relnamespace = n.oid
    JOIN multi_tenant.tenant_objects o ON n.nspname = o.schema_name
    WHERE o.tenant_id = NEW.tenant_id;
    
    IF v_current_storage_gb >= v_tenant.max_storage_gb THEN
        RAISE EXCEPTION 'Tenant % has reached maximum storage limit of % GB', 
                        NEW.tenant_id, v_tenant.max_storage_gb;
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for resource limits
CREATE TRIGGER enforce_resource_limits
BEFORE INSERT ON multi_tenant.resource_usage
FOR EACH ROW EXECUTE FUNCTION multi_tenant.enforce_resource_limits();

-- Function to monitor tenant resource usage
CREATE OR REPLACE FUNCTION multi_tenant.monitor_resource_usage() RETURNS VOID AS $$
DECLARE
    v_tenant RECORD;
    v_connection_count INTEGER;
    v_storage_used_gb NUMERIC;
    v_cpu_percent NUMERIC;
    v_query_count INTEGER;
    v_avg_query_time_ms NUMERIC;
BEGIN
    -- Loop through active tenants
    FOR v_tenant IN
        SELECT * FROM multi_tenant.tenants
        WHERE status = 'active'
    LOOP
        -- Get connection count
        SELECT count(*) INTO v_connection_count
        FROM pg_stat_activity
        WHERE application_name LIKE 'tenant_' || v_tenant.tenant_id || '%';
        
        -- Get storage usage
        SELECT COALESCE(sum(pg_total_relation_size(c.oid)) / (1024^3), 0) INTO v_storage_used_gb
        FROM pg_class c
        JOIN pg_namespace n ON c.relnamespace = n.oid
        JOIN multi_tenant.tenant_objects o ON n.nspname = o.schema_name
        WHERE o.tenant_id = v_tenant.tenant_id;
        
        -- Get CPU usage (simplified - in a real implementation, this would use OS-level metrics)
        SELECT COALESCE(avg(total_time), 0) / 1000 INTO v_cpu_percent
        FROM pg_stat_statements s
        JOIN pg_roles r ON s.userid = r.oid
        WHERE r.rolname = 'tenant_' || v_tenant.tenant_id;
        
        -- Get query stats
        SELECT count(*), COALESCE(avg(total_time), 0) INTO v_query_count, v_avg_query_time_ms
        FROM pg_stat_statements s
        JOIN pg_roles r ON s.userid = r.oid
        WHERE r.rolname = 'tenant_' || v_tenant.tenant_id;
        
        -- Record usage
        INSERT INTO multi_tenant.resource_usage (
            tenant_id, connection_count, storage_used_gb, 
            cpu_percent, query_count, avg_query_time_ms
        ) VALUES (
            v_tenant.tenant_id, v_connection_count, v_storage_used_gb,
            v_cpu_percent, v_query_count, v_avg_query_time_ms
        );
        
        -- Check for limit warnings
        IF v_connection_count > v_tenant.max_connections * 0.8 THEN
            INSERT INTO logs.notification_log (
                event_type, severity, username, message
            ) VALUES (
                'TENANT_RESOURCE_WARNING', 'WARNING', current_user, 
                format('Tenant %s approaching connection limit: %s/%s', 
                       v_tenant.tenant_name, v_connection_count, v_tenant.max_connections)
            );
        END IF;
        
        IF v_storage_used_gb > v_tenant.max_storage_gb * 0.8 THEN
            INSERT INTO logs.notification_log (
                event_type, severity, username, message
            ) VALUES (
                'TENANT_RESOURCE_WARNING', 'WARNING', current_user, 
                format('Tenant %s approaching storage limit: %.2f/%s GB', 
                       v_tenant.tenant_name, v_storage_used_gb, v_tenant.max_storage_gb)
            );
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- Function to grant cross-tenant access
CREATE OR REPLACE FUNCTION multi_tenant.grant_cross_tenant_access(
    p_source_tenant_id UUID,
    p_target_tenant_id UUID,
    p_access_type TEXT,
    p_object_type TEXT DEFAULT NULL,
    p_object_name TEXT DEFAULT NULL,
    p_expires_at TIMESTAMPTZ DEFAULT NULL
) RETURNS VOID AS $$
DECLARE
    v_source_schema TEXT;
    v_target_schema TEXT;
    v_sql TEXT;
BEGIN
    -- Verify tenants exist
    IF NOT EXISTS (SELECT 1 FROM multi_tenant.tenants WHERE tenant_id = p_source_tenant_id) THEN
        RAISE EXCEPTION 'Source tenant with ID % not found', p_source_tenant_id;
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM multi_tenant.tenants WHERE tenant_id = p_target_tenant_id) THEN
        RAISE EXCEPTION 'Target tenant with ID % not found', p_target_tenant_id;
    END IF;
    
    -- Get tenant schemas
    SELECT schema_name INTO v_source_schema
    FROM multi_tenant.tenant_objects
    WHERE tenant_id = p_source_tenant_id
      AND object_type = 'SCHEMA'
    LIMIT 1;
    
    SELECT schema_name INTO v_target_schema
    FROM multi_tenant.tenant_objects
    WHERE tenant_id = p_target_tenant_id
      AND object_type = 'SCHEMA'
    LIMIT 1;
    
    -- Grant access based on access type
    CASE p_access_type
        WHEN 'READ' THEN
            IF p_object_type = 'TABLE' AND p_object_name IS NOT NULL THEN
                -- Grant read access to specific table
                v_sql := format('
                    GRANT SELECT ON %I.%I TO %I
                ', v_target_schema, p_object_name, 'tenant_' || p_source_tenant_id);
                EXECUTE v_sql;
            ELSE
                -- Grant read access to all tables
                v_sql := format('
                    GRANT USAGE ON SCHEMA %I TO %I;
                    GRANT SELECT ON ALL TABLES IN SCHEMA %I TO %I
                ', v_target_schema, 'tenant_' || p_source_tenant_id,
                   v_target_schema, 'tenant_' || p_source_tenant_id);
                EXECUTE v_sql;
            END IF;
        
        WHEN 'WRITE' THEN
            IF p_object_type = 'TABLE' AND p_object_name IS NOT NULL THEN
                -- Grant write access to specific table
                v_sql := format('
                    GRANT SELECT, INSERT, UPDATE, DELETE ON %I.%I TO %I
                ', v_target_schema, p_object_name, 'tenant_' || p_source_tenant_id);
                EXECUTE v_sql;
            ELSE
                -- Grant write access to all tables
                v_sql := format('
                    GRANT USAGE ON SCHEMA %I TO %I;
                    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA %I TO %I
                ', v_target_schema, 'tenant_' || p_source_tenant_id,
                   v_target_schema, 'tenant_' || p_source_tenant_id);
                EXECUTE v_sql;
            END IF;
        
        ELSE
            RAISE EXCEPTION 'Unsupported access type: %', p_access_type;
    END CASE;
    
    -- Create RLS policy for cross-tenant access
    IF p_object_type = 'TABLE' AND p_object_name IS NOT NULL THEN
        v_sql := format('
            CREATE POLICY cross_tenant_access ON %I.%I
                FOR %s
                TO %I
                USING (tenant_id = %L)
        ', v_target_schema, p_object_name, 
           CASE WHEN p_access_type = 'READ' THEN 'SELECT' ELSE 'ALL' END,
           'tenant_' || p_source_tenant_id, p_target_tenant_id);
        EXECUTE v_sql;
    END IF;
    
    -- Record cross-tenant access
    INSERT INTO multi_tenant.cross_tenant_access (
        source_tenant_id, target_tenant_id, access_type,
        object_type, object_name, granted_by, expires_at
    ) VALUES (
        p_source_tenant_id, p_target_tenant_id, p_access_type,
        p_object_type, p_object_name, current_user, p_expires_at
    );
    
    -- Log cross-tenant access grant
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'CROSS_TENANT_ACCESS_GRANTED', 'INFO', current_user, 
        format('Granted %s access from tenant %s to tenant %s%s', 
               p_access_type, p_source_tenant_id, p_target_tenant_id,
               CASE WHEN p_object_name IS NOT NULL 
                    THEN ' for ' || p_object_type || ' ' || p_object_name
                    ELSE '' END)
    );
END;
$$ LANGUAGE plpgsql;

-- Function to revoke cross-tenant access
CREATE OR REPLACE FUNCTION multi_tenant.revoke_cross_tenant_access(
    p_source_tenant_id UUID,
    p_target_tenant_id UUID,
    p_access_type TEXT,
    p_object_type TEXT DEFAULT NULL,
    p_object_name TEXT DEFAULT NULL
) RETURNS VOID AS $$
DECLARE
    v_source_schema TEXT;
    v_target_schema TEXT;
    v_sql TEXT;
BEGIN
    -- Get tenant schemas
    SELECT schema_name INTO v_source_schema
    FROM multi_tenant.tenant_objects
    WHERE tenant_id = p_source_tenant_id
      AND object_type = 'SCHEMA'
    LIMIT 1;
    
    SELECT schema_name INTO v_target_schema
    FROM multi_tenant.tenant_objects
    WHERE tenant_id = p_target_tenant_id
      AND object_type = 'SCHEMA'
    LIMIT 1;
    
    -- Revoke access based on access type
    CASE p_access_type
        WHEN 'READ' THEN
            IF p_object_type = 'TABLE' AND p_object_name IS NOT NULL THEN
                -- Revoke read access from specific table
                v_sql := format('
                    REVOKE SELECT ON %I.%I FROM %I
                ', v_target_schema, p_object_name, 'tenant_' || p_source_tenant_id);
                EXECUTE v_sql;
            ELSE
                -- Revoke read access from all tables
                v_sql := format('
                    REVOKE SELECT ON ALL TABLES IN SCHEMA %I FROM %I;
                    REVOKE USAGE ON SCHEMA %I FROM %I
                ', v_target_schema, 'tenant_' || p_source_tenant_id,
                   v_target_schema, 'tenant_' || p_source_tenant_id);
                EXECUTE v_sql;
            END IF;
        
        WHEN 'WRITE' THEN
            IF p_object_type = 'TABLE' AND p_object_name IS NOT NULL THEN
                -- Revoke write access from specific table
                v_sql := format('
                    REVOKE SELECT, INSERT, UPDATE, DELETE ON %I.%I FROM %I
                ', v_target_schema, p_object_name, 'tenant_' || p_source_tenant_id);
                EXECUTE v_sql;
            ELSE
                -- Revoke write access from all tables
                v_sql := format('
                    REVOKE SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA %I FROM %I;
                    REVOKE USAGE ON SCHEMA %I FROM %I
                ', v_target_schema, 'tenant_' || p_source_tenant_id,
                   v_target_schema, 'tenant_' || p_source_tenant_id);
                EXECUTE v_sql;
            END IF;
        
        ELSE
            RAISE EXCEPTION 'Unsupported access type: %', p_access_type;
    END CASE;
    
    -- Drop RLS policy for cross-tenant access
    IF p_object_type = 'TABLE' AND p_object_name IS NOT NULL THEN
        v_sql := format('
            DROP POLICY IF EXISTS cross_tenant_access ON %I.%I
        ', v_target_schema, p_object_name);
        EXECUTE v_sql;
    END IF;
    
    -- Update cross-tenant access record
    UPDATE multi_tenant.cross_tenant_access
    SET expires_at = NOW()
    WHERE source_tenant_id = p_source_tenant_id
      AND target_tenant_id = p_target_tenant_id
      AND access_type = p_access_type
      AND (object_type = p_object_type OR (object_type IS NULL AND p_object_type IS NULL))
      AND (object_name = p_object_name OR (object_name IS NULL AND p_object_name IS NULL));
    
    -- Log cross-tenant access revocation
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'CROSS_TENANT_ACCESS_REVOKED', 'INFO', current_user, 
        format('Revoked %s access from tenant %s to tenant %s%s', 
               p_access_type, p_source_tenant_id, p_target_tenant_id,
               CASE WHEN p_object_name IS NOT NULL 
                    THEN ' for ' || p_object_type || ' ' || p_object_name
                    ELSE '' END)
    );
END;
$$ LANGUAGE plpgsql;

-- Function to get tenant resource usage
CREATE OR REPLACE FUNCTION multi_tenant.get_tenant_resource_usage(
    p_tenant_id UUID,
    p_days INTEGER DEFAULT 7
) RETURNS TABLE (
    day DATE,
    avg_connections INTEGER,
    max_connections INTEGER,
    avg_storage_gb NUMERIC,
    max_storage_gb NUMERIC,
    avg_cpu_percent NUMERIC,
    max_cpu_percent NUMERIC,
    total_queries INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        date_trunc('day', ru.timestamp)::DATE AS day,
        round(avg(ru.connection_count))::INTEGER AS avg_connections,
        max(ru.connection_count)::INTEGER AS max_connections,
        round(avg(ru.storage_used_gb), 2) AS avg_storage_gb,
        max(ru.storage_used_gb) AS max_storage_gb,
        round(avg(ru.cpu_percent), 2) AS avg_cpu_percent,
        max(ru.cpu_percent) AS max_cpu_percent,
        sum(ru.query_count)::INTEGER AS total_queries
    FROM multi_tenant.resource_usage ru
    WHERE ru.tenant_id = p_tenant_id
      AND ru.timestamp >= NOW() - (p_days || ' days')::INTERVAL
    GROUP BY day
    ORDER BY day;
END;
$$ LANGUAGE plpgsql;

-- Function to get tenant connection pool configuration
CREATE OR REPLACE FUNCTION multi_tenant.get_connection_pool_config(
    p_tenant_id UUID
) RETURNS TABLE (
    pool_name TEXT,
    min_size INTEGER,
    max_size INTEGER,
    idle_timeout_seconds INTEGER,
    max_client_lifetime_seconds INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        cp.pool_name,
        cp.min_size,
        cp.max_size,
        cp.idle_timeout_seconds,
        cp.max_client_lifetime_seconds
    FROM multi_tenant.connection_pools cp
    WHERE cp.tenant_id = p_tenant_id;
END;
$$ LANGUAGE plpgsql;

-- Grant permissions
GRANT USAGE ON SCHEMA multi_tenant TO security_admin;
GRANT SELECT ON ALL TABLES IN SCHEMA multi_tenant TO security_admin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA multi_tenant TO security_admin;
