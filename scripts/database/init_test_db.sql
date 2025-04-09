-- Initialize test database for security testing
-- This script creates the necessary schemas, tables, and functions for security testing

-- Create schemas
CREATE SCHEMA IF NOT EXISTS logs;
CREATE SCHEMA IF NOT EXISTS analytics;
CREATE SCHEMA IF NOT EXISTS key_management;
CREATE SCHEMA IF NOT EXISTS security;
CREATE SCHEMA IF NOT EXISTS audit;
CREATE SCHEMA IF NOT EXISTS data_classification;

-- Create log tables
CREATE TABLE IF NOT EXISTS logs.notification_log (
    id SERIAL PRIMARY KEY,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    username TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS logs.query_log (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    query_text TEXT NOT NULL,
    execution_time_ms INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS logs.data_change_log (
    id SERIAL PRIMARY KEY,
    table_schema TEXT NOT NULL,
    table_name TEXT NOT NULL,
    operation TEXT NOT NULL,
    record_id TEXT,
    old_data JSONB,
    new_data JSONB,
    username TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS logs.security_event_log (
    id SERIAL PRIMARY KEY,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    username TEXT NOT NULL,
    ip_address TEXT,
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create analytics tables
CREATE TABLE IF NOT EXISTS analytics.query_patterns (
    id SERIAL PRIMARY KEY,
    query_pattern TEXT NOT NULL,
    frequency INTEGER NOT NULL DEFAULT 1,
    avg_duration NUMERIC(10,2) NOT NULL DEFAULT 0,
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS analytics.user_profiles (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    typical_queries JSONB,
    typical_login_hours INTEGER[],
    typical_session_duration INTEGER,
    typical_access_patterns JSONB,
    last_updated TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create key management tables
CREATE TABLE IF NOT EXISTS key_management.encryption_keys (
    id SERIAL PRIMARY KEY,
    key_id UUID NOT NULL UNIQUE,
    key_data BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

-- Create data classification tables
CREATE TABLE IF NOT EXISTS data_classification.levels (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL,
    level_order INTEGER NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS data_classification.column_classifications (
    id SERIAL PRIMARY KEY,
    schema_name TEXT NOT NULL,
    table_name TEXT NOT NULL,
    column_name TEXT NOT NULL,
    level_id INTEGER NOT NULL REFERENCES data_classification.levels(id),
    UNIQUE(schema_name, table_name, column_name)
);

-- Insert default classification levels
INSERT INTO data_classification.levels (name, description, level_order)
VALUES 
('Public', 'Data that can be freely shared', 1),
('Internal', 'Data for internal use only', 2),
('Confidential', 'Sensitive data with restricted access', 3),
('Restricted', 'Highly sensitive data with very limited access', 4)
ON CONFLICT (name) DO NOTHING;

-- Create analytics functions
CREATE OR REPLACE FUNCTION analytics.normalize_query(p_query TEXT)
RETURNS TEXT AS $$
DECLARE
    v_normalized TEXT;
BEGIN
    -- Simple normalization: replace literals with placeholders
    v_normalized := regexp_replace(p_query, '''[^'']*''', '''?''', 'g');
    v_normalized := regexp_replace(v_normalized, '\d+', '?', 'g');
    
    RETURN v_normalized;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION analytics.update_query_patterns(p_query TEXT, p_duration_ms INTEGER)
RETURNS VOID AS $$
DECLARE
    v_normalized TEXT;
BEGIN
    -- Normalize the query
    v_normalized := analytics.normalize_query(p_query);
    
    -- Update query patterns
    INSERT INTO analytics.query_patterns (query_pattern, frequency, avg_duration, last_seen)
    VALUES (v_normalized, 1, p_duration_ms, NOW())
    ON CONFLICT (query_pattern) DO UPDATE
    SET frequency = analytics.query_patterns.frequency + 1,
        avg_duration = (analytics.query_patterns.avg_duration * analytics.query_patterns.frequency + p_duration_ms) / (analytics.query_patterns.frequency + 1),
        last_seen = NOW();
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION analytics.detect_query_anomalies()
RETURNS TABLE (
    query_pattern TEXT,
    frequency INTEGER,
    avg_duration NUMERIC,
    last_seen TIMESTAMPTZ,
    anomaly_score NUMERIC,
    anomaly_type TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        qp.query_pattern,
        qp.frequency,
        qp.avg_duration,
        qp.last_seen,
        CASE
            WHEN qp.frequency < 5 THEN 0.8
            WHEN qp.avg_duration > 1000 THEN 0.9
            ELSE 0.0
        END AS anomaly_score,
        CASE
            WHEN qp.frequency < 5 THEN 'Rare Query'
            WHEN qp.avg_duration > 1000 THEN 'Slow Query'
            ELSE 'Normal'
        END AS anomaly_type
    FROM analytics.query_patterns qp
    WHERE qp.frequency < 5 OR qp.avg_duration > 1000
    ORDER BY anomaly_score DESC;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION analytics.update_user_profile(
    p_username TEXT,
    p_query TEXT DEFAULT NULL,
    p_login_hour INTEGER DEFAULT NULL,
    p_session_duration INTEGER DEFAULT NULL,
    p_access_pattern JSONB DEFAULT NULL
)
RETURNS VOID AS $$
DECLARE
    v_profile JSONB;
BEGIN
    -- Create or update user profile
    INSERT INTO analytics.user_profiles (username, typical_queries, typical_login_hours, typical_session_duration, typical_access_patterns)
    VALUES (p_username, '[]'::JSONB, ARRAY[]::INTEGER[], 0, '{}'::JSONB)
    ON CONFLICT (username) DO NOTHING;
    
    -- Update query patterns if provided
    IF p_query IS NOT NULL THEN
        UPDATE analytics.user_profiles
        SET typical_queries = jsonb_insert(
            COALESCE(typical_queries, '[]'::JSONB),
            '{0}',
            to_jsonb(analytics.normalize_query(p_query))
        )
        WHERE username = p_username;
    END IF;
    
    -- Update login hours if provided
    IF p_login_hour IS NOT NULL THEN
        UPDATE analytics.user_profiles
        SET typical_login_hours = array_append(COALESCE(typical_login_hours, ARRAY[]::INTEGER[]), p_login_hour)
        WHERE username = p_username;
    END IF;
    
    -- Update session duration if provided
    IF p_session_duration IS NOT NULL THEN
        UPDATE analytics.user_profiles
        SET typical_session_duration = (COALESCE(typical_session_duration, 0) + p_session_duration) / 2
        WHERE username = p_username;
    END IF;
    
    -- Update access patterns if provided
    IF p_access_pattern IS NOT NULL THEN
        UPDATE analytics.user_profiles
        SET typical_access_patterns = typical_access_patterns || p_access_pattern
        WHERE username = p_username;
    END IF;
    
    -- Update last_updated timestamp
    UPDATE analytics.user_profiles
    SET last_updated = NOW()
    WHERE username = p_username;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION analytics.detect_user_anomalies()
RETURNS TABLE (
    username TEXT,
    anomaly_type TEXT,
    anomaly_score NUMERIC,
    details JSONB
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        up.username,
        'Unusual Login Hour' AS anomaly_type,
        0.8 AS anomaly_score,
        jsonb_build_object('message', 'User logged in at unusual hour')
    FROM analytics.user_profiles up
    WHERE up.username IN (
        SELECT DISTINCT username FROM logs.notification_log
        WHERE event_type = 'LOGIN'
        AND created_at > NOW() - INTERVAL '1 day'
    )
    LIMIT 5;
END;
$$ LANGUAGE plpgsql;

-- Create key management functions
CREATE OR REPLACE FUNCTION key_management.create_encryption_key()
RETURNS UUID AS $$
DECLARE
    v_key_id UUID;
    v_key_data BYTEA;
BEGIN
    -- Generate a new key ID
    v_key_id := gen_random_uuid();
    
    -- Generate random key data (256 bits)
    v_key_data := gen_random_bytes(32);
    
    -- Store the key
    INSERT INTO key_management.encryption_keys (key_id, key_data)
    VALUES (v_key_id, v_key_data);
    
    -- Log key creation
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'KEY_CREATED', 'INFO', current_user, 
        format('Created encryption key %s', v_key_id)
    );
    
    RETURN v_key_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION key_management.get_current_key()
RETURNS UUID AS $$
DECLARE
    v_key_id UUID;
BEGIN
    -- Get the most recently created active key
    SELECT key_id INTO v_key_id
    FROM key_management.encryption_keys
    WHERE is_active = TRUE
    ORDER BY created_at DESC
    LIMIT 1;
    
    -- If no key exists, create one
    IF v_key_id IS NULL THEN
        v_key_id := key_management.create_encryption_key();
    END IF;
    
    RETURN v_key_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION key_management.rotate_encryption_key()
RETURNS UUID AS $$
DECLARE
    v_new_key_id UUID;
BEGIN
    -- Create a new key
    v_new_key_id := key_management.create_encryption_key();
    
    -- Log key rotation
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'KEY_ROTATED', 'INFO', current_user, 
        format('Rotated to new encryption key %s', v_new_key_id)
    );
    
    RETURN v_new_key_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION key_management.encrypt_data(p_data TEXT)
RETURNS BYTEA AS $$
DECLARE
    v_key_id UUID;
    v_key_data BYTEA;
    v_encrypted BYTEA;
BEGIN
    -- Get the current key
    v_key_id := key_management.get_current_key();
    
    -- Get the key data
    SELECT key_data INTO v_key_data
    FROM key_management.encryption_keys
    WHERE key_id = v_key_id;
    
    -- Encrypt the data using pgcrypto
    v_encrypted := encrypt(
        convert_to(p_data, 'UTF8'),
        v_key_data,
        'aes'
    );
    
    RETURN v_encrypted;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION key_management.decrypt_data(p_encrypted BYTEA)
RETURNS TEXT AS $$
DECLARE
    v_key_id UUID;
    v_key_data BYTEA;
    v_decrypted TEXT;
BEGIN
    -- Get the current key
    v_key_id := key_management.get_current_key();
    
    -- Get the key data
    SELECT key_data INTO v_key_data
    FROM key_management.encryption_keys
    WHERE key_id = v_key_id;
    
    -- Decrypt the data using pgcrypto
    v_decrypted := convert_from(
        decrypt(
            p_encrypted,
            v_key_data,
            'aes'
        ),
        'UTF8'
    );
    
    RETURN v_decrypted;
END;
$$ LANGUAGE plpgsql;

-- Create audit functions
CREATE OR REPLACE FUNCTION audit.enable_row_level_audit(p_table_name TEXT)
RETURNS VOID AS $$
DECLARE
    v_schema_name TEXT;
    v_table_name TEXT;
    v_trigger_name TEXT;
BEGIN
    -- Parse schema and table name
    IF p_table_name LIKE '%.%' THEN
        v_schema_name := split_part(p_table_name, '.', 1);
        v_table_name := split_part(p_table_name, '.', 2);
    ELSE
        v_schema_name := 'public';
        v_table_name := p_table_name;
    END IF;
    
    -- Create trigger name
    v_trigger_name := 'trg_audit_' || v_table_name;
    
    -- Create trigger function
    EXECUTE format('
        CREATE OR REPLACE FUNCTION %I.%I()
        RETURNS TRIGGER AS $func$
        BEGIN
            IF TG_OP = ''INSERT'' THEN
                INSERT INTO logs.data_change_log (
                    table_schema, table_name, operation, record_id, new_data, username
                ) VALUES (
                    TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP, NEW.id::TEXT, row_to_json(NEW), current_user
                );
                RETURN NEW;
            ELSIF TG_OP = ''UPDATE'' THEN
                INSERT INTO logs.data_change_log (
                    table_schema, table_name, operation, record_id, old_data, new_data, username
                ) VALUES (
                    TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP, NEW.id::TEXT, row_to_json(OLD), row_to_json(NEW), current_user
                );
                RETURN NEW;
            ELSIF TG_OP = ''DELETE'' THEN
                INSERT INTO logs.data_change_log (
                    table_schema, table_name, operation, record_id, old_data, username
                ) VALUES (
                    TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP, OLD.id::TEXT, row_to_json(OLD), current_user
                );
                RETURN OLD;
            END IF;
            RETURN NULL;
        END;
        $func$ LANGUAGE plpgsql;
    ', v_schema_name, 'fn_' || v_trigger_name);
    
    -- Create trigger
    EXECUTE format('
        DROP TRIGGER IF EXISTS %I ON %I.%I;
        CREATE TRIGGER %I
        AFTER INSERT OR UPDATE OR DELETE ON %I.%I
        FOR EACH ROW EXECUTE FUNCTION %I.%I();
    ', v_trigger_name, v_schema_name, v_table_name, v_trigger_name, v_schema_name, v_table_name, v_schema_name, 'fn_' || v_trigger_name);
    
    -- Log trigger creation
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'AUDIT_ENABLED', 'INFO', current_user, 
        format('Enabled row-level audit for %I.%I', v_schema_name, v_table_name)
    );
END;
$$ LANGUAGE plpgsql;

-- Create security functions
CREATE OR REPLACE FUNCTION security.constant_time_compare(a TEXT, b TEXT)
RETURNS BOOLEAN AS $$
DECLARE
    a_bytes BYTEA;
    b_bytes BYTEA;
    i INTEGER;
    result INTEGER := 0;
BEGIN
    IF length(a) <> length(b) THEN
        -- Still do the comparison to avoid timing differences
        a_bytes := convert_to(a, 'UTF8');
        b_bytes := convert_to(b, 'UTF8');
        FOR i IN 1..length(a_bytes) LOOP
            result := result | get_byte(a_bytes, i-1) # get_byte(b_bytes, i-1);
        END LOOP;
        RETURN FALSE;
    END IF;
    
    a_bytes := convert_to(a, 'UTF8');
    b_bytes := convert_to(b, 'UTF8');
    
    FOR i IN 1..length(a_bytes) LOOP
        result := result | (get_byte(a_bytes, i-1) # get_byte(b_bytes, i-1));
    END LOOP;
    
    RETURN result = 0;
END;
$$ LANGUAGE plpgsql;

-- Grant permissions
GRANT USAGE ON SCHEMA logs TO PUBLIC;
GRANT USAGE ON SCHEMA analytics TO PUBLIC;
GRANT USAGE ON SCHEMA key_management TO PUBLIC;
GRANT USAGE ON SCHEMA security TO PUBLIC;
GRANT USAGE ON SCHEMA audit TO PUBLIC;
GRANT USAGE ON SCHEMA data_classification TO PUBLIC;

-- Create initial encryption key
SELECT key_management.create_encryption_key();
