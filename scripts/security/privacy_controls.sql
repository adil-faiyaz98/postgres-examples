-- PostgreSQL Privacy Controls
-- This script implements comprehensive privacy controls for the PostgreSQL Security Framework

\c db_dev;

-- Create schema for privacy controls
CREATE SCHEMA IF NOT EXISTS privacy;

-- Create extension for data masking and tokenization
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Create table for storing privacy settings
CREATE TABLE IF NOT EXISTS privacy.settings (
    id SERIAL PRIMARY KEY,
    schema_name TEXT NOT NULL,
    table_name TEXT NOT NULL,
    column_name TEXT NOT NULL,
    privacy_type TEXT NOT NULL,
    privacy_config JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(schema_name, table_name, column_name)
);

-- Create table for storing tokenization mappings
CREATE TABLE IF NOT EXISTS privacy.tokenization_mappings (
    id SERIAL PRIMARY KEY,
    schema_name TEXT NOT NULL,
    table_name TEXT NOT NULL,
    column_name TEXT NOT NULL,
    original_value TEXT NOT NULL,
    tokenized_value TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(schema_name, table_name, column_name, original_value)
);

-- Create index on tokenization mappings for faster lookups
CREATE INDEX IF NOT EXISTS idx_tokenization_mappings_lookup
ON privacy.tokenization_mappings (schema_name, table_name, column_name, tokenized_value);

-- Create function to mask data based on privacy settings
CREATE OR REPLACE FUNCTION privacy.mask_data(
    p_value TEXT,
    p_privacy_type TEXT,
    p_privacy_config JSONB
) RETURNS TEXT AS $$
DECLARE
    v_result TEXT;
    v_mask_char TEXT;
    v_visible_chars INTEGER;
    v_visible_start INTEGER;
    v_visible_end INTEGER;
    v_format TEXT;
BEGIN
    IF p_value IS NULL THEN
        RETURN NULL;
    END IF;

    CASE p_privacy_type
        -- Full masking (replace with asterisks)
        WHEN 'full_mask' THEN
            v_mask_char := COALESCE(p_privacy_config->>'mask_char', '*');
            v_result := REPEAT(v_mask_char, LENGTH(p_value));
        
        -- Partial masking (show first/last N characters)
        WHEN 'partial_mask' THEN
            v_mask_char := COALESCE(p_privacy_config->>'mask_char', '*');
            v_visible_start := COALESCE((p_privacy_config->>'visible_start')::INTEGER, 0);
            v_visible_end := COALESCE((p_privacy_config->>'visible_end')::INTEGER, 0);
            
            IF LENGTH(p_value) <= (v_visible_start + v_visible_end) THEN
                v_result := p_value;
            ELSE
                v_result := 
                    SUBSTRING(p_value, 1, v_visible_start) || 
                    REPEAT(v_mask_char, LENGTH(p_value) - v_visible_start - v_visible_end) ||
                    SUBSTRING(p_value, LENGTH(p_value) - v_visible_end + 1);
            END IF;
        
        -- Format-preserving masking (e.g., for credit cards, SSNs)
        WHEN 'format_preserving' THEN
            v_format := COALESCE(p_privacy_config->>'format', 'XXXX-XXXX-XXXX-XXXX');
            v_visible_end := COALESCE((p_privacy_config->>'visible_end')::INTEGER, 4);
            
            IF v_format = 'XXXX-XXXX-XXXX-XXXX' AND LENGTH(p_value) >= 16 THEN
                -- Credit card format
                v_result := 
                    REPEAT('*', 4) || '-' ||
                    REPEAT('*', 4) || '-' ||
                    REPEAT('*', 4) || '-' ||
                    SUBSTRING(p_value, LENGTH(p_value) - v_visible_end + 1);
            ELSIF v_format = 'XXX-XX-XXXX' AND LENGTH(p_value) >= 9 THEN
                -- SSN format
                v_result := 
                    REPEAT('*', 3) || '-' ||
                    REPEAT('*', 2) || '-' ||
                    SUBSTRING(p_value, LENGTH(p_value) - v_visible_end + 1);
            ELSE
                -- Generic format
                v_result := REGEXP_REPLACE(p_value, '[0-9a-zA-Z]', '*', 'g');
            END IF;
        
        -- Email masking (show domain only)
        WHEN 'email_mask' THEN
            IF p_value LIKE '%@%' THEN
                v_result := 
                    REPEAT('*', POSITION('@' IN p_value) - 1) || 
                    SUBSTRING(p_value, POSITION('@' IN p_value));
            ELSE
                v_result := REPEAT('*', LENGTH(p_value));
            END IF;
        
        -- Truncation (show only first N characters)
        WHEN 'truncate' THEN
            v_visible_chars := COALESCE((p_privacy_config->>'visible_chars')::INTEGER, 3);
            IF LENGTH(p_value) <= v_visible_chars THEN
                v_result := p_value;
            ELSE
                v_result := SUBSTRING(p_value, 1, v_visible_chars) || '...';
            END IF;
        
        -- Default: return as is
        ELSE
            v_result := p_value;
    END CASE;
    
    RETURN v_result;
END;
$$ LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER;

-- Create function to tokenize data
CREATE OR REPLACE FUNCTION privacy.tokenize_data(
    p_schema_name TEXT,
    p_table_name TEXT,
    p_column_name TEXT,
    p_value TEXT,
    p_deterministic BOOLEAN DEFAULT TRUE
) RETURNS TEXT AS $$
DECLARE
    v_tokenized_value TEXT;
    v_salt TEXT;
BEGIN
    IF p_value IS NULL THEN
        RETURN NULL;
    END IF;
    
    -- For deterministic tokenization, check if we already have a mapping
    IF p_deterministic THEN
        SELECT tokenized_value INTO v_tokenized_value
        FROM privacy.tokenization_mappings
        WHERE schema_name = p_schema_name
          AND table_name = p_table_name
          AND column_name = p_column_name
          AND original_value = p_value;
        
        -- If found, return the existing tokenized value
        IF v_tokenized_value IS NOT NULL THEN
            RETURN v_tokenized_value;
        END IF;
    END IF;
    
    -- Generate a new tokenized value
    IF p_deterministic THEN
        -- Deterministic tokenization (same input always produces same output)
        v_tokenized_value := encode(
            hmac(
                p_value::bytea, 
                current_setting('app.tokenization_key', true)::bytea, 
                'sha256'
            ),
            'hex'
        );
    ELSE
        -- Non-deterministic tokenization (random token each time)
        v_salt := gen_random_uuid()::text;
        v_tokenized_value := encode(
            hmac(
                p_value::bytea || v_salt::bytea, 
                current_setting('app.tokenization_key', true)::bytea, 
                'sha256'
            ),
            'hex'
        );
    END IF;
    
    -- Store the mapping for deterministic tokenization
    IF p_deterministic THEN
        INSERT INTO privacy.tokenization_mappings (
            schema_name, table_name, column_name, original_value, tokenized_value
        ) VALUES (
            p_schema_name, p_table_name, p_column_name, p_value, v_tokenized_value
        ) ON CONFLICT (schema_name, table_name, column_name, original_value) DO NOTHING;
    END IF;
    
    RETURN v_tokenized_value;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to detokenize data
CREATE OR REPLACE FUNCTION privacy.detokenize_data(
    p_schema_name TEXT,
    p_table_name TEXT,
    p_column_name TEXT,
    p_tokenized_value TEXT
) RETURNS TEXT AS $$
DECLARE
    v_original_value TEXT;
BEGIN
    IF p_tokenized_value IS NULL THEN
        RETURN NULL;
    END IF;
    
    -- Look up the original value
    SELECT original_value INTO v_original_value
    FROM privacy.tokenization_mappings
    WHERE schema_name = p_schema_name
      AND table_name = p_table_name
      AND column_name = p_column_name
      AND tokenized_value = p_tokenized_value;
    
    -- Return the original value if found, otherwise return NULL
    RETURN v_original_value;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to apply privacy controls to a query result
CREATE OR REPLACE FUNCTION privacy.apply_privacy_controls(
    p_query TEXT,
    p_role TEXT DEFAULT current_user
) RETURNS SETOF record AS $$
DECLARE
    v_sql TEXT;
    v_privacy_settings RECORD;
    v_column_list TEXT := '';
    v_from_clause TEXT;
    v_where_clause TEXT;
    v_result record;
BEGIN
    -- Extract FROM clause from the query
    v_from_clause := substring(p_query FROM '(?i)FROM\s+(.+?)(?:\s+WHERE|\s+GROUP|\s+ORDER|\s+LIMIT|\s+OFFSET|\s*$)');
    
    -- Extract WHERE clause from the query (if any)
    v_where_clause := substring(p_query FROM '(?i)WHERE\s+(.+?)(?:\s+GROUP|\s+ORDER|\s+LIMIT|\s+OFFSET|\s*$)');
    
    -- Build the column list with privacy controls applied
    FOR v_privacy_settings IN
        SELECT s.schema_name, s.table_name, s.column_name, s.privacy_type, s.privacy_config
        FROM privacy.settings s
        JOIN pg_roles r ON r.rolname = p_role
        LEFT JOIN pg_class c ON c.relname = s.table_name
        LEFT JOIN pg_namespace n ON n.nspname = s.schema_name AND c.relnamespace = n.oid
        WHERE pg_has_role(r.oid, 'privacy_viewer', 'member')
    LOOP
        -- Add privacy control for this column
        v_column_list := v_column_list || 
            CASE WHEN v_column_list <> '' THEN ', ' ELSE '' END ||
            'privacy.mask_data(' || 
            quote_ident(v_privacy_settings.schema_name) || '.' || 
            quote_ident(v_privacy_settings.table_name) || '.' || 
            quote_ident(v_privacy_settings.column_name) || ', ' ||
            quote_literal(v_privacy_settings.privacy_type) || ', ' ||
            quote_literal(v_privacy_settings.privacy_config::text) || '::jsonb) AS ' ||
            quote_ident(v_privacy_settings.column_name);
    END LOOP;
    
    -- Build the final query
    v_sql := 'SELECT ' || v_column_list || ' FROM ' || v_from_clause;
    IF v_where_clause IS NOT NULL THEN
        v_sql := v_sql || ' WHERE ' || v_where_clause;
    END IF;
    
    -- Execute the query with privacy controls
    FOR v_result IN EXECUTE v_sql
    LOOP
        RETURN NEXT v_result;
    END LOOP;
    
    RETURN;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to register a column for privacy controls
CREATE OR REPLACE FUNCTION privacy.register_column(
    p_schema_name TEXT,
    p_table_name TEXT,
    p_column_name TEXT,
    p_privacy_type TEXT,
    p_privacy_config JSONB DEFAULT '{}'::jsonb
) RETURNS VOID AS $$
BEGIN
    -- Validate privacy type
    IF p_privacy_type NOT IN ('full_mask', 'partial_mask', 'format_preserving', 'email_mask', 'truncate') THEN
        RAISE EXCEPTION 'Invalid privacy type: %', p_privacy_type;
    END IF;
    
    -- Insert or update privacy settings
    INSERT INTO privacy.settings (
        schema_name, table_name, column_name, privacy_type, privacy_config
    ) VALUES (
        p_schema_name, p_table_name, p_column_name, p_privacy_type, p_privacy_config
    ) ON CONFLICT (schema_name, table_name, column_name) DO UPDATE
    SET privacy_type = p_privacy_type,
        privacy_config = p_privacy_config,
        updated_at = NOW();
    
    -- Log the registration
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'PRIVACY_CONTROL_REGISTERED', 'INFO', current_user, 
        format('Privacy control registered for %I.%I.%I with type %s', 
               p_schema_name, p_table_name, p_column_name, p_privacy_type)
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to unregister a column from privacy controls
CREATE OR REPLACE FUNCTION privacy.unregister_column(
    p_schema_name TEXT,
    p_table_name TEXT,
    p_column_name TEXT
) RETURNS VOID AS $$
BEGIN
    -- Delete privacy settings
    DELETE FROM privacy.settings
    WHERE schema_name = p_schema_name
      AND table_name = p_table_name
      AND column_name = p_column_name;
    
    -- Log the unregistration
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'PRIVACY_CONTROL_UNREGISTERED', 'INFO', current_user, 
        format('Privacy control unregistered for %I.%I.%I', 
               p_schema_name, p_table_name, p_column_name)
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to generate a data privacy report
CREATE OR REPLACE FUNCTION privacy.generate_report() RETURNS TABLE (
    schema_name TEXT,
    table_name TEXT,
    column_name TEXT,
    privacy_type TEXT,
    privacy_config JSONB,
    tokenization_count BIGINT,
    last_updated TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        s.schema_name,
        s.table_name,
        s.column_name,
        s.privacy_type,
        s.privacy_config,
        COUNT(tm.id) AS tokenization_count,
        s.updated_at AS last_updated
    FROM privacy.settings s
    LEFT JOIN privacy.tokenization_mappings tm
        ON s.schema_name = tm.schema_name
        AND s.table_name = tm.table_name
        AND s.column_name = tm.column_name
    GROUP BY 
        s.schema_name,
        s.table_name,
        s.column_name,
        s.privacy_type,
        s.privacy_config,
        s.updated_at
    ORDER BY 
        s.schema_name,
        s.table_name,
        s.column_name;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create view for privacy settings
CREATE OR REPLACE VIEW privacy.privacy_settings_view AS
SELECT 
    s.id,
    s.schema_name,
    s.table_name,
    s.column_name,
    s.privacy_type,
    s.privacy_config,
    s.created_at,
    s.updated_at,
    COUNT(tm.id) AS tokenization_count
FROM privacy.settings s
LEFT JOIN privacy.tokenization_mappings tm
    ON s.schema_name = tm.schema_name
    AND s.table_name = tm.table_name
    AND s.column_name = tm.column_name
GROUP BY 
    s.id,
    s.schema_name,
    s.table_name,
    s.column_name,
    s.privacy_type,
    s.privacy_config,
    s.created_at,
    s.updated_at
ORDER BY 
    s.schema_name,
    s.table_name,
    s.column_name;

-- Create role for privacy administration
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'privacy_admin') THEN
        CREATE ROLE privacy_admin;
    END IF;
    
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'privacy_viewer') THEN
        CREATE ROLE privacy_viewer;
    END IF;
END
$$;

-- Grant permissions
GRANT USAGE ON SCHEMA privacy TO privacy_admin, privacy_viewer;
GRANT SELECT ON privacy.privacy_settings_view TO privacy_admin, privacy_viewer;
GRANT SELECT, INSERT, UPDATE, DELETE ON privacy.settings TO privacy_admin;
GRANT SELECT ON privacy.tokenization_mappings TO privacy_admin;
GRANT EXECUTE ON FUNCTION privacy.mask_data TO privacy_admin, privacy_viewer;
GRANT EXECUTE ON FUNCTION privacy.tokenize_data TO privacy_admin;
GRANT EXECUTE ON FUNCTION privacy.detokenize_data TO privacy_admin;
GRANT EXECUTE ON FUNCTION privacy.apply_privacy_controls TO privacy_admin, privacy_viewer;
GRANT EXECUTE ON FUNCTION privacy.register_column TO privacy_admin;
GRANT EXECUTE ON FUNCTION privacy.unregister_column TO privacy_admin;
GRANT EXECUTE ON FUNCTION privacy.generate_report TO privacy_admin, privacy_viewer;

-- Grant privacy roles to security roles
GRANT privacy_admin TO security_admin;
GRANT privacy_viewer TO app_user;

-- Example usage:
-- Register a column for privacy controls
-- SELECT privacy.register_column('public', 'customers', 'email', 'email_mask');
-- SELECT privacy.register_column('public', 'customers', 'credit_card', 'format_preserving', '{"format": "XXXX-XXXX-XXXX-XXXX", "visible_end": 4}');
-- SELECT privacy.register_column('public', 'customers', 'ssn', 'format_preserving', '{"format": "XXX-XX-XXXX", "visible_end": 4}');
-- SELECT privacy.register_column('public', 'customers', 'address', 'partial_mask', '{"visible_start": 0, "visible_end": 0, "mask_char": "*"}');
-- SELECT privacy.register_column('public', 'customers', 'phone', 'partial_mask', '{"visible_start": 0, "visible_end": 4, "mask_char": "*"}');

-- Tokenize sensitive data
-- UPDATE public.customers SET credit_card_token = privacy.tokenize_data('public', 'customers', 'credit_card', credit_card);

-- Apply privacy controls to a query
-- SELECT * FROM privacy.apply_privacy_controls('SELECT * FROM public.customers') AS t(id int, name text, email text, credit_card text, ssn text, address text, phone text);

-- Generate privacy report
-- SELECT * FROM privacy.generate_report();
