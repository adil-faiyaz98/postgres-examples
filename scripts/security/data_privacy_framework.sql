-- Comprehensive Data Privacy Framework for PostgreSQL Security Framework
CREATE SCHEMA IF NOT EXISTS privacy;

-- Create extension for machine learning
CREATE EXTENSION IF NOT EXISTS plpython3u;

-- Table for storing PII detection results
CREATE TABLE IF NOT EXISTS privacy.pii_detection_results (
    id SERIAL PRIMARY KEY,
    schema_name TEXT NOT NULL,
    table_name TEXT NOT NULL,
    column_name TEXT NOT NULL,
    confidence_score NUMERIC(5,2) NOT NULL,
    pii_type TEXT NOT NULL,
    sample_data TEXT,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed BOOLEAN NOT NULL DEFAULT FALSE,
    reviewed_by TEXT,
    reviewed_at TIMESTAMPTZ,
    UNIQUE(schema_name, table_name, column_name, pii_type)
);

-- Table for storing data masking rules
CREATE TABLE IF NOT EXISTS privacy.masking_rules (
    id SERIAL PRIMARY KEY,
    schema_name TEXT NOT NULL,
    table_name TEXT NOT NULL,
    column_name TEXT NOT NULL,
    masking_type TEXT NOT NULL,
    masking_parameters JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE(schema_name, table_name, column_name)
);

-- Table for storing consent rules
CREATE TABLE IF NOT EXISTS privacy.consent_rules (
    id SERIAL PRIMARY KEY,
    consent_type TEXT NOT NULL,
    data_category TEXT NOT NULL,
    processing_purpose TEXT NOT NULL,
    is_allowed BOOLEAN NOT NULL,
    legal_basis TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(consent_type, data_category, processing_purpose)
);

-- Table for storing user consent
CREATE TABLE IF NOT EXISTS privacy.user_consent (
    id SERIAL PRIMARY KEY,
    user_id TEXT NOT NULL,
    consent_type TEXT NOT NULL,
    data_category TEXT NOT NULL,
    processing_purpose TEXT NOT NULL,
    is_granted BOOLEAN NOT NULL,
    granted_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    consent_version TEXT NOT NULL,
    consent_record_id TEXT NOT NULL,
    UNIQUE(user_id, consent_type, data_category, processing_purpose)
);

-- Function to detect PII in database columns
CREATE OR REPLACE FUNCTION privacy.detect_pii() RETURNS SETOF privacy.pii_detection_results AS $$
import re
import json

# Define PII patterns
pii_patterns = {
    'EMAIL': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
    'PHONE_NUMBER': r'^\+?[0-9]{10,15}$',
    'SSN': r'^(?!000|666|9)[0-9]{3}-?(?!00)[0-9]{2}-?(?!0000)[0-9]{4}$',
    'CREDIT_CARD': r'^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})$',
    'IP_ADDRESS': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
    'DATE_OF_BIRTH': r'^(?:19|20)\d\d-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])$',
    'NAME': r'^[A-Z][a-z]+(?: [A-Z][a-z]+)+$'
}

# Get all tables and columns
tables = plpy.execute("""
    SELECT 
        table_schema AS schema_name,
        table_name,
        column_name,
        data_type
    FROM information_schema.columns
    WHERE table_schema NOT IN ('pg_catalog', 'information_schema', 'privacy')
      AND data_type IN ('character varying', 'text', 'character')
""")

# Check each column for PII
for table in tables:
    schema = table['schema_name']
    table_name = table['table_name']
    column = table['column_name']
    
    # Skip columns that are likely not PII based on name
    if column.lower() in ('id', 'created_at', 'updated_at', 'deleted_at'):
        continue
    
    # Get sample data
    try:
        sample_data = plpy.execute(f"""
            SELECT {column} AS value
            FROM {schema}.{table_name}
            WHERE {column} IS NOT NULL
            LIMIT 100
        """)
    except Exception as e:
        # Skip if we can't query the table
        continue
    
    if not sample_data:
        continue
    
    # Check each PII pattern
    for pii_type, pattern in pii_patterns.items():
        matches = 0
        total = 0
        sample_value = None
        
        for row in sample_data:
            if row['value'] is None:
                continue
                
            value = str(row['value'])
            total += 1
            
            if re.match(pattern, value):
                matches += 1
                if sample_value is None:
                    # Store a redacted sample
                    if len(value) > 4:
                        sample_value = value[:2] + '*' * (len(value) - 4) + value[-2:]
                    else:
                        sample_value = '****'
        
        # Calculate confidence score
        if total > 0:
            confidence = (matches / total) * 100
            
            # Only report if confidence is above threshold
            if confidence > 30:
                # Insert detection result
                result = plpy.execute(f"""
                    INSERT INTO privacy.pii_detection_results (
                        schema_name, table_name, column_name, 
                        confidence_score, pii_type, sample_data
                    ) VALUES (
                        '{schema}', '{table_name}', '{column}',
                        {confidence}, '{pii_type}', {plpy.quote_nullable(sample_value)}
                    )
                    ON CONFLICT (schema_name, table_name, column_name, pii_type) 
                    DO UPDATE SET 
                        confidence_score = {confidence},
                        sample_data = {plpy.quote_nullable(sample_value)},
                        detected_at = NOW()
                    RETURNING *
                """)
                
                # Yield the result
                for r in result:
                    yield r

$$ LANGUAGE plpython3u;

-- Function to apply data masking
CREATE OR REPLACE FUNCTION privacy.apply_masking(
    p_schema_name TEXT,
    p_table_name TEXT,
    p_column_name TEXT,
    p_masking_type TEXT,
    p_masking_parameters JSONB DEFAULT NULL
) RETURNS VOID AS $$
DECLARE
    v_sql TEXT;
    v_view_name TEXT;
    v_masking_expression TEXT;
BEGIN
    -- Generate view name
    v_view_name := p_table_name || '_masked';
    
    -- Generate masking expression based on masking type
    CASE p_masking_type
        WHEN 'full_mask' THEN
            v_masking_expression := format('CASE WHEN %I IS NOT NULL THEN ''********'' ELSE NULL END', p_column_name);
        
        WHEN 'partial_mask' THEN
            v_masking_expression := format(
                'CASE WHEN %I IS NOT NULL THEN 
                    SUBSTRING(%I, 1, %s) || %L || SUBSTRING(%I, LENGTH(%I) - %s + 1, %s) 
                 ELSE NULL END',
                p_column_name, p_column_name, 
                COALESCE((p_masking_parameters->>'visible_start')::INTEGER, 0),
                REPEAT((p_masking_parameters->>'mask_char')::TEXT, 4),
                p_column_name, p_column_name,
                COALESCE((p_masking_parameters->>'visible_end')::INTEGER, 0),
                COALESCE((p_masking_parameters->>'visible_end')::INTEGER, 0)
            );
        
        WHEN 'email_mask' THEN
            v_masking_expression := format(
                'CASE WHEN %I IS NOT NULL THEN 
                    SUBSTRING(%I, 1, 1) || %L || SUBSTRING(%I FROM POSITION(''@'' IN %I))
                 ELSE NULL END',
                p_column_name, p_column_name, '****', p_column_name, p_column_name
            );
        
        WHEN 'randomize' THEN
            v_masking_expression := format('md5(random()::text)');
        
        WHEN 'nullify' THEN
            v_masking_expression := 'NULL';
        
        ELSE
            RAISE EXCEPTION 'Unsupported masking type: %', p_masking_type;
    END CASE;
    
    -- Create or replace masked view
    v_sql := format('
        CREATE OR REPLACE VIEW %I.%I AS
        SELECT 
    ', p_schema_name, v_view_name);
    
    -- Add all columns with masking applied to the specified column
    v_sql := v_sql || (
        SELECT string_agg(
            CASE 
                WHEN column_name = p_column_name THEN
                    format('%s AS %I', v_masking_expression, column_name)
                ELSE
                    format('%I', column_name)
            END,
            ', '
        )
        FROM information_schema.columns
        WHERE table_schema = p_schema_name
          AND table_name = p_table_name
    );
    
    v_sql := v_sql || format('
        FROM %I.%I
    ', p_schema_name, p_table_name);
    
    -- Execute SQL
    EXECUTE v_sql;
    
    -- Store masking rule
    INSERT INTO privacy.masking_rules (
        schema_name, table_name, column_name, 
        masking_type, masking_parameters, created_by
    ) VALUES (
        p_schema_name, p_table_name, p_column_name,
        p_masking_type, p_masking_parameters, current_user
    ) ON CONFLICT (schema_name, table_name, column_name) DO UPDATE
    SET masking_type = p_masking_type,
        masking_parameters = p_masking_parameters,
        created_by = current_user,
        created_at = NOW(),
        is_active = TRUE;
    
    -- Log masking application
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'DATA_MASKING_APPLIED', 'INFO', current_user, 
        format('Applied %s masking to %I.%I.%I', 
               p_masking_type, p_schema_name, p_table_name, p_column_name)
    );
END;
$$ LANGUAGE plpgsql;

-- Function to implement differential privacy
CREATE OR REPLACE FUNCTION privacy.differential_privacy(
    p_value NUMERIC,
    p_epsilon NUMERIC DEFAULT 1.0,
    p_sensitivity NUMERIC DEFAULT 1.0
) RETURNS NUMERIC AS $$
import numpy as np

# Implement Laplace mechanism for differential privacy
def add_laplace_noise(value, epsilon, sensitivity):
    # Calculate scale parameter
    scale = sensitivity / epsilon
    
    # Generate Laplace noise
    noise = np.random.laplace(0, scale)
    
    # Add noise to value
    return value + noise

# Apply differential privacy
if p_value is None:
    return None
    
return add_laplace_noise(p_value, p_epsilon, p_sensitivity)
$$ LANGUAGE plpython3u;

-- Function to check user consent
CREATE OR REPLACE FUNCTION privacy.check_consent(
    p_user_id TEXT,
    p_data_category TEXT,
    p_processing_purpose TEXT
) RETURNS BOOLEAN AS $$
DECLARE
    v_consent_granted BOOLEAN;
BEGIN
    -- Check if user has granted consent
    SELECT is_granted INTO v_consent_granted
    FROM privacy.user_consent
    WHERE user_id = p_user_id
      AND data_category = p_data_category
      AND processing_purpose = p_processing_purpose
      AND (expires_at IS NULL OR expires_at > NOW())
      AND revoked_at IS NULL;
    
    -- If no consent record found, check default consent rules
    IF v_consent_granted IS NULL THEN
        SELECT is_allowed INTO v_consent_granted
        FROM privacy.consent_rules
        WHERE data_category = p_data_category
          AND processing_purpose = p_processing_purpose
        LIMIT 1;
    END IF;
    
    -- Default to false if no consent rule found
    RETURN COALESCE(v_consent_granted, FALSE);
END;
$$ LANGUAGE plpgsql;

-- Function to record user consent
CREATE OR REPLACE FUNCTION privacy.record_consent(
    p_user_id TEXT,
    p_consent_type TEXT,
    p_data_category TEXT,
    p_processing_purpose TEXT,
    p_is_granted BOOLEAN,
    p_consent_version TEXT,
    p_expires_at TIMESTAMPTZ DEFAULT NULL
) RETURNS TEXT AS $$
DECLARE
    v_consent_record_id TEXT;
BEGIN
    -- Generate consent record ID
    v_consent_record_id := gen_random_uuid()::TEXT;
    
    -- Record consent
    INSERT INTO privacy.user_consent (
        user_id, consent_type, data_category, processing_purpose,
        is_granted, granted_at, expires_at, consent_version, consent_record_id
    ) VALUES (
        p_user_id, p_consent_type, p_data_category, p_processing_purpose,
        p_is_granted, 
        CASE WHEN p_is_granted THEN NOW() ELSE NULL END,
        p_expires_at, p_consent_version, v_consent_record_id
    ) ON CONFLICT (user_id, consent_type, data_category, processing_purpose) DO UPDATE
    SET is_granted = p_is_granted,
        granted_at = CASE WHEN p_is_granted THEN NOW() ELSE privacy.user_consent.granted_at END,
        revoked_at = CASE WHEN NOT p_is_granted THEN NOW() ELSE NULL END,
        expires_at = p_expires_at,
        consent_version = p_consent_version,
        consent_record_id = v_consent_record_id;
    
    -- Log consent recording
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'CONSENT_RECORDED', 'INFO', current_user, 
        format('User %s %s consent for %s/%s (version: %s)',
               p_user_id, 
               CASE WHEN p_is_granted THEN 'granted' ELSE 'revoked' END,
               p_data_category, p_processing_purpose, p_consent_version)
    );
    
    RETURN v_consent_record_id;
END;
$$ LANGUAGE plpgsql;

-- Function to create a consent-aware view
CREATE OR REPLACE FUNCTION privacy.create_consent_view(
    p_schema_name TEXT,
    p_table_name TEXT,
    p_user_id_column TEXT,
    p_data_category TEXT,
    p_processing_purpose TEXT
) RETURNS VOID AS $$
DECLARE
    v_sql TEXT;
    v_view_name TEXT;
BEGIN
    -- Generate view name
    v_view_name := p_table_name || '_' || p_processing_purpose;
    
    -- Create consent-aware view
    v_sql := format('
        CREATE OR REPLACE VIEW %I.%I AS
        SELECT *
        FROM %I.%I
        WHERE privacy.check_consent(%I, %L, %L)
    ', p_schema_name, v_view_name, p_schema_name, p_table_name, 
       p_user_id_column, p_data_category, p_processing_purpose);
    
    -- Execute SQL
    EXECUTE v_sql;
    
    -- Log view creation
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'CONSENT_VIEW_CREATED', 'INFO', current_user, 
        format('Created consent-aware view %I.%I for %s/%s',
               p_schema_name, v_view_name, p_data_category, p_processing_purpose)
    );
END;
$$ LANGUAGE plpgsql;

-- Function to get PII summary
CREATE OR REPLACE FUNCTION privacy.get_pii_summary() RETURNS TABLE (
    schema_name TEXT,
    table_name TEXT,
    pii_columns INTEGER,
    highest_confidence NUMERIC,
    pii_types TEXT[],
    has_masking BOOLEAN
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        r.schema_name,
        r.table_name,
        count(DISTINCT r.column_name) AS pii_columns,
        max(r.confidence_score) AS highest_confidence,
        array_agg(DISTINCT r.pii_type) AS pii_types,
        EXISTS (
            SELECT 1 
            FROM privacy.masking_rules m 
            WHERE m.schema_name = r.schema_name 
              AND m.table_name = r.table_name
              AND m.is_active = TRUE
        ) AS has_masking
    FROM privacy.pii_detection_results r
    GROUP BY r.schema_name, r.table_name
    ORDER BY highest_confidence DESC;
END;
$$ LANGUAGE plpgsql;

-- Function to get user consent summary
CREATE OR REPLACE FUNCTION privacy.get_user_consent_summary(
    p_user_id TEXT
) RETURNS TABLE (
    data_category TEXT,
    processing_purpose TEXT,
    is_granted BOOLEAN,
    granted_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    consent_version TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        uc.data_category,
        uc.processing_purpose,
        uc.is_granted,
        uc.granted_at,
        uc.expires_at,
        uc.consent_version
    FROM privacy.user_consent uc
    WHERE uc.user_id = p_user_id
      AND uc.revoked_at IS NULL
    ORDER BY uc.data_category, uc.processing_purpose;
END;
$$ LANGUAGE plpgsql;

-- Grant permissions
GRANT USAGE ON SCHEMA privacy TO security_admin;
GRANT SELECT ON ALL TABLES IN SCHEMA privacy TO security_admin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA privacy TO security_admin;
