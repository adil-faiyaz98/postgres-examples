-- PostgreSQL Data Classification System
-- This script implements a comprehensive data classification system for the PostgreSQL Security Framework

\c db_dev;

-- Create schema for data classification
CREATE SCHEMA IF NOT EXISTS data_classification;

-- Create table for storing classification levels
CREATE TABLE IF NOT EXISTS data_classification.levels (
    id SERIAL PRIMARY KEY,
    level_name TEXT NOT NULL UNIQUE,
    level_description TEXT NOT NULL,
    level_order INTEGER NOT NULL,
    security_controls JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create table for storing data categories
CREATE TABLE IF NOT EXISTS data_classification.categories (
    id SERIAL PRIMARY KEY,
    category_name TEXT NOT NULL UNIQUE,
    category_description TEXT NOT NULL,
    regulatory_references JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create table for storing column classifications
CREATE TABLE IF NOT EXISTS data_classification.column_classifications (
    id SERIAL PRIMARY KEY,
    schema_name TEXT NOT NULL,
    table_name TEXT NOT NULL,
    column_name TEXT NOT NULL,
    level_id INTEGER NOT NULL REFERENCES data_classification.levels(id),
    category_id INTEGER NOT NULL REFERENCES data_classification.categories(id),
    justification TEXT,
    classified_by TEXT NOT NULL,
    classified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_reviewed_by TEXT,
    last_reviewed_at TIMESTAMPTZ,
    UNIQUE(schema_name, table_name, column_name)
);

-- Create table for storing table classifications
CREATE TABLE IF NOT EXISTS data_classification.table_classifications (
    id SERIAL PRIMARY KEY,
    schema_name TEXT NOT NULL,
    table_name TEXT NOT NULL,
    level_id INTEGER NOT NULL REFERENCES data_classification.levels(id),
    category_id INTEGER NOT NULL REFERENCES data_classification.categories(id),
    justification TEXT,
    classified_by TEXT NOT NULL,
    classified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_reviewed_by TEXT,
    last_reviewed_at TIMESTAMPTZ,
    UNIQUE(schema_name, table_name)
);

-- Create table for storing classification rules
CREATE TABLE IF NOT EXISTS data_classification.rules (
    id SERIAL PRIMARY KEY,
    rule_name TEXT NOT NULL UNIQUE,
    rule_description TEXT NOT NULL,
    rule_pattern TEXT NOT NULL,
    level_id INTEGER NOT NULL REFERENCES data_classification.levels(id),
    category_id INTEGER NOT NULL REFERENCES data_classification.categories(id),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create table for storing classification scan results
CREATE TABLE IF NOT EXISTS data_classification.scan_results (
    id SERIAL PRIMARY KEY,
    scan_id UUID NOT NULL,
    schema_name TEXT NOT NULL,
    table_name TEXT NOT NULL,
    column_name TEXT NOT NULL,
    rule_id INTEGER NOT NULL REFERENCES data_classification.rules(id),
    match_count INTEGER NOT NULL,
    sample_matches JSONB,
    scan_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create index on scan results for faster lookups
CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id
ON data_classification.scan_results (scan_id);

-- Create function to classify a column
CREATE OR REPLACE FUNCTION data_classification.classify_column(
    p_schema_name TEXT,
    p_table_name TEXT,
    p_column_name TEXT,
    p_level_name TEXT,
    p_category_name TEXT,
    p_justification TEXT DEFAULT NULL
) RETURNS VOID AS $$
DECLARE
    v_level_id INTEGER;
    v_category_id INTEGER;
BEGIN
    -- Get level ID
    SELECT id INTO v_level_id
    FROM data_classification.levels
    WHERE level_name = p_level_name;
    
    IF v_level_id IS NULL THEN
        RAISE EXCEPTION 'Classification level "%" not found', p_level_name;
    END IF;
    
    -- Get category ID
    SELECT id INTO v_category_id
    FROM data_classification.categories
    WHERE category_name = p_category_name;
    
    IF v_category_id IS NULL THEN
        RAISE EXCEPTION 'Classification category "%" not found', p_category_name;
    END IF;
    
    -- Insert or update column classification
    INSERT INTO data_classification.column_classifications (
        schema_name,
        table_name,
        column_name,
        level_id,
        category_id,
        justification,
        classified_by
    ) VALUES (
        p_schema_name,
        p_table_name,
        p_column_name,
        v_level_id,
        v_category_id,
        p_justification,
        current_user
    ) ON CONFLICT (schema_name, table_name, column_name) DO UPDATE
    SET level_id = v_level_id,
        category_id = v_category_id,
        justification = p_justification,
        classified_by = current_user,
        classified_at = NOW();
    
    -- Log the classification
    INSERT INTO logs.notification_log (
        event_type,
        severity,
        username,
        message,
        additional_data
    ) VALUES (
        'DATA_CLASSIFICATION',
        'INFO',
        current_user,
        format('Classified column %I.%I.%I as %s (%s)',
               p_schema_name, p_table_name, p_column_name, p_level_name, p_category_name),
        jsonb_build_object(
            'schema_name', p_schema_name,
            'table_name', p_table_name,
            'column_name', p_column_name,
            'level_name', p_level_name,
            'category_name', p_category_name,
            'justification', p_justification
        )
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to classify a table
CREATE OR REPLACE FUNCTION data_classification.classify_table(
    p_schema_name TEXT,
    p_table_name TEXT,
    p_level_name TEXT,
    p_category_name TEXT,
    p_justification TEXT DEFAULT NULL
) RETURNS VOID AS $$
DECLARE
    v_level_id INTEGER;
    v_category_id INTEGER;
BEGIN
    -- Get level ID
    SELECT id INTO v_level_id
    FROM data_classification.levels
    WHERE level_name = p_level_name;
    
    IF v_level_id IS NULL THEN
        RAISE EXCEPTION 'Classification level "%" not found', p_level_name;
    END IF;
    
    -- Get category ID
    SELECT id INTO v_category_id
    FROM data_classification.categories
    WHERE category_name = p_category_name;
    
    IF v_category_id IS NULL THEN
        RAISE EXCEPTION 'Classification category "%" not found', p_category_name;
    END IF;
    
    -- Insert or update table classification
    INSERT INTO data_classification.table_classifications (
        schema_name,
        table_name,
        level_id,
        category_id,
        justification,
        classified_by
    ) VALUES (
        p_schema_name,
        p_table_name,
        v_level_id,
        v_category_id,
        p_justification,
        current_user
    ) ON CONFLICT (schema_name, table_name) DO UPDATE
    SET level_id = v_level_id,
        category_id = v_category_id,
        justification = p_justification,
        classified_by = current_user,
        classified_at = NOW();
    
    -- Log the classification
    INSERT INTO logs.notification_log (
        event_type,
        severity,
        username,
        message,
        additional_data
    ) VALUES (
        'DATA_CLASSIFICATION',
        'INFO',
        current_user,
        format('Classified table %I.%I as %s (%s)',
               p_schema_name, p_table_name, p_level_name, p_category_name),
        jsonb_build_object(
            'schema_name', p_schema_name,
            'table_name', p_table_name,
            'level_name', p_level_name,
            'category_name', p_category_name,
            'justification', p_justification
        )
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to get column classification
CREATE OR REPLACE FUNCTION data_classification.get_column_classification(
    p_schema_name TEXT,
    p_table_name TEXT,
    p_column_name TEXT
) RETURNS TABLE (
    schema_name TEXT,
    table_name TEXT,
    column_name TEXT,
    level_name TEXT,
    level_description TEXT,
    level_order INTEGER,
    category_name TEXT,
    category_description TEXT,
    regulatory_references JSONB,
    security_controls JSONB,
    justification TEXT,
    classified_by TEXT,
    classified_at TIMESTAMPTZ,
    last_reviewed_by TEXT,
    last_reviewed_at TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        cc.schema_name,
        cc.table_name,
        cc.column_name,
        l.level_name,
        l.level_description,
        l.level_order,
        c.category_name,
        c.category_description,
        c.regulatory_references,
        l.security_controls,
        cc.justification,
        cc.classified_by,
        cc.classified_at,
        cc.last_reviewed_by,
        cc.last_reviewed_at
    FROM data_classification.column_classifications cc
    JOIN data_classification.levels l ON cc.level_id = l.id
    JOIN data_classification.categories c ON cc.category_id = c.id
    WHERE cc.schema_name = p_schema_name
      AND cc.table_name = p_table_name
      AND cc.column_name = p_column_name;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to get table classification
CREATE OR REPLACE FUNCTION data_classification.get_table_classification(
    p_schema_name TEXT,
    p_table_name TEXT
) RETURNS TABLE (
    schema_name TEXT,
    table_name TEXT,
    level_name TEXT,
    level_description TEXT,
    level_order INTEGER,
    category_name TEXT,
    category_description TEXT,
    regulatory_references JSONB,
    security_controls JSONB,
    justification TEXT,
    classified_by TEXT,
    classified_at TIMESTAMPTZ,
    last_reviewed_by TEXT,
    last_reviewed_at TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        tc.schema_name,
        tc.table_name,
        l.level_name,
        l.level_description,
        l.level_order,
        c.category_name,
        c.category_description,
        c.regulatory_references,
        l.security_controls,
        tc.justification,
        tc.classified_by,
        tc.classified_at,
        tc.last_reviewed_by,
        tc.last_reviewed_at
    FROM data_classification.table_classifications tc
    JOIN data_classification.levels l ON tc.level_id = l.id
    JOIN data_classification.categories c ON tc.category_id = c.id
    WHERE tc.schema_name = p_schema_name
      AND tc.table_name = p_table_name;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to add a classification rule
CREATE OR REPLACE FUNCTION data_classification.add_rule(
    p_rule_name TEXT,
    p_rule_description TEXT,
    p_rule_pattern TEXT,
    p_level_name TEXT,
    p_category_name TEXT
) RETURNS INTEGER AS $$
DECLARE
    v_level_id INTEGER;
    v_category_id INTEGER;
    v_rule_id INTEGER;
BEGIN
    -- Get level ID
    SELECT id INTO v_level_id
    FROM data_classification.levels
    WHERE level_name = p_level_name;
    
    IF v_level_id IS NULL THEN
        RAISE EXCEPTION 'Classification level "%" not found', p_level_name;
    END IF;
    
    -- Get category ID
    SELECT id INTO v_category_id
    FROM data_classification.categories
    WHERE category_name = p_category_name;
    
    IF v_category_id IS NULL THEN
        RAISE EXCEPTION 'Classification category "%" not found', p_category_name;
    END IF;
    
    -- Insert rule
    INSERT INTO data_classification.rules (
        rule_name,
        rule_description,
        rule_pattern,
        level_id,
        category_id
    ) VALUES (
        p_rule_name,
        p_rule_description,
        p_rule_pattern,
        v_level_id,
        v_category_id
    ) RETURNING id INTO v_rule_id;
    
    -- Log the rule addition
    INSERT INTO logs.notification_log (
        event_type,
        severity,
        username,
        message,
        additional_data
    ) VALUES (
        'DATA_CLASSIFICATION_RULE',
        'INFO',
        current_user,
        format('Added classification rule "%s" for level %s (%s)',
               p_rule_name, p_level_name, p_category_name),
        jsonb_build_object(
            'rule_name', p_rule_name,
            'rule_description', p_rule_description,
            'rule_pattern', p_rule_pattern,
            'level_name', p_level_name,
            'category_name', p_category_name
        )
    );
    
    RETURN v_rule_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to scan a column for sensitive data
CREATE OR REPLACE FUNCTION data_classification.scan_column(
    p_schema_name TEXT,
    p_table_name TEXT,
    p_column_name TEXT,
    p_scan_id UUID DEFAULT gen_random_uuid()
) RETURNS TABLE (
    rule_id INTEGER,
    rule_name TEXT,
    level_name TEXT,
    category_name TEXT,
    match_count INTEGER,
    sample_matches JSONB
) AS $$
DECLARE
    v_rule RECORD;
    v_match_count INTEGER;
    v_sample_matches JSONB;
    v_query TEXT;
BEGIN
    -- Loop through active rules
    FOR v_rule IN
        SELECT r.id, r.rule_name, r.rule_pattern, l.level_name, c.category_name
        FROM data_classification.rules r
        JOIN data_classification.levels l ON r.level_id = l.id
        JOIN data_classification.categories c ON r.category_id = c.id
        WHERE r.is_active = TRUE
    LOOP
        -- Build query to count matches
        v_query := format(
            'SELECT COUNT(*) FROM %I.%I WHERE %I ~ %L',
            p_schema_name, p_table_name, p_column_name, v_rule.rule_pattern
        );
        
        -- Execute query
        EXECUTE v_query INTO v_match_count;
        
        -- If matches found, get sample matches
        IF v_match_count > 0 THEN
            -- Build query to get sample matches
            v_query := format(
                'SELECT jsonb_agg(sample) FROM (SELECT %I AS match FROM %I.%I WHERE %I ~ %L LIMIT 5) AS sample',
                p_column_name, p_schema_name, p_table_name, p_column_name, v_rule.rule_pattern
            );
            
            -- Execute query
            EXECUTE v_query INTO v_sample_matches;
            
            -- Store scan result
            INSERT INTO data_classification.scan_results (
                scan_id,
                schema_name,
                table_name,
                column_name,
                rule_id,
                match_count,
                sample_matches
            ) VALUES (
                p_scan_id,
                p_schema_name,
                p_table_name,
                p_column_name,
                v_rule.id,
                v_match_count,
                v_sample_matches
            );
            
            -- Return result
            rule_id := v_rule.id;
            rule_name := v_rule.rule_name;
            level_name := v_rule.level_name;
            category_name := v_rule.category_name;
            match_count := v_match_count;
            sample_matches := v_sample_matches;
            
            RETURN NEXT;
        END IF;
    END LOOP;
    
    RETURN;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to scan a table for sensitive data
CREATE OR REPLACE FUNCTION data_classification.scan_table(
    p_schema_name TEXT,
    p_table_name TEXT,
    p_scan_id UUID DEFAULT gen_random_uuid()
) RETURNS TABLE (
    column_name TEXT,
    rule_id INTEGER,
    rule_name TEXT,
    level_name TEXT,
    category_name TEXT,
    match_count INTEGER,
    sample_matches JSONB
) AS $$
DECLARE
    v_column RECORD;
    v_result RECORD;
BEGIN
    -- Loop through columns in the table
    FOR v_column IN
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = p_schema_name
          AND table_name = p_table_name
          AND data_type IN ('character varying', 'text', 'character')
    LOOP
        -- Scan each column
        FOR v_result IN
            SELECT * FROM data_classification.scan_column(
                p_schema_name,
                p_table_name,
                v_column.column_name,
                p_scan_id
            )
        LOOP
            -- Return result
            column_name := v_column.column_name;
            rule_id := v_result.rule_id;
            rule_name := v_result.rule_name;
            level_name := v_result.level_name;
            category_name := v_result.category_name;
            match_count := v_result.match_count;
            sample_matches := v_result.sample_matches;
            
            RETURN NEXT;
        END LOOP;
    END LOOP;
    
    RETURN;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to generate a data classification report
CREATE OR REPLACE FUNCTION data_classification.generate_report() RETURNS TABLE (
    schema_name TEXT,
    table_name TEXT,
    column_name TEXT,
    level_name TEXT,
    category_name TEXT,
    classified_by TEXT,
    classified_at TIMESTAMPTZ,
    last_reviewed_at TIMESTAMPTZ,
    regulatory_references JSONB,
    security_controls JSONB
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        cc.schema_name,
        cc.table_name,
        cc.column_name,
        l.level_name,
        c.category_name,
        cc.classified_by,
        cc.classified_at,
        cc.last_reviewed_at,
        c.regulatory_references,
        l.security_controls
    FROM data_classification.column_classifications cc
    JOIN data_classification.levels l ON cc.level_id = l.id
    JOIN data_classification.categories c ON cc.category_id = c.id
    ORDER BY
        l.level_order DESC,
        cc.schema_name,
        cc.table_name,
        cc.column_name;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to review a classification
CREATE OR REPLACE FUNCTION data_classification.review_classification(
    p_schema_name TEXT,
    p_table_name TEXT,
    p_column_name TEXT DEFAULT NULL
) RETURNS VOID AS $$
BEGIN
    IF p_column_name IS NOT NULL THEN
        -- Review column classification
        UPDATE data_classification.column_classifications
        SET last_reviewed_by = current_user,
            last_reviewed_at = NOW()
        WHERE schema_name = p_schema_name
          AND table_name = p_table_name
          AND column_name = p_column_name;
        
        -- Log the review
        INSERT INTO logs.notification_log (
            event_type,
            severity,
            username,
            message
        ) VALUES (
            'DATA_CLASSIFICATION_REVIEW',
            'INFO',
            current_user,
            format('Reviewed classification for column %I.%I.%I',
                   p_schema_name, p_table_name, p_column_name)
        );
    ELSE
        -- Review table classification
        UPDATE data_classification.table_classifications
        SET last_reviewed_by = current_user,
            last_reviewed_at = NOW()
        WHERE schema_name = p_schema_name
          AND table_name = p_table_name;
        
        -- Log the review
        INSERT INTO logs.notification_log (
            event_type,
            severity,
            username,
            message
        ) VALUES (
            'DATA_CLASSIFICATION_REVIEW',
            'INFO',
            current_user,
            format('Reviewed classification for table %I.%I',
                   p_schema_name, p_table_name)
        );
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create view for classification overview
CREATE OR REPLACE VIEW data_classification.classification_overview AS
SELECT
    cc.schema_name,
    cc.table_name,
    cc.column_name,
    l.level_name,
    l.level_order,
    c.category_name,
    cc.classified_by,
    cc.classified_at,
    cc.last_reviewed_at,
    CASE
        WHEN cc.last_reviewed_at IS NULL THEN 'Never'
        WHEN cc.last_reviewed_at < NOW() - INTERVAL '1 year' THEN 'Overdue'
        ELSE 'Current'
    END AS review_status
FROM data_classification.column_classifications cc
JOIN data_classification.levels l ON cc.level_id = l.id
JOIN data_classification.categories c ON cc.category_id = c.id
ORDER BY
    l.level_order DESC,
    cc.schema_name,
    cc.table_name,
    cc.column_name;

-- Create role for data classification administration
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'data_classification_admin') THEN
        CREATE ROLE data_classification_admin;
    END IF;
    
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'data_classification_viewer') THEN
        CREATE ROLE data_classification_viewer;
    END IF;
END
$$;

-- Grant permissions
GRANT USAGE ON SCHEMA data_classification TO data_classification_admin, data_classification_viewer;
GRANT SELECT ON ALL TABLES IN SCHEMA data_classification TO data_classification_admin, data_classification_viewer;
GRANT INSERT, UPDATE, DELETE ON data_classification.levels TO data_classification_admin;
GRANT INSERT, UPDATE, DELETE ON data_classification.categories TO data_classification_admin;
GRANT INSERT, UPDATE, DELETE ON data_classification.column_classifications TO data_classification_admin;
GRANT INSERT, UPDATE, DELETE ON data_classification.table_classifications TO data_classification_admin;
GRANT INSERT, UPDATE, DELETE ON data_classification.rules TO data_classification_admin;
GRANT INSERT ON data_classification.scan_results TO data_classification_admin;
GRANT EXECUTE ON FUNCTION data_classification.classify_column TO data_classification_admin;
GRANT EXECUTE ON FUNCTION data_classification.classify_table TO data_classification_admin;
GRANT EXECUTE ON FUNCTION data_classification.get_column_classification TO data_classification_admin, data_classification_viewer;
GRANT EXECUTE ON FUNCTION data_classification.get_table_classification TO data_classification_admin, data_classification_viewer;
GRANT EXECUTE ON FUNCTION data_classification.add_rule TO data_classification_admin;
GRANT EXECUTE ON FUNCTION data_classification.scan_column TO data_classification_admin;
GRANT EXECUTE ON FUNCTION data_classification.scan_table TO data_classification_admin;
GRANT EXECUTE ON FUNCTION data_classification.generate_report TO data_classification_admin, data_classification_viewer;
GRANT EXECUTE ON FUNCTION data_classification.review_classification TO data_classification_admin;

-- Grant data classification roles to security roles
GRANT data_classification_admin TO security_admin;
GRANT data_classification_viewer TO app_user;

-- Insert default classification levels
INSERT INTO data_classification.levels (level_name, level_description, level_order, security_controls)
VALUES
    ('Public', 'Information that can be freely disclosed to the public', 1, '{
        "encryption": "none",
        "access_control": "standard",
        "audit_logging": "minimal",
        "retention": "standard",
        "masking": "none"
    }'::jsonb),
    ('Internal', 'Information intended for internal use only', 2, '{
        "encryption": "at_rest",
        "access_control": "role_based",
        "audit_logging": "standard",
        "retention": "standard",
        "masking": "none"
    }'::jsonb),
    ('Confidential', 'Sensitive information that requires protection', 3, '{
        "encryption": "at_rest_and_in_transit",
        "access_control": "strict_role_based",
        "audit_logging": "detailed",
        "retention": "extended",
        "masking": "partial"
    }'::jsonb),
    ('Restricted', 'Highly sensitive information with strict access controls', 4, '{
        "encryption": "end_to_end",
        "access_control": "strict_need_to_know",
        "audit_logging": "comprehensive",
        "retention": "extended",
        "masking": "full"
    }'::jsonb)
ON CONFLICT (level_name) DO UPDATE
SET level_description = EXCLUDED.level_description,
    level_order = EXCLUDED.level_order,
    security_controls = EXCLUDED.security_controls,
    updated_at = NOW();

-- Insert default classification categories
INSERT INTO data_classification.categories (category_name, category_description, regulatory_references)
VALUES
    ('General', 'General business information', NULL),
    ('Personal', 'Personal information', '{
        "GDPR": "Article 4(1)",
        "CCPA": "1798.140(o)",
        "HIPAA": "N/A"
    }'::jsonb),
    ('Financial', 'Financial information', '{
        "GDPR": "Article 4(1)",
        "CCPA": "1798.140(o)",
        "PCI-DSS": "Requirement 3",
        "GLBA": "Applicable"
    }'::jsonb),
    ('Health', 'Health information', '{
        "GDPR": "Article 9",
        "CCPA": "1798.140(o)",
        "HIPAA": "Applicable"
    }'::jsonb),
    ('Authentication', 'Authentication information', '{
        "GDPR": "Article 32",
        "NIST": "SP 800-63B"
    }'::jsonb)
ON CONFLICT (category_name) DO UPDATE
SET category_description = EXCLUDED.category_description,
    regulatory_references = EXCLUDED.regulatory_references,
    updated_at = NOW();

-- Insert default classification rules
INSERT INTO data_classification.rules (rule_name, rule_description, rule_pattern, level_id, category_id)
VALUES
    ('Credit Card Number', 'Matches credit card numbers', 
     '(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})',
     (SELECT id FROM data_classification.levels WHERE level_name = 'Restricted'),
     (SELECT id FROM data_classification.categories WHERE category_name = 'Financial')),
     
    ('Social Security Number', 'Matches US Social Security Numbers',
     '(?:\d{3}-\d{2}-\d{4}|\d{9})',
     (SELECT id FROM data_classification.levels WHERE level_name = 'Restricted'),
     (SELECT id FROM data_classification.categories WHERE category_name = 'Personal')),
     
    ('Email Address', 'Matches email addresses',
     '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
     (SELECT id FROM data_classification.levels WHERE level_name = 'Confidential'),
     (SELECT id FROM data_classification.categories WHERE category_name = 'Personal')),
     
    ('Phone Number', 'Matches phone numbers',
     '(?:\+\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}',
     (SELECT id FROM data_classification.levels WHERE level_name = 'Confidential'),
     (SELECT id FROM data_classification.categories WHERE category_name = 'Personal')),
     
    ('Password', 'Matches password fields',
     '(?i)password|passwd|pwd',
     (SELECT id FROM data_classification.levels WHERE level_name = 'Restricted'),
     (SELECT id FROM data_classification.categories WHERE category_name = 'Authentication')),
     
    ('Health Information', 'Matches health-related information',
     '(?i)health|medical|diagnosis|patient|treatment',
     (SELECT id FROM data_classification.levels WHERE level_name = 'Restricted'),
     (SELECT id FROM data_classification.categories WHERE category_name = 'Health'))
ON CONFLICT (rule_name) DO UPDATE
SET rule_description = EXCLUDED.rule_description,
    rule_pattern = EXCLUDED.rule_pattern,
    level_id = EXCLUDED.level_id,
    category_id = EXCLUDED.category_id,
    updated_at = NOW();

-- Example usage:
-- Classify a column
-- SELECT data_classification.classify_column('public', 'customers', 'email', 'Confidential', 'Personal', 'Contains customer email addresses');

-- Classify a table
-- SELECT data_classification.classify_table('public', 'customers', 'Confidential', 'Personal', 'Contains customer information');

-- Get column classification
-- SELECT * FROM data_classification.get_column_classification('public', 'customers', 'email');

-- Scan a column for sensitive data
-- SELECT * FROM data_classification.scan_column('public', 'customers', 'email');

-- Scan a table for sensitive data
-- SELECT * FROM data_classification.scan_table('public', 'customers');

-- Generate a data classification report
-- SELECT * FROM data_classification.generate_report();
