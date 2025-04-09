-- Intermediate Security Tier for PostgreSQL 16
-- This script applies intermediate security settings to a PostgreSQL database

-- 1. Enable encryption for data at rest
-- Install pgcrypto extension for encryption functions
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Create a sample table with encrypted data
CREATE TABLE IF NOT EXISTS encrypted_data (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    credit_card TEXT NOT NULL,
    ssn TEXT NOT NULL
);

-- Create functions to encrypt and decrypt data
CREATE OR REPLACE FUNCTION encrypt_credit_card(credit_card TEXT) 
RETURNS TEXT AS $$
BEGIN
    RETURN pgp_sym_encrypt(credit_card, 'encryption_key');
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION decrypt_credit_card(encrypted_credit_card TEXT) 
RETURNS TEXT AS $$
BEGIN
    RETURN pgp_sym_decrypt(encrypted_credit_card::bytea, 'encryption_key');
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2. Set up audit logging
-- Create audit schema and tables
CREATE SCHEMA IF NOT EXISTS audit;

CREATE TABLE IF NOT EXISTS audit.logged_actions (
    event_id BIGSERIAL PRIMARY KEY,
    schema_name TEXT NOT NULL,
    table_name TEXT NOT NULL,
    user_name TEXT,
    action_tstamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    action TEXT NOT NULL CHECK (action IN ('I','D','U')),
    original_data TEXT,
    new_data TEXT,
    query TEXT
);

-- Create audit trigger function
CREATE OR REPLACE FUNCTION audit.if_modified_func() RETURNS TRIGGER AS $body$
DECLARE
    v_old_data TEXT;
    v_new_data TEXT;
BEGIN
    IF (TG_OP = 'UPDATE') THEN
        v_old_data := ROW(OLD.*);
        v_new_data := ROW(NEW.*);
        INSERT INTO audit.logged_actions (
            schema_name, table_name, user_name, action, original_data, new_data, query
        ) VALUES (
            TG_TABLE_SCHEMA::TEXT, TG_TABLE_NAME::TEXT, session_user::TEXT, 'U', v_old_data, v_new_data, current_query()
        );
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        v_old_data := ROW(OLD.*);
        INSERT INTO audit.logged_actions (
            schema_name, table_name, user_name, action, original_data, query
        ) VALUES (
            TG_TABLE_SCHEMA::TEXT, TG_TABLE_NAME::TEXT, session_user::TEXT, 'D', v_old_data, current_query()
        );
        RETURN OLD;
    ELSIF (TG_OP = 'INSERT') THEN
        v_new_data := ROW(NEW.*);
        INSERT INTO audit.logged_actions (
            schema_name, table_name, user_name, action, new_data, query
        ) VALUES (
            TG_TABLE_SCHEMA::TEXT, TG_TABLE_NAME::TEXT, session_user::TEXT, 'I', v_new_data, current_query()
        );
        RETURN NEW;
    ELSE
        RAISE WARNING '[AUDIT.IF_MODIFIED_FUNC] - Other action occurred: %, at %',TG_OP,now();
        RETURN NULL;
    END IF;
END;
$body$ LANGUAGE plpgsql SECURITY DEFINER;

-- Apply audit trigger to encrypted_data table
DROP TRIGGER IF EXISTS audit_trigger_row ON encrypted_data;
CREATE TRIGGER audit_trigger_row
AFTER INSERT OR UPDATE OR DELETE ON encrypted_data
FOR EACH ROW EXECUTE FUNCTION audit.if_modified_func();

-- 3. Implement Row-Level Security (RLS)
-- Create a sample table with RLS
CREATE TABLE IF NOT EXISTS customer_data (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER NOT NULL,
    customer_name TEXT NOT NULL,
    credit_score INTEGER,
    account_balance NUMERIC(10,2)
);

-- Enable RLS on the table
ALTER TABLE customer_data ENABLE ROW LEVEL SECURITY;

-- Create policies for different roles
CREATE POLICY customer_data_admin_policy ON customer_data
    TO app_admin
    USING (true);  -- Admins can see all rows

CREATE POLICY customer_data_readwrite_policy ON customer_data
    TO app_readwrite
    USING (customer_id % 2 = 0)  -- Example: can only see even customer_ids
    WITH CHECK (customer_id % 2 = 0);

CREATE POLICY customer_data_readonly_policy ON customer_data
    TO app_readonly
    USING (customer_id % 2 = 0);  -- Example: can only see even customer_ids

-- 4. Configure logging for security events
ALTER SYSTEM SET log_connections = 'on';
ALTER SYSTEM SET log_disconnections = 'on';
ALTER SYSTEM SET log_duration = 'on';
ALTER SYSTEM SET log_statement = 'ddl';  -- Log all DDL statements
ALTER SYSTEM SET log_min_error_statement = 'error';  -- Log statements causing errors

-- Apply changes
SELECT pg_reload_conf();
