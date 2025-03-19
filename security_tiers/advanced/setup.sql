-- PostgreSQL Advanced Security Tier Setup
-- This tier adds AI-driven security, encryption, and high compliance features

-- 0. Apply standard tier first (ensure it's already run)
\i ../standard/setup.sql

-- 1. Advanced security extensions
CREATE EXTENSION IF NOT EXISTS plpython3u;  -- For AI/ML integrations
CREATE EXTENSION IF NOT EXISTS hstore;      -- For storing ML model metadata
CREATE EXTENSION IF NOT EXISTS pg_trgm;     -- For query similarity analysis

-- 2. Advanced encryption setup
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE SCHEMA IF NOT EXISTS encrypted_data;
GRANT USAGE ON SCHEMA encrypted_data TO security_admin;

-- 3. Create function for transparent data encryption
CREATE OR REPLACE FUNCTION encrypted_data.encrypt_sensitive_data(data text, key_id text)
RETURNS text AS $$
DECLARE
    encryption_key text;
BEGIN
    -- In production, retrieve key from a secure key management service
    SELECT 'REPLACE_WITH_SECURE_KEY' INTO encryption_key; 
    
    RETURN encode(
        pgp_sym_encrypt(
            data,
            encryption_key,
            'cipher-algo=aes256'
        ),
        'base64'
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION encrypted_data.decrypt_sensitive_data(encrypted_data text, key_id text)
RETURNS text AS $$
DECLARE
    encryption_key text;
BEGIN
    -- In production, retrieve key from a secure key management service
    SELECT 'REPLACE_WITH_SECURE_KEY' INTO encryption_key;
    
    RETURN pgp_sym_decrypt(
        decode(encrypted_data, 'base64'),
        encryption_key
    );
EXCEPTION
    WHEN OTHERS THEN
        RETURN NULL; -- Handle decryption failure gracefully
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 4. Create AI/ML security schema
CREATE SCHEMA IF NOT EXISTS ai_security;
GRANT USAGE ON SCHEMA ai_security TO security_admin;

-- 5. Create tables for AI-driven security
CREATE TABLE IF NOT EXISTS ai_security.ml_models (
    model_id SERIAL PRIMARY KEY,
    model_name TEXT NOT NULL,
    model_type TEXT NOT NULL,
    model_parameters JSONB,
    training_accuracy NUMERIC,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_updated TIMESTAMPTZ DEFAULT NOW(),
    active BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS ai_security.security_predictions (
    prediction_id BIGSERIAL PRIMARY KEY,
    model_id INTEGER REFERENCES ai_security.ml_models(model_id),
    event_data JSONB NOT NULL,
    risk_score NUMERIC NOT NULL,
    confidence NUMERIC NOT NULL,
    prediction_time TIMESTAMPTZ DEFAULT NOW(),
    features_used JSONB,
    explanation TEXT
);

-- 6. Create AI anomaly detection function
CREATE OR REPLACE FUNCTION ai_security.detect_anomalies(
    p_username TEXT,
    p_database TEXT,
    p_query TEXT,
    p_execution_time NUMERIC,
    p_client_addr INET
) RETURNS NUMERIC AS $$
import json
import numpy as np
from sklearn.ensemble import IsolationForest

# This is a simplified example - in production, would load model from disk/DB
# or use a more sophisticated online learning approach

# Extract features from the input
features = {
    'query_length': len(p_query),
    'execution_time': float(p_execution_time),
    'hour_of_day': plpy.execute("SELECT EXTRACT(HOUR FROM NOW())")[0]['date_part'],
    'is_weekend': plpy.execute("SELECT EXTRACT(DOW FROM NOW()) IN (0, 6)")[0]['?column?'],
    'query_contains_select': 'SELECT' in p_query.upper(),
    'query_contains_insert': 'INSERT' in p_query.upper(),
    'query_contains_update': 'UPDATE' in p_query.upper(),
    'query_contains_delete': 'DELETE' in p_query.upper()
}

# Convert to feature vector
X = np.array([list(features.values())])

# Create and train model (in prod, would use pre-trained model)
model = IsolationForest(n_estimators=100, contamination=0.05)

# Get historical data to train the model
query = """
SELECT 
    LENGTH(query) as query_length,
    execution_time,
    EXTRACT(HOUR FROM detection_time) as hour_of_day,
    EXTRACT(DOW FROM detection_time) IN (0, 6) as is_weekend,
    query_text ILIKE '%SELECT%' as contains_select,
    query_text ILIKE '%INSERT%' as contains_insert,
    query_text ILIKE '%UPDATE%' as contains_update,
    query_text ILIKE '%DELETE%' as contains_delete
FROM 
    security_monitoring.anomalies
WHERE 
    username = %s
    AND database_name = %s
LIMIT 1000
"""
plan = plpy.prepare(query, ["text", "text"])
result = plpy.execute(plan, [p_username, p_database])

# Convert historical data to numpy array
if len(result) > 10:  # Only if we have enough historical data
    historical_data = np.array([[
        r['query_length'],
        r['execution_time'],
        r['hour_of_day'],
        r['is_weekend'],
        r['contains_select'],
        r['contains_insert'], 
        r['contains_update'],
        r['contains_delete']
    ] for r in result])
    
    # Train model on historical data
    model.fit(historical_data)
    
    # Predict anomaly score (-1 for anomalies, 1 for normal)
    prediction = model.predict(X)[0]
    score = model.score_samples(X)[0]
    
    # Convert to risk score (0-100)
    risk_score = min(100, max(0, int((1 - score) * 100)))
    
    # Log prediction
    log_query = """
    INSERT INTO ai_security.security_predictions 
    (model_id, event_data, risk_score, confidence, features_used)
    VALUES (
        1, 
        %s,
        %s,
        %s,
        %s
    )
    """
    log_plan = plpy.prepare(log_query, ["json", "numeric", "numeric", "json"])
    plpy.execute(log_plan, [
        json.dumps({
            'username': p_username,
            'database': p_database,
            'query': p_query,
            'client_addr': str(p_client_addr)
        }),
        risk_score,
        abs(score),
        json.dumps(features)
    ])
    
    return risk_score
else:
    # Not enough data for accurate prediction
    return 50  # neutral risk score
$$ LANGUAGE plpython3u SECURITY DEFINER;

-- 7. Create trigger for AI anomaly detection on each query
CREATE OR REPLACE FUNCTION ai_security.query_security_check()
RETURNS TRIGGER AS $$
DECLARE
    risk_score NUMERIC;
BEGIN
    -- Call AI function to evaluate query risk
    SELECT ai_security.detect_anomalies(
        current_user,
        current_database(),
        current_query(),
        (EXTRACT(EPOCH FROM (clock_timestamp() - statement_timestamp()))),
        inet_client_addr()
    ) INTO risk_score;
    
    -- Log high-risk queries (score > 80)
    IF risk_score > 80 THEN
        INSERT INTO security_monitoring.anomalies (
            username, 
            database_name, 
            query_signature, 
            execution_time,
            expected_execution_time,
            deviation_factor,
            query_text,
            action_taken
        ) VALUES (
            current_user,
            current_database(),
            md5(current_query()),
            (EXTRACT(EPOCH FROM (clock_timestamp() - statement_timestamp()))),
            0, -- We don't have an expected time in this case
            risk_score / 100.0,
            current_query(),
            'Flagged by AI security'
        );
        
        -- For very high risk, could abort transaction
        -- IF risk_score > 95 THEN
        --     RAISE EXCEPTION 'Query blocked by AI security due to high risk score: %', risk_score;
        -- END IF;
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 8. Enhanced security settings
ALTER SYSTEM SET log_statement = 'all';  -- Log all statements
ALTER SYSTEM SET log_min_duration_statement = '0';  -- Log all queries
ALTER SYSTEM SET log_duration = 'on';
ALTER SYSTEM SET ssl_ciphers = 'HIGH:!aNULL:!MD5';  -- Only high-strength ciphers

-- 9. Row-Level Security for sensitive tables (example)
CREATE TABLE IF NOT EXISTS sensitive_data.customer_data (
    customer_id UUID PRIMARY KEY,
    first_name TEXT,
    last_name TEXT,
    ssn TEXT,
    credit_card TEXT,
    address TEXT,
    created_by TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE sensitive_data.customer_data ENABLE ROW LEVEL SECURITY;

CREATE POLICY customer_data_isolation_policy ON sensitive_data.customer_data
    USING (created_by = current_user OR 
           current_user IN (SELECT current_setting('security.admin_users', true)));

-- 10. Include additional production-ready security features
\i additional_security.sql

-- 11. Reload PostgreSQL configuration
SELECT pg_reload_conf();

-- 12. Initial ML model setup
INSERT INTO ai_security.ml_models 
(model_name, model_type, model_parameters, training_accuracy, active)
VALUES 
('SecurityAnomalyDetector', 'IsolationForest', 
 '{"n_estimators": 100, "contamination": 0.05, "random_state": 42}', 
 0.95, true)
ON CONFLICT DO NOTHING; 