\c db_dev;

-- 1) Create table to store received global AI security models
CREATE TABLE IF NOT EXISTS cybersecurity_grid.global_security_models (
    model_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    received_on TIMESTAMPTZ DEFAULT NOW(),
    aggregated_parameters JSONB NOT NULL,  -- Aggregated AI model from all nodes
    global_accuracy NUMERIC(5,2)
);

-- 2) Function to fetch AI security model updates from the global cybersecurity grid
CREATE OR REPLACE FUNCTION cybersecurity_grid.fetch_global_ai_security_model()
RETURNS VOID AS $$
DECLARE fl_server_url TEXT := 'https://global-cybersecurity-grid.com/api/models';
DECLARE global_model JSONB;
BEGIN
    -- Fetch latest aggregated AI security model
    global_model := (SELECT http_get(fl_server_url));

    -- Store global AI security model in PostgreSQL
    INSERT INTO cybersecurity_grid.global_security_models (aggregated_parameters)
    VALUES (global_model);

    -- Log global AI security model update
    INSERT INTO logs.notification_log (event_type, event_source, details, logged_by, logged_at)
    VALUES ('Global AI Security Model Received', 'cybersecurity_grid.fetch_global_ai_security_model', json_build_object('timestamp', NOW()), 'system', NOW());
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 3) Automate AI security model updates every 24 hours
SELECT cron.schedule('0 0 * * *', 'SELECT cybersecurity_grid.fetch_global_ai_security_model();');
