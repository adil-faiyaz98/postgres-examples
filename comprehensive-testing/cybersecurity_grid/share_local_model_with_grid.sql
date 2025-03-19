\c db_dev;

-- 1) Create function to share trained local AI security models with a global Federated Learning server
CREATE OR REPLACE FUNCTION cybersecurity_grid.share_local_ai_model()
RETURNS VOID AS $$
DECLARE fl_server_url TEXT := 'https://global-cybersecurity-grid.com/api/models';
DECLARE model_payload TEXT;
BEGIN
    -- Select latest trained AI model from PostgreSQL instance
    SELECT model_parameters INTO model_payload
    FROM cybersecurity_grid.local_ai_models
    ORDER BY trained_on DESC
    LIMIT 1;

    -- Send trained model to global AI security aggregator
    PERFORM http_post(fl_server_url, 'application/json', json_build_object('model', model_payload));

    -- Log federated AI model sharing
    INSERT INTO logs.notification_log (event_type, event_source, details, logged_by, logged_at)
    VALUES ('Federated AI Model Shared', 'cybersecurity_grid.share_local_ai_model', json_build_object('timestamp', NOW()), 'system', NOW());
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Automate AI model sharing every 12 hours
SELECT cron.schedule('0 */12 * * *', 'SELECT cybersecurity_grid.share_local_ai_model();');

\c db_dev;

-- 3) Create table to store PostgreSQL nodes participating in the cybersecurity grid
CREATE TABLE IF NOT EXISTS global_cybersecurity_grid.nodes (
    node_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    node_address TEXT UNIQUE NOT NULL,
    region TEXT NOT NULL,  -- (e.g., "North America", "Europe")
    node_status TEXT DEFAULT 'ACTIVE', -- ACTIVE, OFFLINE, COMPROMISED
    last_updated TIMESTAMPTZ DEFAULT NOW()
);

-- 4) Function to register PostgreSQL nodes as security participants in the grid
CREATE OR REPLACE FUNCTION global_cybersecurity_grid.register_node(node_address TEXT, region TEXT)
RETURNS VOID AS $$
BEGIN
    INSERT INTO global_cybersecurity_grid.nodes (node_address, region)
    VALUES (node_address, region)
    ON CONFLICT (node_address) DO UPDATE
    SET last_updated = NOW();
END;
$$ LANGUAGE plpgsql;


-- 3) Create function to share trained local AI security models with a global Federated Learning server
CREATE OR REPLACE FUNCTION global_cybersecurity_grid.share_local_ai_model()
RETURNS VOID AS $$
DECLARE fl_server_url TEXT := 'https://global-cybersecurity-grid.com/api/models';
DECLARE model_payload TEXT;
BEGIN
    -- Select latest trained AI model from PostgreSQL instance
    SELECT model_parameters INTO model_payload
    FROM global_cybersecurity_grid.federated_ai_models
    ORDER BY trained_on DESC
    LIMIT 1;

    -- Send trained model to global AI security aggregator
    PERFORM http_post(fl_server_url, 'application/json', json_build_object('model', model_payload));

    -- Log federated AI model sharing
    INSERT INTO logs.notification_log (event_type, event_source, details, logged_by, logged_at)
    VALUES ('Federated AI Model Shared', 'global_cybersecurity_grid.share_local_ai_model', json_build_object('timestamp', NOW()), 'system', NOW());
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 4) Automate AI model sharing every 12 hours
SELECT cron.schedule('0 */12 * * *', 'SELECT global_cybersecurity_grid.share_local_ai_model();');


