\c db_dev;

-- 1) Create table to store PostgreSQL instances participating in the global cyber defense network
CREATE TABLE IF NOT EXISTS global_cyber_defense.defense_nodes (
    node_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    node_address TEXT UNIQUE NOT NULL,
    region TEXT NOT NULL,  -- (e.g., "North America", "Europe")
    node_status TEXT DEFAULT 'ACTIVE', -- ACTIVE, OFFLINE, COMPROMISED
    last_updated TIMESTAMPTZ DEFAULT NOW()
);

-- 2) Function to register PostgreSQL instances as AI-driven security nodes
CREATE OR REPLACE FUNCTION global_cyber_defense.register_node(node_address TEXT, region TEXT)
RETURNS VOID AS $$
BEGIN
    INSERT INTO global_cyber_defense.defense_nodes (node_address, region)
    VALUES (node_address, region)
    ON CONFLICT (node_address) DO UPDATE
    SET last_updated = NOW();
END;
$$ LANGUAGE plpgsql;
