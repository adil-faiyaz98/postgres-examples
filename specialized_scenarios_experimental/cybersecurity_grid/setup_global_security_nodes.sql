\c db_dev;

-- 1) Create table to register PostgreSQL security nodes in the global cybersecurity grid
CREATE TABLE IF NOT EXISTS cybersecurity_grid.global_security_nodes (
    node_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    node_address TEXT UNIQUE NOT NULL,
    geographic_region TEXT NOT NULL,  -- (e.g., "North America", "Europe")
    node_status TEXT DEFAULT 'ACTIVE', -- ACTIVE, OFFLINE, COMPROMISED
    last_updated TIMESTAMPTZ DEFAULT NOW()
);

-- 2) Function to register PostgreSQL instances as security nodes in the cybersecurity grid
CREATE OR REPLACE FUNCTION cybersecurity_grid.register_global_node(node_address TEXT, geographic_region TEXT)
RETURNS VOID AS $$
BEGIN
    INSERT INTO cybersecurity_grid.global_security_nodes (node_address, geographic_region)
    VALUES (node_address, geographic_region)
    ON CONFLICT (node_address) DO UPDATE
    SET last_updated = NOW();
END;
$$ LANGUAGE plpgsql;
