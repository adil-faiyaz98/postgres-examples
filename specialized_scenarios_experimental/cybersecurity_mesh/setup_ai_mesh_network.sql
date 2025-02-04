\c db_dev;

-- 1) Create table to store PostgreSQL cybersecurity mesh nodes
CREATE TABLE IF NOT EXISTS cybersecurity_mesh.mesh_nodes (
    node_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    node_address TEXT UNIQUE NOT NULL,
    region TEXT NOT NULL,  -- (e.g., "North America", "Europe")
    node_status TEXT DEFAULT 'ACTIVE', -- ACTIVE, OFFLINE, COMPROMISED
    last_checked TIMESTAMPTZ DEFAULT NOW()
);

-- 2) Function to register PostgreSQL instances as security mesh nodes
CREATE OR REPLACE FUNCTION cybersecurity_mesh.register_mesh_node(node_address TEXT, region TEXT)
RETURNS VOID AS $$
BEGIN
    INSERT INTO cybersecurity_mesh.mesh_nodes (node_address, region)
    VALUES (node_address, region)
    ON CONFLICT (node_address) DO UPDATE
    SET last_checked = NOW();
END;
$$ LANGUAGE plpgsql;
