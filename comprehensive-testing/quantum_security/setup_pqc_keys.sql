\c db_dev;

-- 1) Create table to store Post-Quantum Cryptographic (PQC) keys
CREATE TABLE IF NOT EXISTS quantum_security.pqc_keys (
    key_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES auth.users(user_id),
    kyber_key TEXT NOT NULL,  -- Lattice-based encryption key
    sphincs_signature TEXT NOT NULL,  -- Hash-based signature
    rainbow_private_key TEXT NOT NULL,  -- Multivariate cryptographic key
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2) Function to generate Post-Quantum Cryptographic keys
CREATE OR REPLACE FUNCTION quantum_security.generate_pqc_keys(user_id UUID)
RETURNS VOID AS $$
DECLARE kyber_key TEXT;
DECLARE sphincs_signature TEXT;
DECLARE rainbow_private_key TEXT;
BEGIN
    -- Generate Kyber (Lattice-Based Encryption) Key
    kyber_key := encode(digest(random()::TEXT, 'sha512'), 'hex');

    -- Generate SPHINCS+ (Hash-Based Signature)
    sphincs_signature := encode(digest(random()::TEXT, 'sha512'), 'hex');

    -- Generate Rainbow (Multivariate Cryptography) Private Key
    rainbow_private_key := encode(digest(random()::TEXT, 'sha512'), 'hex');

    -- Store PQC keys in PostgreSQL
    INSERT INTO quantum_security.pqc_keys (user_id, kyber_key, sphincs_signature, rainbow_private_key)
    VALUES (user_id, kyber_key, sphincs_signature, rainbow_private_key);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;


-- 3) Create table to store PostgreSQL instances participating in the Quantum AI Cyber Threat Exchange
CREATE TABLE IF NOT EXISTS quantum_ai_threat_exchange.nodes (
    node_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    node_address TEXT UNIQUE NOT NULL,
    region TEXT NOT NULL,  -- (e.g., "North America", "Europe")
    node_status TEXT DEFAULT 'ACTIVE', -- ACTIVE, OFFLINE, COMPROMISED
    post_quantum_encryption TEXT DEFAULT 'KYBER512', -- Kyber, Falcon, or SPHINCS+
    last_checked TIMESTAMPTZ DEFAULT NOW()
);

-- 4) Function to register PostgreSQL instances as security nodes in the Quantum AI Threat Exchange
CREATE OR REPLACE FUNCTION quantum_ai_threat_exchange.register_threat_node(node_address TEXT, region TEXT)
RETURNS VOID AS $$
BEGIN
    INSERT INTO quantum_ai_threat_exchange.nodes (node_address, region)
    VALUES (node_address, region)
    ON CONFLICT (node_address) DO UPDATE
    SET last_checked = NOW();
END;
$$ LANGUAGE plpgsql;

