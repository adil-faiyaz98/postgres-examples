\c db_dev;

-- 1) Create table to store PostgreSQL security intelligence on the blockchain
CREATE TABLE IF NOT EXISTS blockchain.security_intelligence (
    block_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    transaction_hash TEXT UNIQUE NOT NULL, -- Hash of the security event on the blockchain
    event_type TEXT NOT NULL,
    event_source TEXT NOT NULL,
    threat_score NUMERIC DEFAULT 50,
    blockchain_timestamp TIMESTAMPTZ DEFAULT NOW()
);
