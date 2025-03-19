\c db_dev;

-- 1) Create table to store AI-driven security threats from blockchain intelligence
CREATE TABLE IF NOT EXISTS blockchain.global_security_threats (
    threat_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    blockchain_transaction TEXT UNIQUE NOT NULL, -- Blockchain transaction reference
    threat_type TEXT NOT NULL,
    source TEXT NOT NULL, -- (e.g., "Ethereum Smart Contract", "Hyperledger Consortium")
    confidence_score NUMERIC CHECK (confidence_score >= 0 AND confidence_score <= 100) DEFAULT 75,
    detection_timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- 2) Function to fetch global AI-detected security threats from blockchain
CREATE OR REPLACE FUNCTION blockchain.fetch_blockchain_security_threats()
RETURNS VOID AS $$
DECLARE blockchain_api_url TEXT := 'https://blockchain-security-network.com/api/global-threats';
DECLARE threats_json JSONB;
BEGIN
    -- Fetch blockchain-recorded security threats
    threats_json := (SELECT http_get(blockchain_api_url));

    -- Validate and insert threats into PostgreSQL
    INSERT INTO blockchain.global_security_threats (blockchain_transaction, threat_type, source, confidence_score)
    SELECT
        transaction,
        threat_type,
        source,
        confidence_score
    FROM jsonb_to_recordset(threats_json) AS x(transaction TEXT, threat_type TEXT, source TEXT, confidence_score NUMERIC)
    WHERE EXISTS (
        SELECT 1 FROM threat_intelligence.trusted_sources WHERE source = x.source
    );

    -- Log blockchain threat ingestion
    INSERT INTO logs.notification_log (event_type, event_source, details, logged_by, logged_at)
    VALUES ('Fetched Blockchain Security Threats', 'blockchain.fetch_blockchain_security_threats', json_build_object('timestamp', NOW()), 'system', NOW());
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 3) Automate threat ingestion every 6 hours
SELECT cron.schedule('0 */6 * * *', 'SELECT blockchain.fetch_blockchain_security_threats();');
