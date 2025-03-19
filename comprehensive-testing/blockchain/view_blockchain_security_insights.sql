\c db_dev;

-- View PostgreSQL security incidents stored on blockchain
SELECT * FROM blockchain.security_intelligence
ORDER BY blockchain_timestamp DESC
LIMIT 50;

-- View validated PostgreSQL security incidents from blockchain records
SELECT si.*, blockchain.validate_security_event(si.block_id) AS blockchain_verified
FROM blockchain.security_intelligence si
ORDER BY blockchain_timestamp DESC
LIMIT 50;

-- View AI-driven blockchain threat intelligence applied to PostgreSQL security
SELECT * FROM blockchain.global_security_threats
ORDER BY detection_timestamp DESC
LIMIT 50;
