\c db_dev;

-- View smart contract-based PostgreSQL security actions
SELECT * FROM dso.security_smart_contracts
ORDER BY last_updated DESC
LIMIT 50;

-- View PostgreSQL authentication events validated using Zero-Trust
SELECT * FROM dso.zero_trust_authentication
ORDER BY auth_timestamp DESC
LIMIT 50;

-- View PostgreSQL Decentralized Identity (DID) authentication requests
SELECT * FROM dso.decentralized_identities
ORDER BY registered_at DESC
LIMIT 50;
