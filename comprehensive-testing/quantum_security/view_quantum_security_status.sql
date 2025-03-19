\c db_dev;

-- View Post-Quantum Cryptographic (PQC) keys assigned to PostgreSQL users
SELECT user_id, created_at
FROM quantum_security.pqc_keys
ORDER BY created_at DESC
LIMIT 50;

-- View encrypted PostgreSQL data transactions
SELECT * FROM logs.notification_log
WHERE event_type = 'Quantum Encryption Applied'
ORDER BY logged_at DESC
LIMIT 50;

-- View Zero-Knowledge Proof security verifications
SELECT * FROM quantum_security.zkp_verifications
ORDER BY verified_at DESC
LIMIT 50;
