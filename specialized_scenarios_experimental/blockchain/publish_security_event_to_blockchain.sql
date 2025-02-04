\c db_dev;

-- 1) Create function to hash PostgreSQL security logs and publish them to blockchain
CREATE OR REPLACE FUNCTION blockchain.publish_security_event()
RETURNS TRIGGER AS $$
DECLARE blockchain_api_url TEXT := 'https://blockchain-security-network.com/api/transactions';
DECLARE event_hash TEXT;
DECLARE blockchain_payload TEXT;
BEGIN
    -- Generate SHA-256 hash of the security event
    SELECT encode(digest(jsonb_pretty(jsonb_build_object(
        'event_type', NEW.event_type,
        'event_source', NEW.event_source,
        'threat_score', NEW.threat_score
    ))::TEXT, 'sha256'), 'hex') INTO event_hash;

    -- Store the blockchain transaction
    INSERT INTO blockchain.security_intelligence (transaction_hash, event_type, event_source, threat_score)
    VALUES (event_hash, NEW.event_type, NEW.event_source, NEW.threat_score);

    -- Publish hashed event to blockchain
    blockchain_payload := json_build_object(
        'transaction_hash', event_hash,
        'event_type', NEW.event_type,
        'event_source', NEW.event_source,
        'threat_score', NEW.threat_score
    )::TEXT;

    PERFORM http_post(blockchain_api_url, 'application/json', blockchain_payload);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Attach trigger to publish PostgreSQL security intelligence to blockchain
CREATE TRIGGER blockchain_publish_security_event_trigger
AFTER INSERT
ON logs.notification_log
FOR EACH ROW
WHEN (NEW.event_type IN ('SQL Injection Attempt', 'Privilege Escalation Attempt', 'AI-Predicted Insider Threat'))
EXECUTE FUNCTION blockchain.publish_security_event();
