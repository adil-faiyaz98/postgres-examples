\c db_dev;

-- 1) Create function to validate PostgreSQL security incidents using blockchain records
CREATE OR REPLACE FUNCTION blockchain.validate_security_event(event_id UUID)
RETURNS BOOLEAN AS $$
DECLARE stored_hash TEXT;
DECLARE calculated_hash TEXT;
BEGIN
    -- Fetch the stored hash from the blockchain database
    SELECT transaction_hash INTO stored_hash
    FROM blockchain.security_intelligence
    WHERE block_id = event_id;

    -- Recalculate the hash from PostgreSQL logs
    SELECT encode(digest(jsonb_pretty(jsonb_build_object(
        'event_type', event_type,
        'event_source', event_source,
        'threat_score', threat_score
    ))::TEXT, 'sha256'), 'hex')
    INTO calculated_hash
    FROM logs.notification_log
    WHERE log_id = event_id;

    -- Validate against blockchain-stored record
    RETURN calculated_hash = stored_hash;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
