\c db_dev;

-- 1) Create table to store PostgreSQL users' Decentralized Identity (DID) credentials
CREATE TABLE IF NOT EXISTS dso.decentralized_identities (
    did_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID UNIQUE NOT NULL REFERENCES auth.users(user_id),
    did_document JSONB NOT NULL, -- Stores decentralized identity credentials
    verification_status TEXT DEFAULT 'PENDING', -- VERIFIED, REJECTED
    registered_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2) Function to verify PostgreSQL user identities using Decentralized Identity (DID)
CREATE OR REPLACE FUNCTION dso.verify_did_authentication()
RETURNS TRIGGER AS $$
DECLARE did_verification_api_url TEXT := 'https://decentralized-identity-verifier.com/api/verify-did';
DECLARE did_payload TEXT;
BEGIN
    did_payload := json_build_object(
        'user_id', NEW.user_id,
        'did_document', NEW.did_document
    )::TEXT;

    -- Send Decentralized Identity verification request
    PERFORM http_post(did_verification_api_url, 'application/json', did_payload);

    -- Log DID authentication request
    INSERT INTO logs.notification_log (event_type, event_source, details, logged_by, logged_at)
    VALUES ('DID Authentication Requested', 'dso.verify_did_authentication', json_build_object('timestamp', NOW()), 'system', NOW());

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 3) Attach trigger to enforce Decentralized Identity authentication on PostgreSQL users
CREATE TRIGGER decentralized_identity_verification_trigger
BEFORE INSERT
ON dso.decentralized_identities
FOR EACH ROW
EXECUTE FUNCTION dso.verify_did_authentication();
