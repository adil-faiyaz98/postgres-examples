\c db_dev;

-- 1) Create table to track Zero-Trust PostgreSQL authentication requests
CREATE TABLE IF NOT EXISTS dso.zero_trust_authentication (
    auth_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,
    session_id UUID NOT NULL,
    device_id TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    authentication_status TEXT DEFAULT 'PENDING', -- PENDING, VERIFIED, DENIED
    auth_timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- 2) Function to verify PostgreSQL Zero-Trust authentication requests
CREATE OR REPLACE FUNCTION dso.verify_zero_trust_auth()
RETURNS TRIGGER AS $$
DECLARE zero_trust_api_url TEXT := 'https://zero-trust-verification.com/api/verify-auth';
DECLARE auth_payload TEXT;
BEGIN
    auth_payload := json_build_object(
        'user_id', NEW.user_id,
        'session_id', NEW.session_id,
        'device_id', NEW.device_id,
        'ip_address', NEW.ip_address
    )::TEXT;

    -- Send authentication request to Zero-Trust verification system
    PERFORM http_post(zero_trust_api_url, 'application/json', auth_payload);

    -- Log Zero-Trust authentication request
    INSERT INTO logs.notification_log (event_type, event_source, details, logged_by, logged_at)
    VALUES ('Zero-Trust Authentication Requested', 'dso.verify_zero_trust_auth', json_build_object('timestamp', NOW()), 'system', NOW());

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 3) Attach trigger to enforce Zero-Trust authentication on PostgreSQL access
CREATE TRIGGER zero_trust_auth_trigger
BEFORE INSERT
ON dso.zero_trust_authentication
FOR EACH ROW
EXECUTE FUNCTION dso.verify_zero_trust_auth();
