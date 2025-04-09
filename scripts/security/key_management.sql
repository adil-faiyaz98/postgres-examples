-- Key Management System for PostgreSQL Security Framework
CREATE SCHEMA IF NOT EXISTS key_management;

-- Table for storing encryption keys
CREATE TABLE IF NOT EXISTS key_management.keys (
    id SERIAL PRIMARY KEY,
    key_name TEXT NOT NULL UNIQUE,
    key_type TEXT NOT NULL,
    key_value BYTEA NOT NULL,
    key_version INTEGER NOT NULL DEFAULT 1,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    created_by TEXT NOT NULL,
    last_rotated_at TIMESTAMPTZ,
    metadata JSONB
);

-- Function to generate a new encryption key
CREATE OR REPLACE FUNCTION key_management.generate_key(
    p_key_name TEXT,
    p_key_type TEXT DEFAULT 'AES-256',
    p_expiry_days INTEGER DEFAULT 365
) RETURNS TEXT AS $$
DECLARE
    v_key_value BYTEA;
    v_key_id INTEGER;
BEGIN
    -- Generate random key
    v_key_value := gen_random_bytes(32); -- 256 bits
    
    -- Store key
    INSERT INTO key_management.keys (
        key_name, key_type, key_value, created_by, expires_at
    ) VALUES (
        p_key_name, p_key_type, v_key_value, current_user,
        NOW() + (p_expiry_days || ' days')::INTERVAL
    ) RETURNING id INTO v_key_id;
    
    -- Log key creation
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'KEY_CREATED', 'INFO', current_user, 
        'Created encryption key: ' || p_key_name
    );
    
    RETURN 'Key ' || p_key_name || ' created with ID ' || v_key_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to rotate a key
CREATE OR REPLACE FUNCTION key_management.rotate_key(
    p_key_name TEXT,
    p_expiry_days INTEGER DEFAULT 365
) RETURNS TEXT AS $$
DECLARE
    v_old_key RECORD;
    v_new_key_value BYTEA;
    v_new_version INTEGER;
BEGIN
    -- Get current key
    SELECT * INTO v_old_key
    FROM key_management.keys
    WHERE key_name = p_key_name AND is_active = TRUE;
    
    IF v_old_key IS NULL THEN
        RAISE EXCEPTION 'Key % not found or not active', p_key_name;
    END IF;
    
    -- Deactivate old key
    UPDATE key_management.keys
    SET is_active = FALSE
    WHERE id = v_old_key.id;
    
    -- Generate new key
    v_new_key_value := gen_random_bytes(32);
    v_new_version := v_old_key.key_version + 1;
    
    -- Store new key
    INSERT INTO key_management.keys (
        key_name, key_type, key_value, key_version, created_by, expires_at
    ) VALUES (
        p_key_name, v_old_key.key_type, v_new_key_value, v_new_version, 
        current_user, NOW() + (p_expiry_days || ' days')::INTERVAL
    );
    
    -- Log key rotation
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'KEY_ROTATED', 'INFO', current_user, 
        'Rotated encryption key: ' || p_key_name || ' to version ' || v_new_version
    );
    
    RETURN 'Key ' || p_key_name || ' rotated to version ' || v_new_version;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to encrypt data
CREATE OR REPLACE FUNCTION key_management.encrypt(
    p_data TEXT,
    p_key_name TEXT
) RETURNS TEXT AS $$
DECLARE
    v_key RECORD;
    v_encrypted BYTEA;
BEGIN
    -- Get active key
    SELECT * INTO v_key
    FROM key_management.keys
    WHERE key_name = p_key_name AND is_active = TRUE;
    
    IF v_key IS NULL THEN
        RAISE EXCEPTION 'Key % not found or not active', p_key_name;
    END IF;
    
    -- Check if key is expired
    IF v_key.expires_at IS NOT NULL AND v_key.expires_at < NOW() THEN
        RAISE EXCEPTION 'Key % is expired', p_key_name;
    END IF;
    
    -- Encrypt data
    v_encrypted := encrypt(p_data::BYTEA, v_key.key_value, 'aes');
    
    -- Return encrypted data with key version
    RETURN v_key.key_version || ':' || encode(v_encrypted, 'base64');
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to decrypt data
CREATE OR REPLACE FUNCTION key_management.decrypt(
    p_encrypted TEXT,
    p_key_name TEXT
) RETURNS TEXT AS $$
DECLARE
    v_key RECORD;
    v_version INTEGER;
    v_encrypted_data BYTEA;
    v_decrypted BYTEA;
BEGIN
    -- Parse version and encrypted data
    v_version := split_part(p_encrypted, ':', 1)::INTEGER;
    v_encrypted_data := decode(split_part(p_encrypted, ':', 2), 'base64');
    
    -- Get key with matching version
    SELECT * INTO v_key
    FROM key_management.keys
    WHERE key_name = p_key_name AND key_version = v_version;
    
    IF v_key IS NULL THEN
        RAISE EXCEPTION 'Key % version % not found', p_key_name, v_version;
    END IF;
    
    -- Decrypt data
    v_decrypted := decrypt(v_encrypted_data, v_key.key_value, 'aes');
    
    -- Return decrypted data
    RETURN convert_from(v_decrypted, 'UTF8');
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create scheduled job for key rotation alerts
CREATE OR REPLACE FUNCTION key_management.check_key_expiry() RETURNS VOID AS $$
DECLARE
    v_key RECORD;
BEGIN
    FOR v_key IN
        SELECT * FROM key_management.keys
        WHERE is_active = TRUE
          AND expires_at IS NOT NULL
          AND expires_at < NOW() + INTERVAL '30 days'
    LOOP
        -- Log expiry warning
        INSERT INTO logs.notification_log (
            event_type, severity, username, message
        ) VALUES (
            'KEY_EXPIRY_WARNING', 'WARNING', current_user, 
            'Key ' || v_key.key_name || ' will expire on ' || v_key.expires_at
        );
    END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant permissions
GRANT USAGE ON SCHEMA key_management TO security_admin;
GRANT SELECT ON key_management.keys TO security_admin;
GRANT EXECUTE ON FUNCTION key_management.generate_key TO security_admin;
GRANT EXECUTE ON FUNCTION key_management.rotate_key TO security_admin;
GRANT EXECUTE ON FUNCTION key_management.encrypt TO app_user, security_admin;
GRANT EXECUTE ON FUNCTION key_management.decrypt TO app_user, security_admin;
GRANT EXECUTE ON FUNCTION key_management.check_key_expiry TO security_admin;
