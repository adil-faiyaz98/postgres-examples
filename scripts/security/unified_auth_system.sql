-- PostgreSQL Unified Authentication and Session Management System
-- This script integrates session management with zero trust authentication

\c db_dev;

-- Create schema for authentication and session management if it doesn't exist
CREATE SCHEMA IF NOT EXISTS auth;

-- Create extension for UUID generation if not exists
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create table for storing user authentication information
CREATE TABLE IF NOT EXISTS auth.users (
    user_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    last_login_attempt TIMESTAMPTZ,
    account_locked BOOLEAN NOT NULL DEFAULT FALSE,
    account_locked_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (status IN ('active', 'inactive', 'suspended'))
);

-- Create table for storing active sessions
CREATE TABLE IF NOT EXISTS auth.active_sessions (
    session_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES auth.users(user_id) ON DELETE CASCADE,
    jwt_token TEXT NOT NULL,
    token_issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    token_expires_at TIMESTAMPTZ NOT NULL,
    client_ip TEXT,
    user_agent TEXT,
    last_active TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_reason TEXT,
    CHECK (token_expires_at > token_issued_at)
);

-- Create index for faster session lookups
CREATE INDEX IF NOT EXISTS idx_active_sessions_user_id ON auth.active_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_active_sessions_token_expires_at ON auth.active_sessions(token_expires_at);

-- Create table for storing JWT signing keys
CREATE TABLE IF NOT EXISTS auth.jwt_keys (
    key_id TEXT PRIMARY KEY,
    key_data TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    CHECK (expires_at > created_at)
);

-- Create function to register a new user
CREATE OR REPLACE FUNCTION auth.register_user(
    p_username TEXT,
    p_email TEXT,
    p_password TEXT,
    p_role TEXT DEFAULT 'user'
) RETURNS UUID AS $$
DECLARE
    v_user_id UUID;
    v_salt TEXT;
    v_password_hash TEXT;
BEGIN
    -- Generate salt
    v_salt := gen_salt('bf');
    
    -- Hash password with salt
    v_password_hash := crypt(p_password, v_salt);
    
    -- Insert new user
    INSERT INTO auth.users (username, email, password_hash, salt, role)
    VALUES (p_username, p_email, v_password_hash, v_salt, p_role)
    RETURNING user_id INTO v_user_id;
    
    -- Log user creation
    INSERT INTO logs.notification_log (event_type, severity, username, message)
    VALUES ('USER_CREATED', 'INFO', p_username, 'New user registered');
    
    RETURN v_user_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to authenticate a user
CREATE OR REPLACE FUNCTION auth.authenticate_user(
    p_username TEXT,
    p_password TEXT,
    p_client_ip TEXT DEFAULT NULL,
    p_user_agent TEXT DEFAULT NULL
) RETURNS TABLE(
    authenticated BOOLEAN,
    user_id UUID,
    username TEXT,
    role TEXT,
    session_id UUID,
    jwt_token TEXT,
    token_expires_at TIMESTAMPTZ
) AS $$
DECLARE
    v_user RECORD;
    v_session_id UUID;
    v_jwt_token TEXT;
    v_token_expires_at TIMESTAMPTZ;
    v_max_failed_attempts INTEGER := 5;
    v_lockout_duration INTERVAL := '30 minutes';
BEGIN
    -- Get user record
    SELECT * INTO v_user
    FROM auth.users
    WHERE username = p_username;
    
    -- Initialize return values
    authenticated := FALSE;
    user_id := NULL;
    username := p_username;
    role := NULL;
    session_id := NULL;
    jwt_token := NULL;
    token_expires_at := NULL;
    
    -- Check if user exists
    IF v_user IS NULL THEN
        -- Log failed login attempt
        INSERT INTO logs.notification_log (event_type, severity, username, source_ip, message)
        VALUES ('LOGIN_FAILURE', 'WARNING', p_username, p_client_ip, 'User not found');
        RETURN;
    END IF;
    
    -- Check if account is locked
    IF v_user.account_locked AND v_user.account_locked_until > NOW() THEN
        -- Log locked account attempt
        INSERT INTO logs.notification_log (event_type, severity, username, source_ip, message)
        VALUES ('LOGIN_FAILURE', 'WARNING', p_username, p_client_ip, 'Account locked');
        RETURN;
    END IF;
    
    -- Reset account lock if lockout period has passed
    IF v_user.account_locked AND v_user.account_locked_until <= NOW() THEN
        UPDATE auth.users
        SET account_locked = FALSE,
            account_locked_until = NULL,
            failed_login_attempts = 0
        WHERE user_id = v_user.user_id;
        
        v_user.account_locked := FALSE;
        v_user.failed_login_attempts := 0;
    END IF;
    
    -- Check password
    IF v_user.password_hash = crypt(p_password, v_user.salt) THEN
        -- Authentication successful
        authenticated := TRUE;
        user_id := v_user.user_id;
        username := v_user.username;
        role := v_user.role;
        
        -- Reset failed login attempts
        UPDATE auth.users
        SET failed_login_attempts = 0,
            last_login_attempt = NOW()
        WHERE user_id = v_user.user_id;
        
        -- Generate JWT token (simplified - in production use a proper JWT library)
        v_token_expires_at := NOW() + INTERVAL '1 hour';
        v_jwt_token := 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' || 
                       encode(json_build_object(
                           'sub', v_user.user_id,
                           'name', v_user.username,
                           'role', v_user.role,
                           'iat', extract(epoch from NOW()),
                           'exp', extract(epoch from v_token_expires_at)
                       )::text::bytea, 'base64') || 
                       '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
        
        -- Create session
        INSERT INTO auth.active_sessions (
            user_id, jwt_token, token_expires_at, client_ip, user_agent
        ) VALUES (
            v_user.user_id, v_jwt_token, v_token_expires_at, p_client_ip, p_user_agent
        ) RETURNING session_id INTO v_session_id;
        
        session_id := v_session_id;
        jwt_token := v_jwt_token;
        token_expires_at := v_token_expires_at;
        
        -- Log successful login
        INSERT INTO logs.notification_log (event_type, severity, username, source_ip, message)
        VALUES ('LOGIN_SUCCESS', 'INFO', p_username, p_client_ip, 'User authenticated successfully');
    ELSE
        -- Authentication failed
        -- Increment failed login attempts
        UPDATE auth.users
        SET failed_login_attempts = failed_login_attempts + 1,
            last_login_attempt = NOW(),
            account_locked = CASE 
                WHEN failed_login_attempts + 1 >= v_max_failed_attempts THEN TRUE 
                ELSE account_locked 
            END,
            account_locked_until = CASE 
                WHEN failed_login_attempts + 1 >= v_max_failed_attempts THEN NOW() + v_lockout_duration
                ELSE account_locked_until
            END
        WHERE user_id = v_user.user_id;
        
        -- Log failed login attempt
        INSERT INTO logs.notification_log (event_type, severity, username, source_ip, message)
        VALUES ('LOGIN_FAILURE', 'WARNING', p_username, p_client_ip, 'Invalid password');
    END IF;
    
    RETURN;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to validate a session
CREATE OR REPLACE FUNCTION auth.validate_session(
    p_jwt_token TEXT,
    p_client_ip TEXT DEFAULT NULL
) RETURNS TABLE(
    valid BOOLEAN,
    user_id UUID,
    username TEXT,
    role TEXT
) AS $$
DECLARE
    v_session RECORD;
    v_user RECORD;
BEGIN
    -- Initialize return values
    valid := FALSE;
    user_id := NULL;
    username := NULL;
    role := NULL;
    
    -- Get session record
    SELECT * INTO v_session
    FROM auth.active_sessions
    WHERE jwt_token = p_jwt_token
    AND token_expires_at > NOW()
    AND NOT revoked;
    
    -- Check if session exists and is valid
    IF v_session IS NULL THEN
        -- Log invalid session attempt
        INSERT INTO logs.notification_log (event_type, severity, source_ip, message)
        VALUES ('SESSION_INVALID', 'WARNING', p_client_ip, 'Invalid or expired session token');
        RETURN;
    END IF;
    
    -- Get user record
    SELECT * INTO v_user
    FROM auth.users
    WHERE user_id = v_session.user_id;
    
    -- Check if user exists and is active
    IF v_user IS NULL OR v_user.status != 'active' THEN
        -- Revoke session
        UPDATE auth.active_sessions
        SET revoked = TRUE,
            revoked_reason = 'User not found or inactive'
        WHERE session_id = v_session.session_id;
        
        -- Log invalid user
        INSERT INTO logs.notification_log (event_type, severity, source_ip, message)
        VALUES ('SESSION_INVALID', 'WARNING', p_client_ip, 'User not found or inactive');
        RETURN;
    END IF;
    
    -- Update last active timestamp
    UPDATE auth.active_sessions
    SET last_active = NOW()
    WHERE session_id = v_session.session_id;
    
    -- Session is valid
    valid := TRUE;
    user_id := v_user.user_id;
    username := v_user.username;
    role := v_user.role;
    
    RETURN;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to revoke a session
CREATE OR REPLACE FUNCTION auth.revoke_session(
    p_session_id UUID,
    p_reason TEXT DEFAULT 'User logout'
) RETURNS BOOLEAN AS $$
DECLARE
    v_session RECORD;
BEGIN
    -- Get session record
    SELECT * INTO v_session
    FROM auth.active_sessions
    WHERE session_id = p_session_id
    AND NOT revoked;
    
    -- Check if session exists
    IF v_session IS NULL THEN
        RETURN FALSE;
    END IF;
    
    -- Revoke session
    UPDATE auth.active_sessions
    SET revoked = TRUE,
        revoked_reason = p_reason
    WHERE session_id = p_session_id;
    
    -- Log session revocation
    INSERT INTO logs.notification_log (event_type, severity, username, message)
    VALUES ('SESSION_REVOKED', 'INFO', (SELECT username FROM auth.users WHERE user_id = v_session.user_id), p_reason);
    
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to revoke all sessions for a user
CREATE OR REPLACE FUNCTION auth.revoke_all_user_sessions(
    p_user_id UUID,
    p_reason TEXT DEFAULT 'Administrative action'
) RETURNS INTEGER AS $$
DECLARE
    v_count INTEGER;
BEGIN
    -- Revoke all active sessions for the user
    UPDATE auth.active_sessions
    SET revoked = TRUE,
        revoked_reason = p_reason
    WHERE user_id = p_user_id
    AND NOT revoked
    AND token_expires_at > NOW();
    
    GET DIAGNOSTICS v_count = ROW_COUNT;
    
    -- Log session revocation
    IF v_count > 0 THEN
        INSERT INTO logs.notification_log (event_type, severity, username, message)
        VALUES ('SESSIONS_REVOKED', 'INFO', (SELECT username FROM auth.users WHERE user_id = p_user_id), 
                format('Revoked %s active sessions: %s', v_count, p_reason));
    END IF;
    
    RETURN v_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to clean up expired sessions
CREATE OR REPLACE FUNCTION auth.cleanup_expired_sessions() RETURNS INTEGER AS $$
DECLARE
    v_count INTEGER;
BEGIN
    -- Delete expired sessions older than 7 days
    DELETE FROM auth.active_sessions
    WHERE token_expires_at < NOW() - INTERVAL '7 days';
    
    GET DIAGNOSTICS v_count = ROW_COUNT;
    
    -- Log cleanup
    IF v_count > 0 THEN
        INSERT INTO logs.notification_log (event_type, severity, message)
        VALUES ('SESSIONS_CLEANUP', 'INFO', format('Cleaned up %s expired sessions', v_count));
    END IF;
    
    RETURN v_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create a trigger to automatically update the updated_at timestamp
CREATE OR REPLACE FUNCTION auth.update_timestamp() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_users_timestamp
BEFORE UPDATE ON auth.users
FOR EACH ROW
EXECUTE FUNCTION auth.update_timestamp();

-- Create a function to integrate with the zero trust authentication service
CREATE OR REPLACE FUNCTION auth.verify_jwt_with_auth_service(
    p_jwt_token TEXT,
    p_auth_service_url TEXT DEFAULT 'http://postgres-auth-service:8080/verify'
) RETURNS BOOLEAN AS $$
DECLARE
    v_result BOOLEAN;
BEGIN
    -- This is a placeholder function that would normally make an HTTP request to the auth service
    -- In a real implementation, you would use plpython3u or plperlu to make an HTTP request
    
    -- For demonstration purposes, we'll just return TRUE if the token is not NULL or empty
    v_result := p_jwt_token IS NOT NULL AND p_jwt_token != '';
    
    -- Log the verification attempt
    INSERT INTO logs.notification_log (event_type, severity, message)
    VALUES ('JWT_VERIFICATION', 'INFO', format('JWT verification result: %s', v_result));
    
    RETURN v_result;
END;
$$ LANGUAGE plpgsql;

-- Create a view to show active sessions with user information
CREATE OR REPLACE VIEW auth.active_user_sessions AS
SELECT 
    s.session_id,
    s.user_id,
    u.username,
    u.email,
    u.role,
    s.token_issued_at,
    s.token_expires_at,
    s.last_active,
    s.client_ip,
    s.user_agent
FROM 
    auth.active_sessions s
JOIN 
    auth.users u ON s.user_id = u.user_id
WHERE 
    NOT s.revoked
    AND s.token_expires_at > NOW();

-- Grant appropriate permissions
GRANT USAGE ON SCHEMA auth TO app_user, security_admin;
GRANT SELECT ON auth.active_user_sessions TO security_admin;
GRANT EXECUTE ON FUNCTION auth.register_user TO app_user;
GRANT EXECUTE ON FUNCTION auth.authenticate_user TO app_user;
GRANT EXECUTE ON FUNCTION auth.validate_session TO app_user;
GRANT EXECUTE ON FUNCTION auth.revoke_session TO app_user;
GRANT EXECUTE ON FUNCTION auth.cleanup_expired_sessions TO security_admin;
GRANT EXECUTE ON FUNCTION auth.revoke_all_user_sessions TO security_admin;

-- Create a scheduled job to clean up expired sessions (runs daily)
SELECT cron.schedule('0 0 * * *', $$SELECT auth.cleanup_expired_sessions()$$);

-- Example usage:
-- Register a new user
-- SELECT auth.register_user('john.doe', 'john.doe@example.com', 'secure_password', 'user');

-- Authenticate a user
-- SELECT * FROM auth.authenticate_user('john.doe', 'secure_password', '192.168.1.1', 'Mozilla/5.0');

-- Validate a session
-- SELECT * FROM auth.validate_session('jwt_token_here', '192.168.1.1');

-- Revoke a session
-- SELECT auth.revoke_session('session_id_here', 'User logout');

-- Revoke all sessions for a user
-- SELECT auth.revoke_all_user_sessions('user_id_here', 'Password changed');

-- Clean up expired sessions
-- SELECT auth.cleanup_expired_sessions();
