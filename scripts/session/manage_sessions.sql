\c db_dev;

-- 1) Create a table to track active user sessions
CREATE TABLE IF NOT EXISTS auth.active_sessions (
    session_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES inventory.customers(customer_id) ON DELETE CASCADE,
    user_email TEXT NOT NULL,
    login_time TIMESTAMPTZ DEFAULT NOW(),
    last_active TIMESTAMPTZ DEFAULT NOW(),
    session_expiry INTERVAL DEFAULT current_setting('app.default_session_expiry', TRUE)::INTERVAL,
    CHECK (last_active + session_expiry >= NOW()) -- Ensure sessions auto-expire
);

-- 2) Function to start a user session
CREATE OR REPLACE FUNCTION auth.start_user_session(p_user_id UUID, p_email TEXT, p_session_expiry INTERVAL DEFAULT current_setting('app.default_session_expiry', TRUE)::INTERVAL)
RETURNS UUID AS $$
DECLARE v_session_id UUID;
BEGIN
    -- Insert session record
    INSERT INTO auth.active_sessions (user_id, user_email, session_expiry)
    VALUES (p_user_id, p_email, p_session_expiry)
    RETURNING session_id INTO v_session_id;

    -- Set session variables dynamically
    PERFORM set_config('app.current_user_id', p_user_id::TEXT, false);
    PERFORM set_config('app.current_user_email', p_email, false);
    PERFORM set_config('app.current_session_id', v_session_id::TEXT, false);

    -- Log session start
    PERFORM auth.log_user_session_event(v_session_id, p_user_id, p_email, '127.0.0.1', 'Unknown', 'LOGIN');

    RETURN v_session_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 3) Function to update session activity timestamp
CREATE OR REPLACE FUNCTION auth.update_session_activity(p_session_id UUID)
RETURNS VOID AS $$
BEGIN
    UPDATE auth.active_sessions
    SET last_active = NOW()
    WHERE session_id = p_session_id;

    -- Log session update
    PERFORM auth.log_user_session_event(p_session_id, (SELECT user_id FROM auth.active_sessions WHERE session_id = p_session_id),
                                         (SELECT user_email FROM auth.active_sessions WHERE session_id = p_session_id),
                                         '127.0.0.1', 'Unknown', 'UPDATE');
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 4) Function to end a user session
CREATE OR REPLACE FUNCTION auth.end_user_session(p_session_id UUID)
RETURNS VOID AS $$
BEGIN
    DELETE FROM auth.active_sessions WHERE session_id = p_session_id;

    -- Reset session variables
    PERFORM set_config('app.current_user_id', '', false);
    PERFORM set_config('app.current_user_email', '', false);
    PERFORM set_config('app.current_session_id', '', false);

    -- Log session logout
    PERFORM auth.log_user_session_event(p_session_id, NULL, NULL, '127.0.0.1', 'Unknown', 'LOGOUT');
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 5) Scheduled job to remove expired sessions every 10 minutes
CREATE OR REPLACE FUNCTION auth.remove_expired_sessions()
RETURNS VOID AS $$
BEGIN
    DELETE FROM auth.active_sessions
    WHERE last_active + session_expiry < NOW();
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Schedule automatic cleanup every 10 minutes
SELECT cron.schedule('*/10 * * * *', 'SELECT auth.remove_expired_sessions()');

-- 6) Verify active session status
SELECT * FROM auth.active_sessions;
