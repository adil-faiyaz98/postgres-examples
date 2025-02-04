\c db_dev;

-- 1) Create table to track user session logs
CREATE TABLE IF NOT EXISTS auth.user_session_logs (
    log_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID NOT NULL REFERENCES auth.active_sessions(session_id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    user_email TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    session_action TEXT NOT NULL CHECK (session_action IN ('LOGIN', 'LOGOUT', 'UPDATE')),
    logged_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2) Function to log user session events
CREATE OR REPLACE FUNCTION auth.log_user_session_event(p_session_id UUID, p_user_id UUID, p_user_email TEXT, p_ip TEXT, p_user_agent TEXT, p_action TEXT)
RETURNS VOID AS $$
BEGIN
    INSERT INTO auth.user_session_logs (session_id, user_id, user_email, ip_address, user_agent, session_action)
    VALUES (p_session_id, p_user_id, p_user_email, p_ip, p_user_agent, p_action);

    -- Log to central notification system
    INSERT INTO logging.central_notification_log (event_type, event_source, event_details, logged_by)
    VALUES ('User Session Event', 'auth.user_session_logs', json_build_object(
        'session_id', p_session_id,
        'user_id', p_user_id,
        'ip_address', p_ip,
        'user_agent', p_user_agent,
        'action', p_action
    ), p_user_email);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 3) Function to monitor active sessions for anomalies
CREATE OR REPLACE FUNCTION auth.monitor_session_anomalies()
RETURNS VOID AS $$
DECLARE anomaly_count INT;
BEGIN
    -- Detect multiple simultaneous logins from different IPs
    SELECT COUNT(*) INTO anomaly_count
    FROM auth.user_session_logs
    GROUP BY user_id, ip_address
    HAVING COUNT(DISTINCT session_id) > 1;

    IF anomaly_count > 0 THEN
        -- Log suspicious session activity
        INSERT INTO logging.central_notification_log (event_type, event_source, event_details, logged_by)
        VALUES ('Suspicious Session Activity', 'auth.user_session_logs', json_build_object(
            'anomaly_count', anomaly_count,
            'timestamp', NOW()
        ), 'system');
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 4) Schedule session anomaly detection every 5 minutes
SELECT cron.schedule('*/5 * * * *', 'SELECT auth.monitor_session_anomalies();');
