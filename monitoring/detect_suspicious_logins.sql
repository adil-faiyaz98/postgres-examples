\c db_dev;

-- Function to detect login anomalies
CREATE OR REPLACE FUNCTION security.detect_suspicious_logins()
RETURNS TRIGGER AS $$
DECLARE login_count INT;
BEGIN
    -- Check if the user has logged in more than the allowed threshold
    SELECT COUNT(*) INTO login_count
    FROM auth.active_sessions
    WHERE user_id = NEW.user_id
    AND login_time >= NOW() - INTERVAL '5 minutes';

    IF login_count > current_setting('custom.suspicious_login_threshold')::INT THEN
        -- Log suspicious login attempt
        INSERT INTO logs.notification_log (event_type, event_source, details, logged_by, logged_at)
        VALUES ('Suspicious Login', 'auth.active_sessions', json_build_object('user_id', NEW.user_id, 'login_count', login_count), current_user, NOW());

        -- Send security alert
        PERFORM pg_notify('security_alert', json_build_object(
            'event', 'Suspicious Login Detected',
            'user_id', NEW.user_id,
            'login_count', login_count,
            'timestamp', NOW()
        )::TEXT);
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Attach trigger to monitor login attempts
CREATE TRIGGER detect_suspicious_logins
AFTER INSERT ON auth.active_sessions
FOR EACH ROW
EXECUTE FUNCTION security.detect_suspicious_logins();
