\c db_dev;

-- 1) Create function to disable compromised user accounts
CREATE OR REPLACE FUNCTION security.auto_lock_user()
RETURNS TRIGGER AS $$
BEGIN
    -- Disable the user if suspicious login detected
    UPDATE auth.users SET is_locked = TRUE
    WHERE user_id = NEW.user_id;

    -- Log security incident
    INSERT INTO logs.notification_log (event_type, event_source, details, logged_by, logged_at)
    VALUES ('Account Locked', 'auth.users', json_build_object('user_id', NEW.user_id, 'reason', 'Suspicious activity detected'), current_user, NOW());

    -- Notify security team
    PERFORM pg_notify('security_alert', json_build_object(
        'event', 'User Account Locked',
        'user_id', NEW.user_id,
        'timestamp', NOW()
    )::TEXT);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Attach trigger to monitor suspicious logins
CREATE TRIGGER lock_user_on_suspicious_login
AFTER INSERT
ON logs.notification_log
FOR EACH ROW
WHEN (NEW.event_type = 'Suspicious Login')
EXECUTE FUNCTION security.auto_lock_user();
