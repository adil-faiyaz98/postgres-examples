\c db_dev;

-- 1) Create function to suspend compromised accounts
CREATE OR REPLACE FUNCTION security.suspend_user_account()
RETURNS TRIGGER AS $$
DECLARE user_to_suspend UUID;
BEGIN
    -- Extract user ID from event details
    user_to_suspend := NEW.details->>'user_id'::UUID;

    -- Suspend the user in the auth.users table
    UPDATE auth.users
    SET is_locked = TRUE
    WHERE user_id = user_to_suspend;

    -- Log security incident
    INSERT INTO logs.notification_log (event_type, event_source, details, logged_by, logged_at)
    VALUES ('User Suspended', 'auth.users', json_build_object('user_id', user_to_suspend, '
