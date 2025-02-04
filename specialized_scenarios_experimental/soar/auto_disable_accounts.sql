\c db_dev;

-- 1) Create function to disable PostgreSQL users based on SOAR playbook execution
CREATE OR REPLACE FUNCTION soar.disable_high_risk_users()
RETURNS TRIGGER AS $$
DECLARE user_to_disable UUID;
BEGIN
    -- Extract user ID from SOAR action logs
    user_to_disable := NEW.details->>'user_id'::UUID;

    -- Disable user in PostgreSQL
    UPDATE auth.users
    SET is_locked = TRUE
    WHERE user_id = user_to_disable;

    -- Log security event
    INSERT INTO logs.notification_log (event_type, event_source, details, logged_by, logged_at)
    VALUES ('User Account Disabled', 'SOAR Automation', json_build_object('user_id', user_to_disable, 'reason', NEW.event_type), 'system', NOW());

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Attach trigger to disable users based on SOAR incident response
CREATE TRIGGER soar_disable_high_risk_users_trigger
AFTER INSERT
ON soar.soar_action_logs
FOR EACH ROW
WHEN (NEW.action_type = 'Disable User Account')
EXECUTE FUNCTION soar.disable_high_risk_users();
