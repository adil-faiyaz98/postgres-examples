\c db_dev;

-- 1) Create function to dynamically update security policies
CREATE OR REPLACE FUNCTION feedback_loop.improve_security_policies()
RETURNS VOID AS $$
BEGIN
    -- Increase access restrictions for users with repeated AI-detected anomalies
    UPDATE auth.roles
    SET access_level = 'RESTRICTED'
    WHERE user_id IN (
        SELECT user_id FROM ml.anomaly_predictions
        WHERE detected_anomaly = TRUE
        AND event_type IN ('Privilege Escalation Attempt', 'Abnormal Query Pattern')
    );

    -- Log AI-driven security policy updates
    INSERT INTO logs.notification_log (event_type, event_source, details, logged_by, logged_at)
    VALUES ('AI Security Policy Update', 'feedback_loop.improve_security_policies', json_build_object('timestamp', NOW()), 'system', NOW());
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Schedule automatic security policy updates every 24 hours
SELECT cron.schedule('0 0 * * *', 'SELECT feedback_loop.improve_security_policies();');
