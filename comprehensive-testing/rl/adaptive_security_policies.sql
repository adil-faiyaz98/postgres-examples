\c db_dev;

-- 1) Create function to adapt security policies based on AI learning
CREATE OR REPLACE FUNCTION rl.adapt_security_policies()
RETURNS VOID AS $$
BEGIN
    -- Apply stricter access controls for users flagged multiple times by AI
    UPDATE auth.roles
    SET access_level = 'HIGH_RESTRICTION'
    WHERE user_id IN (
        SELECT user_id FROM rl.security_rewards
        WHERE reward_score < 0
        GROUP BY user_id
        HAVING COUNT(*) > 3
    );

    -- Adjust anomaly detection thresholds dynamically
    UPDATE ml.anomaly_predictions
    SET anomaly_score = anomaly_score * 0.9  -- Reduce false positives
    WHERE detected_anomaly = TRUE
    AND event_type = 'SQL Injection Attempt';

    -- Log security policy updates
    INSERT INTO logs.notification_log (event_type, event_source, details, logged_by, logged_at)
    VALUES ('Adaptive Security Policy Update', 'rl.adapt_security_policies', json_build_object('timestamp', NOW()), 'system', NOW());
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Schedule security policy updates based on AI learning every 24 hours
SELECT cron.schedule('0 0 * * *', 'SELECT rl.adapt_security_policies();');
