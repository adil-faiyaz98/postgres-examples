\c db_dev;

-- 1) Create function to assign reward scores based on past security responses
CREATE OR REPLACE FUNCTION rl.assign_security_rewards()
RETURNS VOID AS $$
BEGIN
    -- Assign positive rewards for correct security actions
    INSERT INTO rl.security_rewards (event_type, user_id, ip_address, action_taken, reward_score)
    SELECT
        sr.event_type, sr.user_id, sr.ip_address, sr.action_type,
        CASE
            WHEN sr.action_type = 'Disable User Account' AND sr.event_type = 'Privilege Escalation Attempt' THEN 1.5
            WHEN sr.action_type = 'Block Malicious IP' AND sr.event_type IN ('SQL Injection Attempt', 'Suspicious Login') THEN 1.0
            ELSE -1.0  -- Negative reward for unnecessary actions
        END AS reward_score
    FROM feedback_loop.soar_security_responses sr
    WHERE NOT EXISTS (
        SELECT 1 FROM rl.security_rewards r
        WHERE r.user_id = sr.user_id AND r.event_type = sr.event_type
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Schedule automatic reward assignment every 6 hours
SELECT cron.schedule('0 */6 * * *', 'SELECT rl.assign_security_rewards();');
