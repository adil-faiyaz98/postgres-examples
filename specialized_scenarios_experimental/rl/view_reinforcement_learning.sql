\c db_dev;

-- View AI-assigned security rewards for past actions
SELECT * FROM rl.security_rewards
ORDER BY feedback_time DESC
LIMIT 50;

-- Identify users with repeated AI-flagged anomalies
SELECT user_id, COUNT(*) AS flagged_times
FROM rl.security_rewards
WHERE reward_score < 0
GROUP BY user_id
HAVING COUNT(*) > 3
ORDER BY flagged_times DESC;

-- Analyze policy changes triggered by AI-based security decisions
SELECT logged_at, event_type, details
FROM logs.notification_log
WHERE event_type = 'Adaptive Security Policy Update'
ORDER BY logged_at DESC;
