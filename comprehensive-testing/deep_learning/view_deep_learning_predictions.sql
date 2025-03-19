\c db_dev;

-- View AI-predicted security anomalies
SELECT * FROM deep_learning.security_training_data
WHERE detected_anomaly = TRUE
ORDER BY detected_at DESC
LIMIT 50;

-- Identify users flagged multiple times by AI
SELECT user_id, COUNT(*) AS anomaly_count
FROM deep_learning.security_training_data
WHERE detected_anomaly = TRUE
GROUP BY user_id
HAVING COUNT(*) > 3
ORDER BY anomaly_count DESC;

-- Analyze time-series forecast of suspicious logins
SELECT date_trunc('day', detected_at) AS day, COUNT(*) AS suspicious_logins
FROM deep_learning.security_training_data
WHERE detected_anomaly = TRUE
GROUP BY date_trunc('day', detected_at)
ORDER BY day DESC;
