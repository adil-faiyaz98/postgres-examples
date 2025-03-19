\c db_dev;

-- 1) Create table to track reinforcement learning security feedback
CREATE TABLE IF NOT EXISTS rl.security_rewards (
    reward_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type TEXT NOT NULL,  -- (e.g., 'Privilege Escalation', 'Suspicious Login')
    user_id UUID,
    ip_address TEXT,
    action_taken TEXT NOT NULL,  -- (e.g., 'Blocked IP', 'Disabled User')
    reward_score NUMERIC(5,2),  -- Score for learning (positive = good, negative = mistake)
    feedback_time TIMESTAMPTZ DEFAULT NOW()
);
