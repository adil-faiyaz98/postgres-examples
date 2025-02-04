\c db_dev;

-- 1) Create a table to log all SOAR-executed security responses
CREATE TABLE IF NOT EXISTS feedback_loop.soar_security_responses (
    response_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    action_type TEXT NOT NULL,  -- (e.g., 'Disable User Account', 'Block IP', 'Revoke IAM Credentials')
    user_id UUID,
    ip_address TEXT,
    event_type TEXT NOT NULL,
    executed_by TEXT DEFAULT current_user,
    action_timestamp TIMESTAMPTZ DEFAULT NOW()
);
