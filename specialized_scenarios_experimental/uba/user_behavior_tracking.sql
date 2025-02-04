\c db_dev;

-- 1) Create table to track user behavior metrics
CREATE TABLE IF NOT EXISTS uba.user_activity_logs (
    log_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES auth.users(user_id),
    session_id UUID,
    event_type TEXT NOT NULL, -- (e.g., 'Login', 'Query Executed', 'Privilege Escalation')
    event_details JSONB,
    event_timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- 2) Create function to log user activity dynamically
CREATE OR REPLACE FUNCTION uba.log_user_activity(
    p_user_id UUID, p_session_id UUID, p_event_type TEXT, p_event_details JSONB
) RETURNS VOID AS $$
BEGIN
    INSERT INTO uba.user_activity_logs (user_id, session_id, event_type, event_details)
    VALUES (p_user_id, p_session_id, p_event_type, p_event_details);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
