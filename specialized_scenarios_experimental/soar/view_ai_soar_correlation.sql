\c db_dev;

-- 1) Create function to execute AI-driven security responses in PostgreSQL
CREATE OR REPLACE FUNCTION soar.execute_adaptive_security_response()
RETURNS VOID AS $$
BEGIN
    -- Automatically disable high-risk PostgreSQL users flagged by SOAR
    UPDATE auth.users
    SET is_locked = TRUE
    WHERE user_id IN (
        SELECT user_id FROM soar.soar_action_logs
        WHERE action_type = 'Disable User Account'
    );

    -- Automatically adjust firewall rules for AI-detected high-risk IPs
    DELETE FROM threat_intelligence.otx_threat_indicators
    WHERE indicator IN (
        SELECT details->>'ip_address' FROM soar.soar_action_logs WHERE action_type = 'Block High-Risk IP'
    );

    -- Log automated SOAR response execution
    INSERT INTO logs.notification_log (event_type, event_source, details, logged_by, logged_at)
    VALUES ('AI SOAR Response Executed', 'soar.execute_adaptive_security_response', json_build_object('timestamp', NOW()), 'system', NOW());
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Automate AI-driven SOAR response execution every 3 hours
SELECT cron.schedule('0 */3 * * *', 'SELECT soar.execute_adaptive_security_response();');
