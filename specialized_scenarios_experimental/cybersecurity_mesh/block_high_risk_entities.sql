\c db_dev;

-- 1) Create function to dynamically block high-risk IPs and users in PostgreSQL
CREATE OR REPLACE FUNCTION cybersecurity_mesh.block_high_risk_entities()
RETURNS VOID AS $$
DECLARE firewall_api_url TEXT := 'https://firewall-provider.com/api/block-ip';
DECLARE ip_to_block TEXT;
DECLARE block_payload TEXT;
BEGIN
    -- Block high-risk IPs detected in PostgreSQL AI threat intelligence
    FOR ip_to_block IN
        SELECT details->>'ip_address' FROM logs.notification_log
        WHERE event_type IN ('SQL Injection Attempt', 'Suspicious Login')
    LOOP
        -- Construct payload to block the IP
        block_payload := json_build_object(
            'ip', ip_to_block,
            'action', 'block',
            'reason', 'AI-Predicted High-Risk Activity',
            'timestamp', NOW()
        )::TEXT;

        -- Send request to firewall provider to block IP
        PERFORM http_post(firewall_api_url, 'application/json', block_payload);
    END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Schedule automatic threat blocking every hour
SELECT cron.schedule('0 * * * *', 'SELECT cybersecurity_mesh.block_high_risk_entities();');
