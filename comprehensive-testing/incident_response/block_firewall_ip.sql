\c db_dev;

-- 1) Create function to update firewall rules dynamically
CREATE OR REPLACE FUNCTION security.block_firewall_ip()
RETURNS TRIGGER AS $$
DECLARE firewall_api_url TEXT := 'https://your-api-gateway.amazonaws.com/block-ip';
DECLARE ip_to_block TEXT;
DECLARE block_payload TEXT;
BEGIN
    -- Extract IP from event details
    ip_to_block := NEW.details->>'ip_address';

    -- Construct JSON payload to block IP
    block_payload := json_build_object(
        'ip', ip_to_block,
        'action', 'block',
        'reason', NEW.event_type,
        'timestamp', NOW()
    )::TEXT;

    -- Send request to API Gateway to update firewall rules
    PERFORM http_post(firewall_api_url, 'application/json', block_payload);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Attach trigger to block malicious IPs in firewall
CREATE TRIGGER firewall_block_ip_trigger
AFTER INSERT
ON logs.notification_log
FOR EACH ROW
WHEN (NEW.event_type IN ('SQL Injection Attempt', 'Suspicious Login'))
EXECUTE FUNCTION security.block_firewall_ip();
