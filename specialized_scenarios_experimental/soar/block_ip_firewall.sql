\c db_dev;

-- 1) Create function to block IPs flagged by SOAR as high-risk
CREATE OR REPLACE FUNCTION soar.block_ai_detected_ip()
RETURNS TRIGGER AS $$
DECLARE firewall_api_url TEXT := 'https://firewall-provider.com/api/block-ip';
DECLARE ip_to_block TEXT;
DECLARE firewall_payload TEXT;
BEGIN
    -- Extract IP from SOAR action logs
    ip_to_block := NEW.details->>'ip_address';

    -- Construct JSON payload to block the IP
    firewall_payload := json_build_object(
        'ip', ip_to_block,
        'action', 'block',
        'reason', 'SOAR AI-Predicted High-Risk Activity',
        'timestamp', NOW()
    )::TEXT;

    -- Send request to firewall provider to block IP
    PERFORM http_post(firewall_api_url, 'application/json', firewall_payload);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Attach trigger to block high-risk IPs in firewall via SOAR
CREATE TRIGGER soar_block_ai_detected_ip_trigger
AFTER INSERT
ON soar.soar_action_logs
FOR EACH ROW
WHEN (NEW.action_type = 'Block High-Risk IP')
EXECUTE FUNCTION soar.block_ai_detected_ip();
