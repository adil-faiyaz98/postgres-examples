\c db_dev;

-- 1) Create function to block malicious IPs in AWS WAF
CREATE OR REPLACE FUNCTION security.block_malicious_ip()
RETURNS TRIGGER AS $$
DECLARE waf_api_url TEXT := 'https://your-api-gateway.amazonaws.com/block-ip';
DECLARE ip_to_block TEXT;
DECLARE block_payload TEXT;
BEGIN
    -- Extract IP from event details
    ip_to_block := NEW.details->>'ip_address';

    -- Construct JSON payload for AWS WAF API
    block_payload := json_build_object(
        'ip', ip_to_block,
        'reason', NEW.event_type,
        'logged_at', NOW()
    )::TEXT;

    -- Send request to AWS WAF to block IP
    PERFORM http_post(waf_api_url, 'application/json', block_payload);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Attach trigger to block IPs in AWS WAF
CREATE TRIGGER aws_waf_block_ip_trigger
AFTER INSERT
ON logs.notification_log
FOR EACH ROW
WHEN (NEW.event_type IN ('SQL Injection Attempt', 'Suspicious Login'))
EXECUTE FUNCTION security.block_malicious_ip();
