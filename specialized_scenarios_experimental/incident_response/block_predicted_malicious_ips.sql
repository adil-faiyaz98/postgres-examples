\c db_dev;

-- 1) Create function to block AI-detected malicious IPs in AWS WAF
CREATE OR REPLACE FUNCTION security.block_ai_predicted_ip()
RETURNS TRIGGER AS $$
DECLARE firewall_api_url TEXT := 'https://your-api-gateway.amazonaws.com/block-ip';
DECLARE ip_to_block TEXT;
DECLARE block_payload TEXT;
BEGIN
    -- Extract predicted high-risk IP from AI anomaly detection
    ip_to_block := NEW.details->>'ip_address';

    -- Construct JSON payload for AWS WAF
    block_payload := json_build_object(
        'ip', ip_to_block,
        'action', 'block',
        'reason', 'AI Predicted Security Threat',
        'timestamp', NOW()
    )::TEXT;

    -- Send request to AWS API Gateway to update WAF rules
    PERFORM http_post(firewall_api_url, 'application/json', block_payload);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Attach trigger to block AI-predicted malicious IPs
CREATE TRIGGER firewall_block_predicted_ip_trigger
AFTER INSERT
ON ml.anomaly_predictions
FOR EACH ROW
WHEN (NEW.event_type = 'SQL Injection Attempt' AND NEW.detected_anomaly = TRUE)
EXECUTE FUNCTION security.block_ai_predicted_ip();
