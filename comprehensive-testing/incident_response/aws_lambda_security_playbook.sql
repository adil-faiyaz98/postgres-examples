\c db_dev;

-- 1) Create function to trigger AWS Lambda for AI-predicted security threats
CREATE OR REPLACE FUNCTION security.trigger_aws_lambda_security_playbook()
RETURNS TRIGGER AS $$
DECLARE lambda_webhook_url TEXT := 'https://your-api-gateway.amazonaws.com/security-playbook';
DECLARE security_payload TEXT;
BEGIN
    security_payload := json_build_object(
        'event_type', NEW.event_type,
        'user_id', NEW.details->>'user_id',
        'ip_address', NEW.details->>'ip_address',
        'action', 'execute-security-playbook',
        'timestamp', NOW()
    )::TEXT;

    -- Send security alert to AWS Lambda
    PERFORM http_post(lambda_webhook_url, 'application/json', security_payload);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Attach trigger to execute security playbooks via AWS Lambda
CREATE TRIGGER aws_lambda_security_playbook_trigger
AFTER INSERT
ON ml.anomaly_predictions
FOR EACH ROW
WHEN (NEW.detected_anomaly = TRUE)
EXECUTE FUNCTION security.trigger_aws_lambda_security_playbook();
