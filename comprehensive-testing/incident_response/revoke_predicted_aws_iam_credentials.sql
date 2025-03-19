\c db_dev;

-- 1) Create function to revoke AI-flagged AWS IAM credentials
CREATE OR REPLACE FUNCTION security.revoke_predicted_iam_credentials()
RETURNS TRIGGER AS $$
DECLARE revoke_iam_api_url TEXT := 'https://your-api-gateway.amazonaws.com/revoke-iam';
DECLARE revoke_payload TEXT;
BEGIN
    -- Construct JSON payload with user details
    revoke_payload := json_build_object(
        'user_id', NEW.details->>'user_id',
        'action', 'revoke-iam-credentials',
        'reason', 'AI Predicted Privilege Escalation',
        'timestamp', NOW()
    )::TEXT;

    -- Send request to AWS API Gateway to revoke IAM credentials
    PERFORM http_post(revoke_iam_api_url, 'application/json', revoke_payload);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Attach trigger to revoke IAM credentials for AI-predicted threats
CREATE TRIGGER aws_revoke_predicted_iam_trigger
AFTER INSERT
ON ml.anomaly_predictions
FOR EACH ROW
WHEN (NEW.event_type = 'Privilege Escalation Attempt' AND NEW.detected_anomaly = TRUE)
EXECUTE FUNCTION security.revoke_predicted_iam_credentials();
