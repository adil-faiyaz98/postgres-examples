\c db_dev;

-- 1) Create function to send security alerts to AWS Lambda
CREATE OR REPLACE FUNCTION security.send_security_alert_to_lambda()
RETURNS TRIGGER AS $$
DECLARE lambda_webhook_url TEXT := 'https://your-api-gateway.amazonaws.com/security-alerts';
DECLARE alert_payload TEXT;
BEGIN
    alert_payload := json_build_object(
        'alert_type', NEW.event_type,
        'source', NEW.event_source,
        'details', NEW.details,
        'logged_by', NEW.logged_by,
        'logged_at', NEW.logged_at
    )::TEXT;

    -- Send security alert to AWS Lambda
    PERFORM http_post(lambda_webhook_url, 'application/json', alert_payload);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Attach trigger to send security events to AWS Lambda
CREATE TRIGGER aws_lambda_security_alert_trigger
AFTER INSERT
ON logs.notification_log
FOR EACH ROW
WHEN (NEW.event_type IN ('SQL Injection Attempt', 'Suspicious Login', 'Privilege Escalation Attempt'))
EXECUTE FUNCTION security.send_security_alert_to_lambda();
