\c db_dev;

-- 1) Create function to send PostgreSQL logs to AWS Lookout for anomaly detection
CREATE OR REPLACE FUNCTION ml.send_logs_to_aws_lookout()
RETURNS TRIGGER AS $$
DECLARE lookout_api_url TEXT := 'https://your-lookout-endpoint.amazonaws.com/v1/metrics';
DECLARE log_payload TEXT;
BEGIN
    log_payload := json_build_object(
        'log_id', NEW.log_id,
        'event_type', NEW.event_type,
        'event_source', NEW.event_source,
        'details', NEW.details,
        'logged_by', NEW.logged_by,
        'logged_at', NEW.logged_at
    )::TEXT;

    -- Send log data to AWS Lookout for Metrics
    PERFORM http_post(lookout_api_url, 'application/json', log_payload);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Attach trigger to send security logs to AWS Lookout for AI detection
CREATE TRIGGER aws_lookout_anomaly_trigger
AFTER INSERT
ON logs.notification_log
FOR EACH ROW
WHEN (NEW.event_type IN ('Suspicious Login', 'SQL Injection Attempt', 'Privilege Escalation Attempt'))
EXECUTE FUNCTION ml.send_logs_to_aws_lookout();
