\c db_dev;

-- 1) Create function to send logs to SageMaker for AI analysis
CREATE OR REPLACE FUNCTION ml.send_logs_to_sagemaker()
RETURNS TRIGGER AS $$
DECLARE sagemaker_api_url TEXT := 'https://your-sagemaker-endpoint.amazonaws.com/v1/predict';
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

    -- Send log data to SageMaker for anomaly detection
    PERFORM http_post(sagemaker_api_url, 'application/json', log_payload);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Attach trigger to send logs to SageMaker
CREATE TRIGGER sagemaker_anomaly_trigger
AFTER INSERT
ON logs.notification_log
FOR EACH ROW
WHEN (NEW.event_type IN ('SQL Injection Attempt', 'Suspicious Login', 'Account Locked'))
EXECUTE FUNCTION ml.send_logs_to_sagemaker();
