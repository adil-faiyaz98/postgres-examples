\c db_dev;

-- 1) Create function to send security logs to Amazon Forecast
CREATE OR REPLACE FUNCTION ml.send_logs_to_amazon_forecast()
RETURNS TRIGGER AS $$
DECLARE forecast_api_url TEXT := 'https://forecast.amazonaws.com/v1/predict';
DECLARE log_payload TEXT;
BEGIN
    log_payload := json_build_object(
        'event_type', NEW.event_type,
        'user_id', NEW.details->>'user_id',
        'timestamp', NEW.logged_at
    )::TEXT;

    -- Send log data to AWS Forecast
    PERFORM http_post(forecast_api_url, 'application/json', log_payload);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Attach trigger to send security logs for AI-based future prediction
CREATE TRIGGER aws_forecast_prediction_trigger
AFTER INSERT
ON logs.notification_log
FOR EACH ROW
WHEN (NEW.event_type IN ('Suspicious Login', 'SQL Injection Attempt', 'Privilege Escalation Attempt'))
EXECUTE FUNCTION ml.send_logs_to_amazon_forecast();
