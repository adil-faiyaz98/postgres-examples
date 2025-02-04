\c db_dev;

-- 1) Create function to send alerts to PagerDuty
CREATE OR REPLACE FUNCTION incident_response.trigger_pagerduty_alert()
RETURNS TRIGGER AS $$
DECLARE pagerduty_api_url TEXT := 'https://events.pagerduty.com/v2/enqueue';
DECLARE pagerduty_routing_key TEXT := 'your-pagerduty-routing-key';
DECLARE incident_payload TEXT;
BEGIN
    incident_payload := json_build_object(
        'routing_key', pagerduty_routing_key,
        'event_action', 'trigger',
        'payload', json_build_object(
            'summary', format('🚨 Security Alert: %s detected', NEW.event_type),
            'source', NEW.event_source,
            'severity', 'critical',
            'custom_details', NEW.details
        )
    )::TEXT;

    -- Send alert to PagerDuty
    PERFORM http_post(pagerduty_api_url, 'application/json', incident_payload);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Attach trigger to send PagerDuty alerts
CREATE TRIGGER pagerduty_security_alert
AFTER INSERT
ON logs.notification_log
FOR EACH ROW
WHEN (NEW.event_type IN ('SQL Injection Attempt', 'Suspicious Login', 'Account Locked'))
EXECUTE FUNCTION incident_response.trigger_pagerduty_alert();
