\c db_dev;

-- 1) Create function to send Slack notifications
CREATE OR REPLACE FUNCTION notifications.send_slack_alert(alert_type TEXT, alert_message TEXT)
RETURNS VOID AS $$
DECLARE slack_webhook_url TEXT := 'https://hooks.slack.com/services/your-webhook-url';
DECLARE payload TEXT;
BEGIN
    payload := json_build_object(
        'text', format(':rotating_light: *%s*: %s', alert_type, alert_message)
    )::TEXT;

    -- Send POST request to Slack webhook URL
    PERFORM http_post(slack_webhook_url, 'application/json', payload);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Function to notify on business rule violations
CREATE OR REPLACE FUNCTION notifications.notify_business_rule_violation()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM notifications.send_slack_alert(
        'Business Rule Violation',
        format('User %s attempted to create an order with a negative amount at %s', current_user, NOW())
    );

    RAISE EXCEPTION 'Order total cannot be negative!';
END;
$$ LANGUAGE plpgsql;

-- 3) Attach trigger to inventory.orders
CREATE TRIGGER slack_business_rule_violation
