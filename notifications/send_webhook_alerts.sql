\c db_dev;

-- Function to send JSON payloads to an external Webhook
CREATE OR REPLACE FUNCTION notifications.send_webhook_alert(event_type TEXT, event_details TEXT)
RETURNS VOID AS $$
DECLARE webhook_url TEXT := current_setting('custom.webhook_url', TRUE);
DECLARE payload TEXT;
BEGIN
    payload := json_build_object(
        'event_type', event_type,
        'details', event_details,
        'timestamp', NOW()
    )::TEXT;

    -- Send Webhook POST request
    PERFORM http_post(webhook_url, 'application/json', payload);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to notify when new partitions are created
CREATE OR REPLACE FUNCTION accounting.notify_partition_creation_webhook()
RETURNS VOID AS $$
DECLARE next_partition TEXT;
BEGIN
    next_partition := 'transactions_' || to_char(NOW() + INTERVAL '1 month', 'YYYY_MM');

    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS accounting.%I
         PARTITION OF accounting.transactions
         FOR VALUES FROM (%L) TO (%L);',
        next_partition,
        date_trunc('month', NOW() + INTERVAL '1 month'),
        date_trunc('month', NOW() + INTERVAL '2 months')
    );

    -- Send Webhook Notification
    PERFORM notifications.send_webhook_alert(
        'Partition Created',
        format('New partition %s created at %s', next_partition, NOW())
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Automate webhook notifications for partition maintenance
SELECT cron.schedule('0 0 1 * *', 'SELECT accounting.notify_partition_creation_webhook();');
