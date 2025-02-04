\c db_dev;

-- Retrieve the most recent security logging
SELECT * FROM logs.notification_log
ORDER BY logged_at DESC
LIMIT 10;

-- Retrieve all RLS violations
SELECT * FROM logs.notification_log
WHERE event_type = 'RLS Violation';

-- Retrieve business rule violations in the last 7 days
SELECT * FROM logs.notification_log
WHERE event_type = 'Business Rule Violation'
AND logged_at >= NOW() - INTERVAL '7 days';

-- Retrieve partition maintenance history
SELECT * FROM logs.notification_log
WHERE event_type IN ('Partition Created', 'Partition Deleted');
