\c db_dev;

-- Function to detect SQL injection patterns using regex
CREATE OR REPLACE FUNCTION security.detect_sql_injection()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.query ~* '(?i)(union select|information_schema|1=1|xp_cmdshell|pg_sleep|char\()' THEN

        -- Log the SQL injection attempt
        INSERT INTO logs.notification_log (event_type, event_source, details, logged_by, logged_at)
        VALUES ('SQL Injection Attempt', 'database_queries', json_build_object('query', NEW.query, 'user', current_user), current_user, NOW());

        -- Send alert
        PERFORM pg_notify('security_alert', json_build_object(
            'event', 'SQL Injection Attempt',
            'user', current_user,
            'query', NEW.query,
            'timestamp', NOW()
        )::TEXT);

        -- Raise an exception to block execution
        RAISE EXCEPTION 'Potential SQL Injection attempt detected!';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Attach trigger to log queries and detect injections
CREATE TRIGGER sql_injection_detector
BEFORE INSERT ON logs.query_log
FOR EACH ROW
EXECUTE FUNCTION security.detect_sql_injection();
