\c db_dev;

-- Install pgMail extension (if not installed)
CREATE EXTENSION IF NOT EXISTS pgmail;

-- Configure SMTP securely
SELECT pgmail.set_smtp_server('smtp.gmail.com', 587);
SELECT pgmail.set_smtp_auth('your-email@gmail.com', current_setting('custom.smtp_password', TRUE));

-- Function to send email alerts on RLS violations
CREATE OR REPLACE FUNCTION notifications.send_rls_violation_email()
RETURNS TRIGGER AS $$
DECLARE email_subject TEXT;
DECLARE email_body TEXT;
BEGIN
    email_subject := 'PostgreSQL RLS Violation Alert!';
    email_body := format('Unauthorized access attempt detected on table: %s by user: %s at %s',
                         TG_TABLE_NAME, current_user, NOW());

    -- Send email securely
    PERFORM pgmail.send_email(
        'security@yourcompany.com',
        email_subject,
        email_body
    );

    RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Attach trigger to customers and orders tables
CREATE TRIGGER email_rls_violation
BEFORE SELECT OR UPDATE OR DELETE
ON inventory.customers
FOR EACH ROW
EXECUTE FUNCTION notifications.send_rls_violation_email();

CREATE TRIGGER email_rls_violation_orders
BEFORE SELECT OR UPDATE OR DELETE
ON inventory.orders
FOR EACH ROW
EXECUTE FUNCTION notifications.send_rls_violation_email();
