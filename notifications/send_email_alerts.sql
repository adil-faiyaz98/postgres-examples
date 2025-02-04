\c db_dev;

-- 1) Install pgMail extension (If not installed)
CREATE EXTENSION IF NOT EXISTS pgmail;

-- 2) Configure SMTP for email delivery (Replace with your SMTP settings)
SELECT pgmail.set_smtp_server('smtp.gmail.com', 587);
SELECT pgmail.set_smtp_auth('your-email@gmail.com', 'your-email-password');

-- 3) Function to send email alerts on RLS violations
CREATE OR REPLACE FUNCTION notifications.send_rls_violation_email()
RETURNS TRIGGER AS $$
DECLARE email_subject TEXT;
DECLARE email_body TEXT;
BEGIN
    email_subject := 'PostgreSQL RLS Violation Alert!';
    email_body := format('Unauthorized access attempt detected on table: %s by user: %s at %s',
                         TG_TABLE_NAME, current_user, NOW());

    -- Send email
    PERFORM pgmail.send_email(
        'hulk_security@yourcompany.com',
        email_subject,
        email_body
    );

    RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 4) Attach trigger to customers and orders tables
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
