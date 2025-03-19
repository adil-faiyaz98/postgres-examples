\c db_dev;

-- 1) Create table to store forensic evidence collected during incident response
CREATE TABLE IF NOT EXISTS irp.forensic_evidence (
    evidence_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID,
    session_id UUID,
    ip_address TEXT,
    executed_query TEXT,
    event_type TEXT NOT NULL,
    captured_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2) Function to collect forensic evidence on detected security threats
CREATE OR REPLACE FUNCTION irp.collect_forensic_evidence()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO irp.forensic_evidence (user_id, session_id, ip_address, executed_query, event_type)
    SELECT
        NEW.details->>'user_id'::UUID,
        NEW.details->>'session_id'::UUID,
        NEW.details->>'ip_address',
        NEW.details->>'executed_query',
        NEW.event_type
    FROM logs.notification_log
    WHERE event_type IN ('SQL Injection Attempt', 'Suspicious Login', 'Privilege Escalation Attempt');

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 3) Attach trigger to automatically collect forensic evidence
CREATE TRIGGER forensic_evidence_collection_trigger
AFTER INSERT
ON logs.notification_log
FOR EACH ROW
WHEN (NEW.event_type IN ('SQL Injection Attempt', 'Suspicious Login', 'Privilege Escalation Attempt'))
EXECUTE FUNCTION irp.collect_forensic_evidence();
