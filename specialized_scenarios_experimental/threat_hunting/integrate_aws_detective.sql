\c db_dev;

-- 1) Create table to store AWS Detective forensic analysis findings
CREATE TABLE IF NOT EXISTS threat_hunting.aws_detective_findings (
    finding_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID,
    ip_address TEXT,
    suspicious_activity TEXT NOT NULL,
    severity TEXT NOT NULL,
    finding_timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- 2) Function to ingest AWS Detective findings into PostgreSQL
CREATE OR REPLACE FUNCTION threat_hunting.ingest_aws_detective_findings(json_data JSONB)
RETURNS VOID AS $$
BEGIN
    INSERT INTO threat_hunting.aws_detective_findings (user_id, ip_address, suspicious_activity, severity)
    SELECT
        user_id,
        ip_address,
        suspicious_activity,
        severity
    FROM jsonb_to_recordset(json_data) AS x(user_id UUID, ip_address TEXT, suspicious_activity TEXT, severity TEXT)
    ON CONFLICT (finding_id) DO UPDATE
    SET severity = EXCLUDED.severity,
        finding_timestamp = NOW();
END;
$$ LANGUAGE plpgsql;
