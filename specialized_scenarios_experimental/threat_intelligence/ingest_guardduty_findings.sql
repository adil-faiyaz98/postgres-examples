\c db_dev;

-- 1) Create table to store AWS GuardDuty threat intelligence findings
CREATE TABLE IF NOT EXISTS threat_intelligence.aws_guardduty_findings (
    finding_id TEXT PRIMARY KEY,
    severity TEXT NOT NULL,
    description TEXT,
    resource TEXT,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- 2) Function to ingest AWS GuardDuty findings from JSON feed
CREATE OR REPLACE FUNCTION threat_intelligence.ingest_guardduty_findings(json_data JSONB)
RETURNS VOID AS $$
BEGIN
    INSERT INTO threat_intelligence.aws_guardduty_findings (finding_id, severity, description, resource)
    SELECT
        finding_id,
        severity,
        description,
        resource
    FROM jsonb_to_recordset(json_data) AS x(finding_id TEXT, severity TEXT, description TEXT, resource TEXT)
    ON CONFLICT (finding_id) DO UPDATE
    SET severity = EXCLUDED.severity,
        description = EXCLUDED.description,
        resource = EXCLUDED.resource,
        timestamp = NOW();
END;
$$ LANGUAGE plpgsql;
