\c db_dev;

-- 1) Create table to store global threat indicators from TAXII
CREATE TABLE IF NOT EXISTS threat_sharing.taxii_threat_indicators (
    taxii_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    indicator_type TEXT NOT NULL,  -- (e.g., 'IP', 'Domain', 'Malware Hash')
    value TEXT NOT NULL,  -- The actual IP, domain, or hash
    confidence_score INTEGER DEFAULT 75,
    last_seen TIMESTAMPTZ DEFAULT NOW()
);

-- 2) Function to ingest threat indicators from TAXII into PostgreSQL
CREATE OR REPLACE FUNCTION threat_sharing.ingest_taxii_threat_indicators(json_data JSONB)
RETURNS VOID AS $$
BEGIN
    INSERT INTO threat_sharing.taxii_threat_indicators (indicator_type, value, confidence_score)
    SELECT
        indicator_type,
        value,
        confidence_score
    FROM jsonb_to_recordset(json_data) AS x(indicator_type TEXT, value TEXT, confidence_score INTEGER)
    ON CONFLICT (value) DO UPDATE
    SET confidence_score = EXCLUDED.confidence_score,
        last_seen = NOW();
END;
$$ LANGUAGE plpgsql;
