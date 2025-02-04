\c db_dev;

-- 1) Create table to store Open Threat Exchange (OTX) threat indicators
CREATE TABLE IF NOT EXISTS threat_intelligence.otx_threat_indicators (
    indicator TEXT PRIMARY KEY,
    indicator_type TEXT NOT NULL,  -- (e.g., 'IP', 'Domain', 'Hash')
    description TEXT,
    confidence_score NUMERIC DEFAULT 1.0,
    last_seen TIMESTAMPTZ DEFAULT NOW()
);

-- 2) Function to ingest OTX threat indicators from JSON feed
CREATE OR REPLACE FUNCTION threat_intelligence.ingest_otx_threat_indicators(json_data JSONB)
RETURNS VOID AS $$
BEGIN
    INSERT INTO threat_intelligence.otx_threat_indicators (indicator, indicator_type, description, confidence_score)
    SELECT
        indicator,
        indicator_type,
        description,
        confidence_score
    FROM jsonb_to_recordset(json_data) AS x(indicator TEXT, indicator_type TEXT, description TEXT, confidence_score NUMERIC)
    ON CONFLICT (indicator) DO UPDATE
    SET indicator_type = EXCLUDED.indicator_type,
        description = EXCLUDED.description,
        confidence_score = EXCLUDED.confidence_score,
        last_seen = NOW();
END;
$$ LANGUAGE plpgsql;
