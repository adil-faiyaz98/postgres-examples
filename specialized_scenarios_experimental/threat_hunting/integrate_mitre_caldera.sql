\c db_dev;

-- 1) Create table to store detected MITRE CALDERA adversary tactics in PostgreSQL
CREATE TABLE IF NOT EXISTS threat_hunting.mitre_caldera_detections (
    detection_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    adversary_id TEXT NOT NULL,
    tactic TEXT NOT NULL,
    technique TEXT NOT NULL,
    detection_timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- 2) Function to ingest MITRE CALDERA detections into PostgreSQL
CREATE OR REPLACE FUNCTION threat_hunting.ingest_mitre_caldera_detections(json_data JSONB)
RETURNS VOID AS $$
BEGIN
    INSERT INTO threat_hunting.mitre_caldera_detections (adversary_id, tactic, technique)
    SELECT
        adversary_id,
        tactic,
        technique
    FROM jsonb_to_recordset(json_data) AS x(adversary_id TEXT, tactic TEXT, technique TEXT)
    ON CONFLICT (adversary_id) DO UPDATE
    SET tactic = EXCLUDED.tactic,
        technique = EXCLUDED.technique,
        detection_timestamp = NOW();
END;
$$ LANGUAGE plpgsql;
