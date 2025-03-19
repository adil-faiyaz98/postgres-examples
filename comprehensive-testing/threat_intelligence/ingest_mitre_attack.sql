\c db_dev;

-- 1) Create table to store MITRE ATT&CK techniques and tactics
CREATE TABLE IF NOT EXISTS threat_intelligence.mitre_attack_mapping (
    attack_id TEXT PRIMARY KEY,
    technique TEXT NOT NULL,
    tactic TEXT NOT NULL,
    description TEXT,
    last_updated TIMESTAMPTZ DEFAULT NOW()
);

-- 2) Function to ingest MITRE ATT&CK data from external JSON feed
CREATE OR REPLACE FUNCTION threat_intelligence.ingest_mitre_attack_data(json_data JSONB)
RETURNS VOID AS $$
BEGIN
    INSERT INTO threat_intelligence.mitre_attack_mapping (attack_id, technique, tactic, description)
    SELECT
        attack_id,
        technique,
        tactic,
        description
    FROM jsonb_to_recordset(json_data) AS x(attack_id TEXT, technique TEXT, tactic TEXT, description TEXT)
    ON CONFLICT (attack_id) DO UPDATE
    SET technique = EXCLUDED.technique,
        tactic = EXCLUDED.tactic,
        description = EXCLUDED.description,
        last_updated = NOW();
END;
$$ LANGUAGE plpgsql;
