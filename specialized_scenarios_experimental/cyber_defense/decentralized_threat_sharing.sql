\c db_dev;

-- 1) Create table to store threat intelligence shared across PostgreSQL security nodes
CREATE TABLE IF NOT EXISTS global_cyber_defense.shared_threat_intelligence (
    threat_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    shared_by_node UUID NOT NULL REFERENCES global_cyber_defense.defense_nodes(node_id),
    threat_type TEXT NOT NULL,
    threat_details JSONB NOT NULL,
    confidence_score NUMERIC DEFAULT 75,
    shared_timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- 2) Function to share PostgreSQL AI-detected security threats with a global security grid
CREATE OR REPLACE FUNCTION global_cyber_defense.share_threat_intelligence()
RETURNS VOID AS $$
DECLARE threat_server_url TEXT := 'https://decentralized-threat-network.com/api/share-threat';
DECLARE threat_payload TEXT;
BEGIN
    -- Select latest AI-detected security threat
    SELECT threat_details INTO threat_payload
    FROM global_cyber_defense.shared_threat_intelligence
    ORDER BY shared_timestamp DESC
    LIMIT 1;

    -- Send threat intelligence to decentralized security network
    PERFORM http_post(threat_server_url, 'application/json', json_build_object('threat', threat_payload));

    -- Log AI-driven threat intelligence sharing
    INSERT INTO logs.notification_log (event_type, event_source, details, logged_by, logged_at)
    VALUES ('AI Threat Intelligence Shared', 'global_cyber_defense.share_threat_intelligence', json_build_object('timestamp', NOW()), 'system', NOW());
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 3) Automate PostgreSQL AI threat sharing every 6 hours
SELECT cron.schedule('0 */6 * * *', 'SELECT global_cyber_defense.share_threat_intelligence();');
