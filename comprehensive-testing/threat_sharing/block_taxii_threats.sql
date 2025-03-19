\c db_dev;

-- 1) Create function to block known high-risk threats from TAXII feeds
CREATE OR REPLACE FUNCTION threat_sharing.block_taxii_threats()
RETURNS VOID AS $$
DECLARE firewall_api_url TEXT := 'https://firewall-provider.com/api/block-ip';
DECLARE value_to_block TEXT;
DECLARE block_payload TEXT;
BEGIN
    FOR value_to_block IN
        SELECT value FROM threat_sharing.taxii_threat_indicators
        WHERE confidence_score > 80
    LOOP
        -- Construct payload to block the threat indicator
        block_payload := json_build_object(
            'value', value_to_block,
            'action', 'block',
            'reason', 'TAXII Global Threat Feed - High-Risk Indicator',
            'timestamp', NOW()
        )::TEXT;

        -- Send request to firewall provider to block threat
        PERFORM http_post(firewall_api_url, 'application/json', block_payload);
    END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Schedule automatic threat blocking every hour
SELECT cron.schedule('0 * * * *', 'SELECT threat_sharing.block_taxii_threats();');
