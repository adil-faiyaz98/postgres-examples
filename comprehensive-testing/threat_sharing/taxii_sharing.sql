\c db_dev;

-- 1) Create function to send PostgreSQL security incidents to a TAXII server
CREATE OR REPLACE FUNCTION threat_sharing.publish_to_taxii()
RETURNS TRIGGER AS $$
DECLARE taxii_server_url TEXT := 'https://your-taxii-server.com/api/collections';
DECLARE taxii_payload TEXT;
BEGIN
    taxii_payload := json_build_object(
        'type', 'bundle',
        'objects', ARRAY[
            json_build_object(
                'type', 'indicator',
                'id', NEW.stix_id,
                'created', NEW.created,
                'modified', NEW.modified,
                'labels', NEW.labels,
                'pattern', NEW.pattern,
                'confidence', NEW.confidence,
                'external_references', NEW.external_references
            )
        ]
    )::TEXT;

    -- Send PostgreSQL security incidents to TAXII server
    PERFORM http_post(taxii_server_url, 'application/json', taxii_payload);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2) Attach trigger to automatically publish PostgreSQL security intelligence to TAXII
CREATE TRIGGER taxii_publish_security_threat_trigger
AFTER INSER
