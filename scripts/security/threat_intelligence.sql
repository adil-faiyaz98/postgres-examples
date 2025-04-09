-- Threat Intelligence Integration for PostgreSQL Security Framework
CREATE SCHEMA IF NOT EXISTS threat_intel;

-- Create extension for HTTP requests
CREATE EXTENSION IF NOT EXISTS http;

-- Table for storing threat intelligence data
CREATE TABLE IF NOT EXISTS threat_intel.indicators (
    id SERIAL PRIMARY KEY,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reputation INTEGER,
    risk_score NUMERIC(5,2),
    malicious BOOLEAN,
    data JSONB,
    UNIQUE(type, value, source)
);

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_indicators_type_value ON threat_intel.indicators (type, value);

-- Table for storing blocklists
CREATE TABLE IF NOT EXISTS threat_intel.blocklists (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    data JSONB,
    UNIQUE(name, type, value)
);

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_blocklists_type_value ON threat_intel.blocklists (type, value);

-- Function to check if an IP is in a blocklist
CREATE OR REPLACE FUNCTION threat_intel.check_ip(
    p_ip TEXT,
    p_username TEXT DEFAULT current_user,
    p_source_ip TEXT DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
    v_result JSONB;
    v_malicious BOOLEAN := FALSE;
    v_sources JSONB := '[]'::jsonb;
    v_blocklists JSONB := '[]'::jsonb;
    v_risk_score NUMERIC := 0;
    v_indicator RECORD;
    v_blocklist RECORD;
BEGIN
    -- Check against indicators
    FOR v_indicator IN
        SELECT * FROM threat_intel.indicators
        WHERE type = 'ip' AND value = p_ip
    LOOP
        v_malicious := v_malicious OR COALESCE(v_indicator.malicious, FALSE);
        v_risk_score := GREATEST(v_risk_score, COALESCE(v_indicator.risk_score, 0));
        v_sources := v_sources || jsonb_build_object(
            'name', v_indicator.source,
            'malicious', v_indicator.malicious,
            'risk_score', v_indicator.risk_score,
            'data', v_indicator.data
        );
    END LOOP;
    
    -- Check against blocklists
    FOR v_blocklist IN
        SELECT * FROM threat_intel.blocklists
        WHERE type = 'ip' AND value = p_ip
    LOOP
        v_malicious := TRUE;
        v_risk_score := 100;
        v_blocklists := v_blocklists || jsonb_build_object(
            'name', v_blocklist.name,
            'data', v_blocklist.data
        );
    END LOOP;
    
    -- Build result
    v_result := jsonb_build_object(
        'type', 'ip',
        'value', p_ip,
        'malicious', v_malicious,
        'risk_score', v_risk_score,
        'sources', v_sources,
        'blocklists', v_blocklists
    );
    
    -- Log check in notification log if malicious
    IF v_malicious THEN
        INSERT INTO logs.notification_log (
            event_type, severity, username, source_ip, message, additional_data
        ) VALUES (
            'THREAT_INTEL_ALERT', 'HIGH', p_username, COALESCE(p_source_ip, p_ip), 
            'Malicious IP detected: ' || p_ip,
            v_result
        );
    END IF;
    
    RETURN v_result;
END;
$$ LANGUAGE plpgsql;

-- Function to check if a domain is malicious
CREATE OR REPLACE FUNCTION threat_intel.check_domain(
    p_domain TEXT,
    p_username TEXT DEFAULT current_user,
    p_source_ip TEXT DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
    v_result JSONB;
    v_malicious BOOLEAN := FALSE;
    v_sources JSONB := '[]'::jsonb;
    v_blocklists JSONB := '[]'::jsonb;
    v_risk_score NUMERIC := 0;
    v_indicator RECORD;
    v_blocklist RECORD;
BEGIN
    -- Check against indicators
    FOR v_indicator IN
        SELECT * FROM threat_intel.indicators
        WHERE type = 'domain' AND value = p_domain
    LOOP
        v_malicious := v_malicious OR COALESCE(v_indicator.malicious, FALSE);
        v_risk_score := GREATEST(v_risk_score, COALESCE(v_indicator.risk_score, 0));
        v_sources := v_sources || jsonb_build_object(
            'name', v_indicator.source,
            'malicious', v_indicator.malicious,
            'risk_score', v_indicator.risk_score,
            'data', v_indicator.data
        );
    END LOOP;
    
    -- Check against blocklists
    FOR v_blocklist IN
        SELECT * FROM threat_intel.blocklists
        WHERE type = 'domain' AND value = p_domain
    LOOP
        v_malicious := TRUE;
        v_risk_score := 100;
        v_blocklists := v_blocklists || jsonb_build_object(
            'name', v_blocklist.name,
            'data', v_blocklist.data
        );
    END LOOP;
    
    -- Build result
    v_result := jsonb_build_object(
        'type', 'domain',
        'value', p_domain,
        'malicious', v_malicious,
        'risk_score', v_risk_score,
        'sources', v_sources,
        'blocklists', v_blocklists
    );
    
    -- Log check in notification log if malicious
    IF v_malicious THEN
        INSERT INTO logs.notification_log (
            event_type, severity, username, source_ip, message, additional_data
        ) VALUES (
            'THREAT_INTEL_ALERT', 'HIGH', p_username, p_source_ip, 
            'Malicious domain detected: ' || p_domain,
            v_result
        );
    END IF;
    
    RETURN v_result;
END;
$$ LANGUAGE plpgsql;

-- Function to add an indicator
CREATE OR REPLACE FUNCTION threat_intel.add_indicator(
    p_type TEXT,
    p_value TEXT,
    p_source TEXT,
    p_malicious BOOLEAN DEFAULT NULL,
    p_risk_score NUMERIC DEFAULT NULL,
    p_data JSONB DEFAULT NULL
) RETURNS INTEGER AS $$
DECLARE
    v_id INTEGER;
BEGIN
    -- Insert or update indicator
    INSERT INTO threat_intel.indicators (
        type, value, source, malicious, risk_score, data
    ) VALUES (
        p_type, p_value, p_source, p_malicious, p_risk_score, p_data
    ) ON CONFLICT (type, value, source) DO UPDATE
    SET last_seen = NOW(),
        malicious = COALESCE(p_malicious, threat_intel.indicators.malicious),
        risk_score = COALESCE(p_risk_score, threat_intel.indicators.risk_score),
        data = COALESCE(p_data, threat_intel.indicators.data)
    RETURNING id INTO v_id;
    
    RETURN v_id;
END;
$$ LANGUAGE plpgsql;

-- Function to add a blocklist entry
CREATE OR REPLACE FUNCTION threat_intel.add_blocklist_entry(
    p_name TEXT,
    p_type TEXT,
    p_value TEXT,
    p_data JSONB DEFAULT NULL
) RETURNS INTEGER AS $$
DECLARE
    v_id INTEGER;
BEGIN
    -- Insert or update blocklist entry
    INSERT INTO threat_intel.blocklists (
        name, type, value, data
    ) VALUES (
        p_name, p_type, p_value, p_data
    ) ON CONFLICT (name, type, value) DO UPDATE
    SET updated_at = NOW(),
        data = COALESCE(p_data, threat_intel.blocklists.data)
    RETURNING id INTO v_id;
    
    RETURN v_id;
END;
$$ LANGUAGE plpgsql;

-- Function to fetch indicators from AlienVault OTX
CREATE OR REPLACE FUNCTION threat_intel.fetch_from_otx(
    p_api_key TEXT,
    p_indicator_type TEXT,
    p_indicator_value TEXT
) RETURNS JSONB AS $$
DECLARE
    v_url TEXT;
    v_response JSONB;
BEGIN
    -- Set API URL based on indicator type
    CASE p_indicator_type
        WHEN 'ip' THEN
            v_url := 'https://otx.alienvault.com/api/v1/indicators/IPv4/' || p_indicator_value || '/general';
        WHEN 'domain' THEN
            v_url := 'https://otx.alienvault.com/api/v1/indicators/domain/' || p_indicator_value || '/general';
        WHEN 'url' THEN
            v_url := 'https://otx.alienvault.com/api/v1/indicators/url/' || p_indicator_value || '/general';
        WHEN 'file_hash' THEN
            v_url := 'https://otx.alienvault.com/api/v1/indicators/file/' || p_indicator_value || '/general';
        ELSE
            RAISE EXCEPTION 'Unsupported indicator type: %', p_indicator_type;
    END CASE;
    
    -- Make API request
    SELECT content::jsonb INTO v_response
    FROM http_get(
        v_url,
        NULL,
        array[('X-OTX-API-KEY', p_api_key)]
    );
    
    -- Extract relevant data
    RETURN v_response;
END;
$$ LANGUAGE plpgsql;

-- Function to fetch indicators from AbuseIPDB
CREATE OR REPLACE FUNCTION threat_intel.fetch_from_abuseipdb(
    p_api_key TEXT,
    p_ip TEXT
) RETURNS JSONB AS $$
DECLARE
    v_url TEXT;
    v_response JSONB;
BEGIN
    -- Set API URL
    v_url := 'https://api.abuseipdb.com/api/v2/check?ipAddress=' || p_ip || '&maxAgeInDays=90';
    
    -- Make API request
    SELECT content::jsonb INTO v_response
    FROM http_get(
        v_url,
        NULL,
        array[('Key', p_api_key), ('Accept', 'application/json')]
    );
    
    -- Extract relevant data
    RETURN v_response;
END;
$$ LANGUAGE plpgsql;

-- Function to fetch Tor exit nodes
CREATE OR REPLACE FUNCTION threat_intel.fetch_tor_exit_nodes() RETURNS INTEGER AS $$
DECLARE
    v_url TEXT := 'https://check.torproject.org/exit-addresses';
    v_response TEXT;
    v_line TEXT;
    v_ip TEXT;
    v_count INTEGER := 0;
BEGIN
    -- Make HTTP request
    SELECT content INTO v_response
    FROM http_get(v_url);
    
    -- Parse response
    FOR v_line IN
        SELECT unnest(string_to_array(v_response, E'\n'))
    LOOP
        -- Extract IP address
        IF v_line LIKE 'ExitAddress %' THEN
            v_ip := split_part(v_line, ' ', 2);
            
            -- Add to blocklist
            PERFORM threat_intel.add_blocklist_entry(
                'tor_exit_nodes',
                'ip',
                v_ip,
                jsonb_build_object('source', v_url)
            );
            
            v_count := v_count + 1;
        END IF;
    END LOOP;
    
    -- Log update
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'THREAT_INTEL_UPDATE', 'INFO', current_user, 
        format('Updated Tor exit node blocklist with %s entries', v_count)
    );
    
    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

-- Function to check active connections against threat intelligence
CREATE OR REPLACE FUNCTION threat_intel.check_active_connections() RETURNS TABLE (
    pid INTEGER,
    client_ip TEXT,
    username TEXT,
    database TEXT,
    malicious BOOLEAN,
    risk_score NUMERIC,
    blocklists JSONB
) AS $$
DECLARE
    v_rec RECORD;
    v_result JSONB;
BEGIN
    FOR v_rec IN
        SELECT
            pid,
            client_addr::text AS client_ip,
            usename AS username,
            datname AS database
        FROM pg_stat_activity
        WHERE client_addr IS NOT NULL
    LOOP
        -- Check IP against threat intelligence
        v_result := threat_intel.check_ip(v_rec.client_ip, v_rec.username);
        
        -- Return results
        pid := v_rec.pid;
        client_ip := v_rec.client_ip;
        username := v_rec.username;
        database := v_rec.database;
        malicious := (v_result->>'malicious')::boolean;
        risk_score := (v_result->>'risk_score')::numeric;
        blocklists := v_result->'blocklists';
        
        RETURN NEXT;
    END LOOP;
    
    RETURN;
END;
$$ LANGUAGE plpgsql;

-- Function to get threat intelligence statistics
CREATE OR REPLACE FUNCTION threat_intel.get_stats() RETURNS TABLE (
    indicator_type TEXT,
    total_count INTEGER,
    malicious_count INTEGER,
    sources TEXT[],
    avg_risk_score NUMERIC
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        i.type,
        count(*)::INTEGER AS total_count,
        count(*) FILTER (WHERE i.malicious)::INTEGER AS malicious_count,
        array_agg(DISTINCT i.source) AS sources,
        avg(i.risk_score)::NUMERIC AS avg_risk_score
    FROM threat_intel.indicators i
    GROUP BY i.type
    ORDER BY total_count DESC;
END;
$$ LANGUAGE plpgsql;

-- Grant permissions
GRANT USAGE ON SCHEMA threat_intel TO app_user, security_admin;
GRANT SELECT ON threat_intel.indicators TO app_user, security_admin;
GRANT SELECT ON threat_intel.blocklists TO app_user, security_admin;
GRANT EXECUTE ON FUNCTION threat_intel.check_ip TO app_user, security_admin;
GRANT EXECUTE ON FUNCTION threat_intel.check_domain TO app_user, security_admin;
GRANT EXECUTE ON FUNCTION threat_intel.add_indicator TO security_admin;
GRANT EXECUTE ON FUNCTION threat_intel.add_blocklist_entry TO security_admin;
GRANT EXECUTE ON FUNCTION threat_intel.fetch_from_otx TO security_admin;
GRANT EXECUTE ON FUNCTION threat_intel.fetch_from_abuseipdb TO security_admin;
GRANT EXECUTE ON FUNCTION threat_intel.fetch_tor_exit_nodes TO security_admin;
GRANT EXECUTE ON FUNCTION threat_intel.check_active_connections TO security_admin;
GRANT EXECUTE ON FUNCTION threat_intel.get_stats TO app_user, security_admin;
