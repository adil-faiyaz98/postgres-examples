-- Advanced Analytics for PostgreSQL Security Framework
CREATE SCHEMA IF NOT EXISTS analytics;

-- Create extension for machine learning
CREATE EXTENSION IF NOT EXISTS plpython3u;

-- Table for storing query patterns
CREATE TABLE IF NOT EXISTS analytics.query_patterns (
    id SERIAL PRIMARY KEY,
    query_pattern TEXT NOT NULL,
    query_hash TEXT NOT NULL,
    frequency INTEGER NOT NULL DEFAULT 1,
    avg_duration NUMERIC,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_anomalous BOOLEAN NOT NULL DEFAULT FALSE,
    anomaly_score NUMERIC,
    UNIQUE(query_hash)
);

-- Table for storing user behavior profiles
CREATE TABLE IF NOT EXISTS analytics.user_profiles (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    login_hour_distribution INTEGER[] NOT NULL DEFAULT ARRAY[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
    query_type_distribution JSONB NOT NULL DEFAULT '{}'::jsonb,
    avg_queries_per_day INTEGER,
    avg_session_duration NUMERIC,
    common_source_ips TEXT[],
    last_updated TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(username)
);

-- Table for storing anomalies
CREATE TABLE IF NOT EXISTS analytics.anomalies (
    id SERIAL PRIMARY KEY,
    anomaly_type TEXT NOT NULL,
    username TEXT,
    source_ip TEXT,
    severity TEXT NOT NULL,
    score NUMERIC NOT NULL,
    description TEXT NOT NULL,
    details JSONB,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved BOOLEAN NOT NULL DEFAULT FALSE,
    resolved_at TIMESTAMPTZ,
    resolution_notes TEXT
);

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_anomalies_username ON analytics.anomalies (username);
CREATE INDEX IF NOT EXISTS idx_anomalies_detected_at ON analytics.anomalies (detected_at);

-- Function to normalize a SQL query
CREATE OR REPLACE FUNCTION analytics.normalize_query(
    p_query TEXT
) RETURNS TEXT AS $$
import re

def normalize_query(query):
    # Convert to lowercase
    query = query.lower()

    # Remove comments
    query = re.sub(r'--.*?$', '', query, flags=re.MULTILINE)
    query = re.sub(r'/\*.*?\*/', '', query, flags=re.DOTALL)

    # Replace literals
    query = re.sub(r"'[^']*'", "'?'", query)  # String literals
    query = re.sub(r'\b\d+\b', '?', query)    # Number literals

    # Replace IN lists
    query = re.sub(r'in\s*\([^)]+\)', 'in (?)', query)

    # Replace multiple whitespace with a single space
    query = re.sub(r'\s+', ' ', query)

    return query.strip()

return normalize_query(p_query)
$$ LANGUAGE plpython3u;

-- Function to extract query type
CREATE OR REPLACE FUNCTION analytics.extract_query_type(
    p_query TEXT
) RETURNS TEXT AS $$
import re

def extract_query_type(query):
    # Convert to lowercase and remove leading/trailing whitespace
    query = query.lower().strip()

    # Extract the first word (command)
    match = re.match(r'^(\w+)', query)
    if match:
        command = match.group(1)

        # Map to query type
        if command in ('select'):
            return 'SELECT'
        elif command in ('insert'):
            return 'INSERT'
        elif command in ('update'):
            return 'UPDATE'
        elif command in ('delete'):
            return 'DELETE'
        elif command in ('create'):
            return 'CREATE'
        elif command in ('alter'):
            return 'ALTER'
        elif command in ('drop'):
            return 'DROP'
        elif command in ('grant', 'revoke'):
            return 'PERMISSION'
        elif command in ('begin', 'commit', 'rollback'):
            return 'TRANSACTION'
        else:
            return 'OTHER'

    return 'UNKNOWN'

return extract_query_type(p_query)
$$ LANGUAGE plpython3u;

-- Function to update query patterns
CREATE OR REPLACE FUNCTION analytics.update_query_patterns(
    p_query TEXT,
    p_duration NUMERIC
) RETURNS INTEGER AS $$
DECLARE
    v_normalized_query TEXT;
    v_query_hash TEXT;
    v_pattern_id INTEGER;
BEGIN
    -- Normalize query
    v_normalized_query := analytics.normalize_query(p_query);

    -- Generate hash
    v_query_hash := md5(v_normalized_query);

    -- Update or insert pattern
    INSERT INTO analytics.query_patterns (
        query_pattern, query_hash, frequency, avg_duration, last_seen
    ) VALUES (
        v_normalized_query, v_query_hash, 1, p_duration, NOW()
    ) ON CONFLICT (query_hash) DO UPDATE
    SET frequency = analytics.query_patterns.frequency + 1,
        avg_duration = (analytics.query_patterns.avg_duration * analytics.query_patterns.frequency + p_duration) / (analytics.query_patterns.frequency + 1),
        last_seen = NOW()
    RETURNING id INTO v_pattern_id;

    RETURN v_pattern_id;
END;
$$ LANGUAGE plpgsql;

-- Function to update user profiles
CREATE OR REPLACE FUNCTION analytics.update_user_profile(
    p_username TEXT,
    p_query TEXT DEFAULT NULL,
    p_login_hour INTEGER DEFAULT NULL,
    p_session_duration NUMERIC DEFAULT NULL,
    p_source_ip TEXT DEFAULT NULL
) RETURNS VOID AS $$
DECLARE
    v_profile RECORD;
    v_query_type TEXT;
    v_query_types JSONB;
    v_login_hours INTEGER[];
    v_source_ips TEXT[];
BEGIN
    -- Get existing profile
    SELECT * INTO v_profile
    FROM analytics.user_profiles
    WHERE username = p_username;

    -- Create profile if it doesn't exist
    IF v_profile IS NULL THEN
        INSERT INTO analytics.user_profiles (username)
        VALUES (p_username)
        RETURNING * INTO v_profile;
    END IF;

    -- Update query type distribution
    IF p_query IS NOT NULL THEN
        v_query_type := analytics.extract_query_type(p_query);
        v_query_types := v_profile.query_type_distribution;

        IF v_query_types ? v_query_type THEN
            v_query_types := jsonb_set(
                v_query_types,
                ARRAY[v_query_type],
                to_jsonb((v_query_types->>v_query_type)::INTEGER + 1)
            );
        ELSE
            v_query_types := v_query_types || jsonb_build_object(v_query_type, 1);
        END IF;

        UPDATE analytics.user_profiles
        SET query_type_distribution = v_query_types,
            last_updated = NOW()
        WHERE username = p_username;
    END IF;

    -- Update login hour distribution
    IF p_login_hour IS NOT NULL THEN
        v_login_hours := v_profile.login_hour_distribution;
        v_login_hours[p_login_hour + 1] := v_login_hours[p_login_hour + 1] + 1;

        UPDATE analytics.user_profiles
        SET login_hour_distribution = v_login_hours,
            last_updated = NOW()
        WHERE username = p_username;
    END IF;

    -- Update session duration
    IF p_session_duration IS NOT NULL THEN
        UPDATE analytics.user_profiles
        SET avg_session_duration = CASE
                WHEN avg_session_duration IS NULL THEN p_session_duration
                ELSE (avg_session_duration + p_session_duration) / 2
            END,
            last_updated = NOW()
        WHERE username = p_username;
    END IF;

    -- Update source IPs
    IF p_source_ip IS NOT NULL THEN
        v_source_ips := v_profile.common_source_ips;

        IF NOT p_source_ip = ANY(v_source_ips) THEN
            v_source_ips := array_append(v_source_ips, p_source_ip);

            UPDATE analytics.user_profiles
            SET common_source_ips = v_source_ips,
                last_updated = NOW()
            WHERE username = p_username;
        END IF;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Function to detect query anomalies
CREATE OR REPLACE FUNCTION analytics.detect_query_anomalies() RETURNS SETOF analytics.anomalies AS $$
import numpy as np
from sklearn.ensemble import IsolationForest
import json

# Get query patterns
query_patterns = plpy.execute("""
    SELECT id, query_pattern, frequency, avg_duration
    FROM analytics.query_patterns
    WHERE frequency > 1
""")

if len(query_patterns) < 10:
    # Not enough data for anomaly detection
    return

# Prepare data for anomaly detection
X = np.array([[r['frequency'], r['avg_duration']] for r in query_patterns])

# Normalize data
X_mean = np.mean(X, axis=0)
X_std = np.std(X, axis=0)
X_norm = (X - X_mean) / X_std

# Train isolation forest model
model = IsolationForest(contamination=0.05, random_state=42)
model.fit(X_norm)

# Predict anomalies
anomaly_scores = model.decision_function(X_norm)
predictions = model.predict(X_norm)

# Update query patterns and create anomaly records
for i, pred in enumerate(predictions):
    if pred == -1:  # Anomaly
        pattern = query_patterns[i]
        anomaly_score = -anomaly_scores[i]  # Convert to positive score

        # Update query pattern
        plpy.execute(f"""
            UPDATE analytics.query_patterns
            SET is_anomalous = TRUE,
                anomaly_score = {anomaly_score}
            WHERE id = {pattern['id']}
        """)

        # Create anomaly record
        result = plpy.execute(f"""
            INSERT INTO analytics.anomalies (
                anomaly_type, severity, score, description, details
            ) VALUES (
                'QUERY_PATTERN',
                CASE
                    WHEN {anomaly_score} > 0.8 THEN 'HIGH'
                    WHEN {anomaly_score} > 0.6 THEN 'MEDIUM'
                    ELSE 'LOW'
                END,
                {anomaly_score},
                'Unusual query pattern detected',
                '{json.dumps({
                    "query_pattern": pattern["query_pattern"],
                    "frequency": pattern["frequency"],
                    "avg_duration": pattern["avg_duration"]
                })}'::jsonb
            ) RETURNING *
        """)

        # Yield anomaly record
        for r in result:
            yield r

$$ LANGUAGE plpython3u;

-- Function to detect user behavior anomalies
CREATE OR REPLACE FUNCTION analytics.detect_user_anomalies() RETURNS SETOF analytics.anomalies AS $$
import numpy as np
from sklearn.ensemble import IsolationForest
import json
from datetime import datetime

# Get user profiles
user_profiles = plpy.execute("""
    SELECT username, login_hour_distribution, query_type_distribution,
           avg_session_duration, common_source_ips
    FROM analytics.user_profiles
""")

if len(user_profiles) < 5:
    # Not enough data for anomaly detection
    return

# Get recent user activity
recent_activity = plpy.execute("""
    SELECT username,
           EXTRACT(HOUR FROM query_start) AS login_hour,
           client_addr AS source_ip,
           EXTRACT(EPOCH FROM (NOW() - query_start)) AS session_duration,
           query
    FROM pg_stat_activity
    WHERE username IS NOT NULL
      AND query_start IS NOT NULL
      AND query != '<IDLE>'
      AND pid != pg_backend_pid()
""")

# Process each user's recent activity
for activity in recent_activity:
    username = activity['username']
    login_hour = int(activity['login_hour'])
    source_ip = activity['source_ip']
    session_duration = activity['session_duration']
    query = activity['query']

    # Find user profile
    user_profile = None
    for profile in user_profiles:
        if profile['username'] == username:
            user_profile = profile
            break

    if user_profile is None:
        continue

    # Check for anomalies
    anomalies = []

    # Check login hour anomaly
    hour_dist = user_profile['login_hour_distribution']
    if hour_dist[login_hour] == 0:
        anomalies.append({
            'type': 'UNUSUAL_LOGIN_TIME',
            'severity': 'MEDIUM',
            'score': 0.7,
            'description': f'User {username} logged in at unusual hour {login_hour}',
            'details': {
                'username': username,
                'login_hour': login_hour,
                'normal_hours': [i for i, count in enumerate(hour_dist) if count > 0]
            }
        })

    # Check source IP anomaly
    common_ips = user_profile['common_source_ips']
    if source_ip not in common_ips:
        anomalies.append({
            'type': 'NEW_SOURCE_IP',
            'severity': 'HIGH',
            'score': 0.9,
            'description': f'User {username} connected from new IP {source_ip}',
            'details': {
                'username': username,
                'new_ip': source_ip,
                'common_ips': common_ips
            }
        })

    # Check session duration anomaly
    avg_duration = user_profile['avg_session_duration']
    if avg_duration and session_duration > avg_duration * 3:
        anomalies.append({
            'type': 'LONG_SESSION',
            'severity': 'LOW',
            'score': 0.5,
            'description': f'User {username} has unusually long session',
            'details': {
                'username': username,
                'session_duration': session_duration,
                'avg_duration': avg_duration
            }
        })

    # Create anomaly records
    for anomaly in anomalies:
        result = plpy.execute(f"""
            INSERT INTO analytics.anomalies (
                anomaly_type, username, source_ip, severity, score, description, details
            ) VALUES (
                '{anomaly['type']}',
                '{username}',
                '{source_ip}',
                '{anomaly['severity']}',
                {anomaly['score']},
                '{anomaly['description']}',
                '{json.dumps(anomaly['details'])}'::jsonb
            ) RETURNING *
        """)

        # Yield anomaly record
        for r in result:
            yield r

$$ LANGUAGE plpython3u;

-- Function to get recent anomalies
CREATE OR REPLACE FUNCTION analytics.get_recent_anomalies(
    p_hours INTEGER DEFAULT 24,
    p_min_severity TEXT DEFAULT 'LOW'
) RETURNS TABLE (
    id INTEGER,
    anomaly_type TEXT,
    username TEXT,
    source_ip TEXT,
    severity TEXT,
    score NUMERIC,
    description TEXT,
    details JSONB,
    detected_at TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        a.id,
        a.anomaly_type,
        a.username,
        a.source_ip,
        a.severity,
        a.score,
        a.description,
        a.details,
        a.detected_at
    FROM analytics.anomalies a
    WHERE a.detected_at >= NOW() - (p_hours || ' hours')::INTERVAL
      AND a.resolved = FALSE
      AND CASE
            WHEN p_min_severity = 'HIGH' THEN a.severity = 'HIGH'
            WHEN p_min_severity = 'MEDIUM' THEN a.severity IN ('HIGH', 'MEDIUM')
            ELSE a.severity IN ('HIGH', 'MEDIUM', 'LOW')
          END
    ORDER BY a.score DESC, a.detected_at DESC;
END;
$$ LANGUAGE plpgsql;

-- Function to resolve an anomaly
CREATE OR REPLACE FUNCTION analytics.resolve_anomaly(
    p_anomaly_id INTEGER,
    p_resolution_notes TEXT
) RETURNS VOID AS $$
BEGIN
    UPDATE analytics.anomalies
    SET resolved = TRUE,
        resolved_at = NOW(),
        resolution_notes = p_resolution_notes
    WHERE id = p_anomaly_id;

    -- Log resolution
    INSERT INTO logs.notification_log (
        event_type, severity, username, message
    ) VALUES (
        'ANOMALY_RESOLVED', 'INFO', current_user,
        format('Resolved anomaly %s: %s', p_anomaly_id, p_resolution_notes)
    );
END;
$$ LANGUAGE plpgsql;

-- Function to get user activity summary
CREATE OR REPLACE FUNCTION analytics.get_user_activity_summary(
    p_username TEXT DEFAULT NULL,
    p_days INTEGER DEFAULT 7
) RETURNS TABLE (
    username TEXT,
    query_count INTEGER,
    avg_queries_per_day NUMERIC,
    most_common_query_type TEXT,
    most_active_hour INTEGER,
    distinct_source_ips INTEGER,
    anomaly_count INTEGER
) AS $$
BEGIN
    RETURN QUERY
    WITH user_activity AS (
        SELECT
            s.usename AS username,
            count(*) AS query_count,
            count(*) / p_days AS avg_queries_per_day,
            mode() WITHIN GROUP (ORDER BY analytics.extract_query_type(s.query)) AS most_common_query_type,
            mode() WITHIN GROUP (ORDER BY EXTRACT(HOUR FROM s.query_start)) AS most_active_hour,
            count(DISTINCT s.client_addr) AS distinct_source_ips
        FROM pg_stat_statements ss
        JOIN pg_stat_activity s ON ss.userid = s.usesysid
        WHERE s.query_start >= NOW() - (p_days || ' days')::INTERVAL
          AND (p_username IS NULL OR s.usename = p_username)
        GROUP BY s.usename
    ),
    user_anomalies AS (
        SELECT
            username,
            count(*) AS anomaly_count
        FROM analytics.anomalies
        WHERE detected_at >= NOW() - (p_days || ' days')::INTERVAL
          AND (p_username IS NULL OR username = p_username)
        GROUP BY username
    )
    SELECT
        ua.username,
        ua.query_count,
        ua.avg_queries_per_day,
        ua.most_common_query_type,
        ua.most_active_hour::INTEGER,
        ua.distinct_source_ips,
        COALESCE(an.anomaly_count, 0) AS anomaly_count
    FROM user_activity ua
    LEFT JOIN user_anomalies an ON ua.username = an.username
    ORDER BY ua.query_count DESC;
END;
$$ LANGUAGE plpgsql;

-- Function to analyze query performance trends
CREATE OR REPLACE FUNCTION analytics.analyze_query_performance(
    p_days INTEGER DEFAULT 7,
    p_min_executions INTEGER DEFAULT 10
) RETURNS TABLE (
    query_pattern TEXT,
    executions INTEGER,
    avg_duration_ms NUMERIC,
    min_duration_ms NUMERIC,
    max_duration_ms NUMERIC,
    stddev_duration_ms NUMERIC,
    trend_direction TEXT,
    trend_percentage NUMERIC
) AS $$
DECLARE
    v_now TIMESTAMPTZ := NOW();
    v_half_period TIMESTAMPTZ := v_now - (p_days || ' days')::INTERVAL / 2;
BEGIN
    RETURN QUERY
    WITH query_stats AS (
        SELECT
            qp.query_pattern,
            count(*) AS executions,
            avg(qp.avg_duration) AS avg_duration_ms,
            min(qp.avg_duration) AS min_duration_ms,
            max(qp.avg_duration) AS max_duration_ms,
            stddev(qp.avg_duration) AS stddev_duration_ms,
            -- Calculate first half period average
            avg(CASE WHEN qp.last_seen < v_half_period THEN qp.avg_duration ELSE NULL END) AS first_half_avg,
            -- Calculate second half period average
            avg(CASE WHEN qp.last_seen >= v_half_period THEN qp.avg_duration ELSE NULL END) AS second_half_avg
        FROM analytics.query_patterns qp
        WHERE qp.last_seen >= v_now - (p_days || ' days')::INTERVAL
        GROUP BY qp.query_pattern
        HAVING count(*) >= p_min_executions
    )
    SELECT
        qs.query_pattern,
        qs.executions,
        qs.avg_duration_ms,
        qs.min_duration_ms,
        qs.max_duration_ms,
        qs.stddev_duration_ms,
        CASE
            WHEN qs.second_half_avg > qs.first_half_avg * 1.1 THEN 'INCREASING'
            WHEN qs.second_half_avg < qs.first_half_avg * 0.9 THEN 'DECREASING'
            ELSE 'STABLE'
        END AS trend_direction,
        CASE
            WHEN qs.first_half_avg = 0 THEN 0
            ELSE ((qs.second_half_avg - qs.first_half_avg) / qs.first_half_avg) * 100
        END AS trend_percentage
    FROM query_stats qs
    ORDER BY qs.avg_duration_ms DESC;
END;
$$ LANGUAGE plpgsql;

-- Function to predict database load
CREATE OR REPLACE FUNCTION analytics.predict_database_load(
    p_hours_ahead INTEGER DEFAULT 24
) RETURNS TABLE (
    hour INTEGER,
    predicted_connections INTEGER,
    predicted_queries INTEGER,
    confidence_level TEXT
) AS $$
import numpy as np
from sklearn.linear_model import LinearRegression
import datetime

# Get historical load data
historical_data = plpy.execute("""
    SELECT
        EXTRACT(HOUR FROM query_start) AS hour,
        COUNT(DISTINCT pid) AS connections,
        COUNT(*) AS queries
    FROM pg_stat_activity
    WHERE query_start >= NOW() - INTERVAL '7 days'
    GROUP BY EXTRACT(HOUR FROM query_start)
    ORDER BY hour
""")

if len(historical_data) < 24:
    # Not enough data for prediction
    return

# Prepare data for prediction
hours = np.array([r['hour'] for r in historical_data]).reshape(-1, 1)
connections = np.array([r['connections'] for r in historical_data])
queries = np.array([r['queries'] for r in historical_data])

# Train models
conn_model = LinearRegression()
conn_model.fit(hours, connections)

query_model = LinearRegression()
query_model.fit(hours, queries)

# Make predictions for the next p_hours_ahead hours
current_hour = datetime.datetime.now().hour
for i in range(p_hours_ahead):
    prediction_hour = (current_hour + i) % 24
    hour_feature = np.array([[prediction_hour]])

    # Predict connections
    predicted_connections = int(conn_model.predict(hour_feature)[0])

    # Predict queries
    predicted_queries = int(query_model.predict(hour_feature)[0])

    # Calculate confidence level based on historical variance
    hour_data = [r for r in historical_data if r['hour'] == prediction_hour]
    if hour_data:
        confidence = "HIGH"
    else:
        confidence = "MEDIUM"

    # Yield prediction
    yield (prediction_hour, predicted_connections, predicted_queries, confidence)

$$ LANGUAGE plpython3u;

-- Function to identify potential security risks
CREATE OR REPLACE FUNCTION analytics.identify_security_risks() RETURNS TABLE (
    risk_type TEXT,
    risk_level TEXT,
    description TEXT,
    affected_objects TEXT[],
    recommendation TEXT
) AS $$
BEGIN
    RETURN QUERY

    -- Check for users with superuser privileges
    SELECT
        'EXCESSIVE_PRIVILEGES' AS risk_type,
        'HIGH' AS risk_level,
        'Users with superuser privileges' AS description,
        array_agg(rolname) AS affected_objects,
        'Review superuser privileges and remove if not necessary' AS recommendation
    FROM pg_roles
    WHERE rolsuper = TRUE AND rolname NOT IN ('postgres')
    HAVING count(*) > 0

    UNION ALL

    -- Check for tables without row-level security
    SELECT
        'MISSING_RLS' AS risk_type,
        'MEDIUM' AS risk_level,
        'Tables containing sensitive data without row-level security' AS description,
        array_agg(table_name) AS affected_objects,
        'Enable row-level security on these tables' AS recommendation
    FROM (
        SELECT c.table_schema || '.' || c.table_name AS table_name
        FROM information_schema.columns c
        JOIN data_classification.column_classifications dc
            ON c.table_schema = dc.schema_name
            AND c.table_name = dc.table_name
        JOIN data_classification.levels l ON dc.level_id = l.id
        LEFT JOIN pg_tables t ON c.table_schema = t.schemaname AND c.table_name = t.tablename
        LEFT JOIN pg_class cls ON cls.relname = c.table_name
        WHERE l.level_order >= 3  -- Confidential or higher
          AND NOT EXISTS (
              SELECT 1 FROM pg_catalog.pg_policy pol
              WHERE pol.polrelid = cls.oid
          )
        GROUP BY c.table_schema, c.table_name
    ) sensitive_tables
    HAVING count(*) > 0

    UNION ALL

    -- Check for unencrypted sensitive columns
    SELECT
        'UNENCRYPTED_DATA' AS risk_type,
        'HIGH' AS risk_level,
        'Sensitive columns without encryption' AS description,
        array_agg(column_name) AS affected_objects,
        'Apply encryption to these columns' AS recommendation
    FROM (
        SELECT c.table_schema || '.' || c.table_name || '.' || c.column_name AS column_name
        FROM information_schema.columns c
        JOIN data_classification.column_classifications dc
            ON c.table_schema = dc.schema_name
            AND c.table_name = dc.table_name
            AND c.column_name = dc.column_name
        JOIN data_classification.levels l ON dc.level_id = l.id
        WHERE l.level_order >= 3  -- Confidential or higher
          AND c.column_name NOT LIKE '%encrypted%'
          AND c.column_name NOT LIKE '%token%'
          AND c.column_name NOT LIKE '%hash%'
    ) sensitive_columns
    HAVING count(*) > 0

    UNION ALL

    -- Check for missing audit logging
    SELECT
        'MISSING_AUDIT' AS risk_type,
        'MEDIUM' AS risk_level,
        'Tables without audit logging' AS description,
        array_agg(table_name) AS affected_objects,
        'Implement audit logging for these tables' AS recommendation
    FROM (
        SELECT c.table_schema || '.' || c.table_name AS table_name
        FROM information_schema.tables c
        WHERE c.table_schema NOT IN ('pg_catalog', 'information_schema')
          AND c.table_type = 'BASE TABLE'
          AND NOT EXISTS (
              SELECT 1 FROM pg_trigger t
              JOIN pg_class cls ON t.tgrelid = cls.oid
              JOIN pg_namespace n ON cls.relnamespace = n.oid
              WHERE n.nspname = c.table_schema
                AND cls.relname = c.table_name
                AND t.tgname LIKE '%audit%'
          )
        GROUP BY c.table_schema, c.table_name
    ) tables_without_audit
    HAVING count(*) > 0;
END;
$$ LANGUAGE plpgsql;

-- Grant permissions
GRANT USAGE ON SCHEMA analytics TO security_admin;
GRANT SELECT ON analytics.query_patterns TO security_admin;
GRANT SELECT ON analytics.user_profiles TO security_admin;
GRANT SELECT ON analytics.anomalies TO security_admin;
GRANT EXECUTE ON FUNCTION analytics.normalize_query TO security_admin;
GRANT EXECUTE ON FUNCTION analytics.extract_query_type TO security_admin;
GRANT EXECUTE ON FUNCTION analytics.update_query_patterns TO security_admin;
GRANT EXECUTE ON FUNCTION analytics.update_user_profile TO security_admin;
GRANT EXECUTE ON FUNCTION analytics.detect_query_anomalies TO security_admin;
GRANT EXECUTE ON FUNCTION analytics.detect_user_anomalies TO security_admin;
GRANT EXECUTE ON FUNCTION analytics.get_recent_anomalies TO security_admin;
GRANT EXECUTE ON FUNCTION analytics.resolve_anomaly TO security_admin;
GRANT EXECUTE ON FUNCTION analytics.get_user_activity_summary TO security_admin;
GRANT EXECUTE ON FUNCTION analytics.analyze_query_performance TO security_admin;
GRANT EXECUTE ON FUNCTION analytics.predict_database_load TO security_admin;
GRANT EXECUTE ON FUNCTION analytics.identify_security_risks TO security_admin;
