-- Advanced Security Features Test Suite
-- This test suite validates the advanced security features of the PostgreSQL Security Framework

\set ON_ERROR_STOP 1
\set QUIET 1

-- Load pgTAP
BEGIN;
\i test/pgTAP/pgtap.sql

-- Plan the tests
SELECT plan(30);

-- Test Column-Level Encryption
SELECT has_function(
    'pgcrypto', 'encrypt', ARRAY['bytea', 'bytea', 'text'],
    'pgcrypto.encrypt(data, key, algorithm) should exist'
);

SELECT has_function(
    'pgcrypto', 'decrypt', ARRAY['bytea', 'bytea', 'text'],
    'pgcrypto.decrypt(data, key, algorithm) should exist'
);

-- Test encryption functions
CREATE TEMPORARY TABLE IF NOT EXISTS test_encryption (
    id SERIAL PRIMARY KEY,
    plaintext TEXT,
    encrypted_text BYTEA,
    encryption_key TEXT
);

INSERT INTO test_encryption (plaintext, encryption_key)
VALUES ('sensitive data', 'encryption_key_for_testing');

UPDATE test_encryption
SET encrypted_text = pgcrypto.encrypt(
    plaintext::bytea,
    encryption_key::bytea,
    'aes'
);

SELECT isnt(
    encrypted_text::text,
    plaintext,
    'Encrypted text should not match plaintext'
)
FROM test_encryption;

SELECT is(
    convert_from(
        pgcrypto.decrypt(
            encrypted_text,
            encryption_key::bytea,
            'aes'
        ),
        'UTF8'
    ),
    plaintext,
    'Decrypted text should match original plaintext'
)
FROM test_encryption;

-- Test Row-Level Security
CREATE TABLE IF NOT EXISTS test_rls (
    id SERIAL PRIMARY KEY,
    tenant_id INTEGER NOT NULL,
    data TEXT NOT NULL
);

INSERT INTO test_rls (tenant_id, data)
VALUES 
    (1, 'Tenant 1 Data 1'),
    (1, 'Tenant 1 Data 2'),
    (2, 'Tenant 2 Data 1'),
    (2, 'Tenant 2 Data 2');

-- Enable RLS on the table
ALTER TABLE test_rls ENABLE ROW LEVEL SECURITY;

-- Create a policy that only allows access to rows with matching tenant_id
CREATE POLICY tenant_isolation_policy ON test_rls
    USING (tenant_id = current_setting('app.tenant_id')::INTEGER);

-- Create test users
CREATE ROLE test_tenant_1 LOGIN;
CREATE ROLE test_tenant_2 LOGIN;

-- Grant permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON test_rls TO test_tenant_1, test_tenant_2;
GRANT USAGE, SELECT ON SEQUENCE test_rls_id_seq TO test_tenant_1, test_tenant_2;

-- Test RLS with tenant 1
SET ROLE test_tenant_1;
SET app.tenant_id TO 1;

SELECT is(
    (SELECT count(*) FROM test_rls),
    2::bigint,
    'Tenant 1 should only see 2 rows'
);

SELECT is(
    (SELECT count(*) FROM test_rls WHERE tenant_id = 1),
    2::bigint,
    'Tenant 1 should see 2 rows with tenant_id = 1'
);

SELECT is(
    (SELECT count(*) FROM test_rls WHERE tenant_id = 2),
    0::bigint,
    'Tenant 1 should see 0 rows with tenant_id = 2'
);

-- Test RLS with tenant 2
SET ROLE test_tenant_2;
SET app.tenant_id TO 2;

SELECT is(
    (SELECT count(*) FROM test_rls),
    2::bigint,
    'Tenant 2 should only see 2 rows'
);

SELECT is(
    (SELECT count(*) FROM test_rls WHERE tenant_id = 2),
    2::bigint,
    'Tenant 2 should see 2 rows with tenant_id = 2'
);

SELECT is(
    (SELECT count(*) FROM test_rls WHERE tenant_id = 1),
    0::bigint,
    'Tenant 2 should see 0 rows with tenant_id = 1'
);

-- Reset role
RESET ROLE;
RESET app.tenant_id;

-- Test Audit Logging
SELECT has_table(
    'logs', 'notification_log',
    'logs.notification_log table should exist'
);

SELECT has_column(
    'logs', 'notification_log', 'event_type',
    'logs.notification_log should have event_type column'
);

SELECT has_column(
    'logs', 'notification_log', 'severity',
    'logs.notification_log should have severity column'
);

SELECT has_column(
    'logs', 'notification_log', 'username',
    'logs.notification_log should have username column'
);

-- Test audit logging functionality
INSERT INTO logs.notification_log (
    event_type, severity, username, message
) VALUES (
    'TEST_EVENT', 'INFO', 'test_user', 'Test audit log entry'
);

SELECT is(
    (SELECT count(*) FROM logs.notification_log WHERE event_type = 'TEST_EVENT'),
    1::bigint,
    'Audit log should contain the test event'
);

-- Test Authentication System
SELECT has_schema(
    'auth',
    'auth schema should exist'
);

SELECT has_table(
    'auth', 'users',
    'auth.users table should exist'
);

SELECT has_table(
    'auth', 'active_sessions',
    'auth.active_sessions table should exist'
);

SELECT has_function(
    'auth', 'register_user', ARRAY['text', 'text', 'text', 'text'],
    'auth.register_user function should exist'
);

SELECT has_function(
    'auth', 'authenticate_user', ARRAY['text', 'text', 'text', 'text'],
    'auth.authenticate_user function should exist'
);

SELECT has_function(
    'auth', 'validate_session', ARRAY['text', 'text'],
    'auth.validate_session function should exist'
);

-- Test user registration
DO $$
DECLARE
    v_user_id UUID;
BEGIN
    SELECT auth.register_user(
        'test_user',
        'test_user@example.com',
        'test_password',
        'user'
    ) INTO v_user_id;
    
    PERFORM is(
        v_user_id IS NOT NULL,
        true,
        'User registration should return a user_id'
    );
    
    PERFORM is(
        (SELECT count(*) FROM auth.users WHERE username = 'test_user'),
        1::bigint,
        'User should be created in the auth.users table'
    );
END $$;

-- Test user authentication
DO $$
DECLARE
    v_auth_result RECORD;
BEGIN
    SELECT * FROM auth.authenticate_user(
        'test_user',
        'test_password',
        '127.0.0.1',
        'Test User Agent'
    ) INTO v_auth_result;
    
    PERFORM is(
        v_auth_result.authenticated,
        true,
        'User authentication should succeed with correct password'
    );
    
    PERFORM isnt(
        v_auth_result.jwt_token,
        NULL,
        'JWT token should be generated on successful authentication'
    );
    
    PERFORM is(
        (SELECT count(*) FROM auth.active_sessions WHERE user_id = v_auth_result.user_id),
        1::bigint,
        'Session should be created on successful authentication'
    );
    
    -- Test with incorrect password
    SELECT * FROM auth.authenticate_user(
        'test_user',
        'wrong_password',
        '127.0.0.1',
        'Test User Agent'
    ) INTO v_auth_result;
    
    PERFORM is(
        v_auth_result.authenticated,
        false,
        'User authentication should fail with incorrect password'
    );
END $$;

-- Test session validation
DO $$
DECLARE
    v_auth_result RECORD;
    v_session_result RECORD;
BEGIN
    SELECT * FROM auth.authenticate_user(
        'test_user',
        'test_password',
        '127.0.0.1',
        'Test User Agent'
    ) INTO v_auth_result;
    
    SELECT * FROM auth.validate_session(
        v_auth_result.jwt_token,
        '127.0.0.1'
    ) INTO v_session_result;
    
    PERFORM is(
        v_session_result.valid,
        true,
        'Session validation should succeed with valid token'
    );
    
    PERFORM is(
        v_session_result.username,
        'test_user',
        'Session validation should return correct username'
    );
    
    -- Test session revocation
    PERFORM auth.revoke_session(
        v_auth_result.session_id,
        'Test revocation'
    );
    
    SELECT * FROM auth.validate_session(
        v_auth_result.jwt_token,
        '127.0.0.1'
    ) INTO v_session_result;
    
    PERFORM is(
        v_session_result.valid,
        false,
        'Session validation should fail after revocation'
    );
END $$;

-- Clean up
DROP TABLE test_encryption;
DROP TABLE test_rls;
DROP ROLE test_tenant_1;
DROP ROLE test_tenant_2;

-- Finish the tests and clean up
SELECT * FROM finish();
ROLLBACK;
