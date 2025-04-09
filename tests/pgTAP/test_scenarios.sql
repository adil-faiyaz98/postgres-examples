
SELECT lives_ok(
    $$SELECT auth.start_user_session(uuid_generate_v4(), 'test@example.com', '30 minutes')$$,
    'User session starts successfully'
);

SELECT lives_ok(
    $$SELECT blockchain.publish_security_event()$$,
    'Security event is successfully published to blockchain'
);

SELECT is(
    (SELECT quantum_security.encrypt_data('SensitiveData', '123e4567-e89b-12d3-a456-426614174000') IS NOT NULL),
    true,
    'Quantum encryption function encrypts data successfully'
);
