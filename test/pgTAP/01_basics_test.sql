\c db_dev;
BEGIN;
SELECT plan(3); -- Number of tests

-- 1) Verify PostgreSQL version
SELECT like(pg_catalog.version(), '%PostgreSQL%', 'PostgreSQL is running');

-- 2) Check if required schemas exist
SELECT has_schema('inventory'), 'Schema inventory exists';
SELECT has_schema('accounting'), 'Schema accounting exists';

-- 3) Verify if necessary extensions are installed
SELECT has_extension('uuid-ossp'), 'uuid-ossp extension is installed';
SELECT has_extension('pgcrypto'), 'pgcrypto extension is installed';

ROLLBACK;
