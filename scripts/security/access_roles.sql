\c db_dev;

-- 1) Create application roles with the principle of least privilege
CREATE ROLE db_admin WITH LOGIN PASSWORD 'adminsecurepassword' SUPERUSER;
CREATE ROLE app_user WITH LOGIN PASSWORD 'appusersecurepassword';
CREATE ROLE readonly_user WITH LOGIN PASSWORD 'readonlysecurepassword';
CREATE ROLE auditor_user WITH LOGIN PASSWORD 'auditsecurepassword';

-- 2) Schema privileges (restricting access properly)
GRANT CONNECT ON DATABASE db_dev TO app_user, readonly_user, auditor_user;
GRANT USAGE ON SCHEMA inventory, accounting TO app_user, readonly_user;
GRANT USAGE ON SCHEMA analytics TO auditor_user;

-- 3) Granting table-level permissions
-- App user: Read & Write access
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA inventory TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA accounting TO app_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA inventory, accounting
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user;

-- Read-only user: Can only SELECT from inventory and accounting
GRANT SELECT ON ALL TABLES IN SCHEMA inventory TO readonly_user;
GRANT SELECT ON ALL TABLES IN SCHEMA accounting TO readonly_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA inventory, accounting
  GRANT SELECT ON TABLES TO readonly_user;

-- Auditor user: Can only read data in analytics for reporting
GRANT SELECT ON ALL TABLES IN SCHEMA analytics TO auditor_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA analytics
  GRANT SELECT ON TABLES TO auditor_user;

-- 4) Secure function execution (e.g., allowing readonly users to call reporting functions)
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA analytics TO auditor_user;

-- 5) Secure future privileges
ALTER DEFAULT PRIVILEGES IN SCHEMA inventory, accounting
  GRANT SELECT ON TABLES TO readonly_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA analytics
  GRANT SELECT ON TABLES TO auditor_user;
