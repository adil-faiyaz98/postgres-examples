\c db_dev;

-- 1) Create PostgreSQL roles with least privilege principle
CREATE ROLE db_admin WITH LOGIN PASSWORD 'secure_admin' SUPERUSER;
CREATE ROLE app_user WITH LOGIN PASSWORD 'secure_app_user' NOSUPERUSER;
CREATE ROLE readonly_user WITH LOGIN PASSWORD 'secure_readonly' NOSUPERUSER;

-- 2) Restrict database access to specific roles
GRANT CONNECT ON DATABASE db_dev TO app_user, readonly_user;
GRANT USAGE ON SCHEMA inventory, accounting, auth TO app_user, readonly_user;

-- 3) Assign table-level privileges
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA inventory TO app_user;
GRANT SELECT ON ALL TABLES IN SCHEMA inventory TO readonly_user;

-- 4) Restrict access to specific functions
REVOKE EXECUTE ON FUNCTION sensitive_function() FROM readonly_user;
GRANT EXECUTE ON FUNCTION public_function() TO readonly_user;

-- 5) Ensure security enforcement at the database level
ALTER DEFAULT PRIVILEGES FOR ROLE db_admin GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user;
ALTER DEFAULT PRIVILEGES FOR ROLE db_admin GRANT SELECT ON TABLES TO readonly_user;

-- 6) Restrict Public Access
REVOKE ALL ON SCHEMA public FROM PUBLIC;
