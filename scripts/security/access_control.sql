\c db_dev;

-- 1) Create PostgreSQL roles with least privilege principle
CREATE ROLE db_admin WITH LOGIN PASSWORD current_setting('custom.db_admin_password') SUPERUSER;
CREATE ROLE app_user WITH LOGIN PASSWORD current_setting('custom.app_user_password') NOSUPERUSER;
CREATE ROLE readonly_user WITH LOGIN PASSWORD current_setting('custom.readonly_user_password') NOSUPERUSER;
CREATE ROLE security_admin WITH LOGIN PASSWORD current_setting('custom.security_admin_password') NOSUPERUSER;

-- 2) Restrict database access to specific roles
GRANT CONNECT ON DATABASE db_dev TO app_user, readonly_user, security_admin;
GRANT USAGE ON SCHEMA inventory, accounting, auth TO app_user, readonly_user;
GRANT USAGE ON SCHEMA analytics TO security_admin;

-- 3) Assign table-level privileges
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA inventory TO app_user;
GRANT SELECT ON ALL TABLES IN SCHEMA inventory TO readonly_user;
GRANT SELECT ON ALL TABLES IN SCHEMA analytics TO security_admin;

-- 4) Restrict access to specific functions
REVOKE EXECUTE ON FUNCTION sensitive_function() FROM readonly_user;
GRANT EXECUTE ON FUNCTION public_function() TO readonly_user;

-- 5) Secure future privileges
ALTER DEFAULT PRIVILEGES FOR ROLE db_admin GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user;
ALTER DEFAULT PRIVILEGES FOR ROLE db_admin GRANT SELECT ON TABLES TO readonly_user;

-- 6) Restrict Public Access
REVOKE ALL ON SCHEMA public FROM PUBLIC;
