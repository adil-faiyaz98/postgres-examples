\c postgres;

-- Create Users
CREATE ROLE app_user WITH LOGIN PASSWORD 'securepassword';
CREATE ROLE readonly_user WITH LOGIN PASSWORD 'readonlypassword';

-- Restrict privileges
GRANT CONNECT ON DATABASE db_dev TO app_user, readonly_user;
GRANT USAGE ON SCHEMA inventory, accounting TO app_user, readonly_user;

-- Assign permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA inventory TO app_user;
GRANT SELECT ON ALL TABLES IN SCHEMA inventory TO readonly_user;
