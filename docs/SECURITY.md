

## Authentication & Access Control

### Role-Based Access Control (RBAC)

| Role Name | Privileges |
|-----------|------------|
| `db_admin` | Full superuser privileges |
| `app_user` | Can read, write, but cannot DROP tables |
| `readonly_user` | Can only SELECT data |

#### Example Setup
```sql
CREATE ROLE db_admin WITH LOGIN PASSWORD 'secure_admin' SUPERUSER;
CREATE ROLE app_user WITH LOGIN PASSWORD 'secure_app_user' NOSUPERUSER;
CREATE ROLE readonly_user WITH LOGIN PASSWORD 'secure_readonly' NOSUPERUSER;

GRANT CONNECT ON DATABASE db_dev TO app_user, readonly_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA inventory TO app_user;
GRANT SELECT ON ALL TABLES IN SCHEMA inventory TO readonly_user;\
```
