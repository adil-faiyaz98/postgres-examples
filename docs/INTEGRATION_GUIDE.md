# PostgreSQL Security Framework Integration Guide

This guide provides detailed instructions on how to integrate the PostgreSQL Security Framework with your custom applications. It covers authentication, authorization, encryption, and monitoring integration.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Authentication Integration](#authentication-integration)
3. [Authorization and Row-Level Security](#authorization-and-row-level-security)
4. [Data Encryption](#data-encryption)
5. [Audit Logging](#audit-logging)
6. [Monitoring Integration](#monitoring-integration)
7. [Zero Trust Architecture](#zero-trust-architecture)
8. [Compliance Validation](#compliance-validation)
9. [Troubleshooting](#troubleshooting)
10. [Examples](#examples)

## Prerequisites

Before integrating with the PostgreSQL Security Framework, ensure you have:

- PostgreSQL 13+ with the security framework installed
- Access to the database with appropriate permissions
- Required extensions installed (pgcrypto, pgaudit, etc.)
- Client libraries for your programming language

## Authentication Integration

### 1. User Registration

To register users in your application:

```sql
-- SQL Example
SELECT auth.register_user(
    'username',
    'user@example.com',
    'secure_password',
    'user'  -- Role: 'user', 'admin', etc.
);
```

```python
# Python Example
import psycopg2

conn = psycopg2.connect("postgresql://username:password@hostname:5432/database")
cursor = conn.cursor()

cursor.execute(
    "SELECT auth.register_user(%s, %s, %s, %s)",
    ("username", "user@example.com", "secure_password", "user")
)
user_id = cursor.fetchone()[0]
conn.commit()
```

### 2. User Authentication

To authenticate users:

```sql
-- SQL Example
SELECT * FROM auth.authenticate_user(
    'username',
    'secure_password',
    '192.168.1.1',  -- Client IP
    'Mozilla/5.0'   -- User Agent
);
```

```python
# Python Example
cursor.execute(
    "SELECT * FROM auth.authenticate_user(%s, %s, %s, %s)",
    ("username", "secure_password", client_ip, user_agent)
)
auth_result = cursor.fetchone()
authenticated = auth_result[0]
user_id = auth_result[1]
username = auth_result[2]
role = auth_result[3]
session_id = auth_result[4]
jwt_token = auth_result[5]
token_expires_at = auth_result[6]

if authenticated:
    # Store JWT token for subsequent requests
    # For example, in a session or cookie
    session['jwt_token'] = jwt_token
    session['session_id'] = session_id
```

### 3. Session Validation

To validate a session:

```sql
-- SQL Example
SELECT * FROM auth.validate_session(
    'jwt_token_here',
    '192.168.1.1'  -- Client IP
);
```

```python
# Python Example
cursor.execute(
    "SELECT * FROM auth.validate_session(%s, %s)",
    (jwt_token, client_ip)
)
session_result = cursor.fetchone()
valid = session_result[0]
user_id = session_result[1]
username = session_result[2]
role = session_result[3]

if not valid:
    # Redirect to login page or return unauthorized error
    return redirect('/login')
```

### 4. Session Termination

To terminate a session:

```sql
-- SQL Example
SELECT auth.revoke_session(
    'session_id_here',
    'User logout'  -- Reason
);
```

```python
# Python Example
cursor.execute(
    "SELECT auth.revoke_session(%s, %s)",
    (session_id, "User logout")
)
success = cursor.fetchone()[0]
conn.commit()

if success:
    # Clear session data
    session.clear()
```

## Authorization and Row-Level Security

### 1. Setting Application Context

Before executing queries, set the application context:

```sql
-- SQL Example
SET app.current_user_id = 'user_id_here';
SET app.tenant_id = 'tenant_id_here';
```

```python
# Python Example
cursor.execute("SET app.current_user_id = %s", (user_id,))
cursor.execute("SET app.tenant_id = %s", (tenant_id,))
```

### 2. Using Row-Level Security

With application context set, RLS policies will automatically filter data:

```sql
-- SQL Example
SELECT * FROM inventory.customers;  -- Only returns rows for current tenant
```

```python
# Python Example
cursor.execute("SELECT * FROM inventory.customers")
customers = cursor.fetchall()
# Only rows accessible to the current user/tenant will be returned
```

### 3. Custom RLS Policies

To create custom RLS policies for your application tables:

```sql
-- SQL Example
CREATE TABLE app.customer_data (
    id SERIAL PRIMARY KEY,
    tenant_id INTEGER NOT NULL,
    customer_name TEXT NOT NULL,
    data JSONB
);

ALTER TABLE app.customer_data ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON app.customer_data
    USING (tenant_id = current_setting('app.tenant_id')::INTEGER);
```

## Data Encryption

### 1. Column-Level Encryption

To encrypt sensitive data:

```sql
-- SQL Example
CREATE TABLE app.sensitive_data (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    plaintext_data TEXT,
    encrypted_data BYTEA
);

-- Encrypt data
UPDATE app.sensitive_data
SET encrypted_data = pgcrypto.encrypt(
    plaintext_data::bytea,
    current_setting('app.encryption_key')::bytea,
    'aes'
);
```

```python
# Python Example
from cryptography.fernet import Fernet

# Generate or retrieve encryption key
encryption_key = Fernet.generate_key()

# Set encryption key in application context
cursor.execute("SET app.encryption_key = %s", (encryption_key.decode(),))

# Insert encrypted data
cursor.execute(
    """
    INSERT INTO app.sensitive_data (user_id, plaintext_data, encrypted_data)
    VALUES (%s, %s, pgcrypto.encrypt(%s::bytea, current_setting('app.encryption_key')::bytea, 'aes'))
    """,
    (user_id, plaintext_data, plaintext_data)
)
conn.commit()
```

### 2. Decrypting Data

To decrypt data:

```sql
-- SQL Example
SELECT id, user_id, convert_from(
    pgcrypto.decrypt(
        encrypted_data,
        current_setting('app.encryption_key')::bytea,
        'aes'
    ),
    'UTF8'
) AS decrypted_data
FROM app.sensitive_data;
```

```python
# Python Example
cursor.execute("SET app.encryption_key = %s", (encryption_key.decode(),))

cursor.execute(
    """
    SELECT id, user_id, convert_from(
        pgcrypto.decrypt(
            encrypted_data,
            current_setting('app.encryption_key')::bytea,
            'aes'
        ),
        'UTF8'
    ) AS decrypted_data
    FROM app.sensitive_data
    WHERE user_id = %s
    """,
    (user_id,)
)
decrypted_data = cursor.fetchall()
```

## Audit Logging

### 1. Logging Security Events

To log security events:

```sql
-- SQL Example
INSERT INTO logs.notification_log (
    event_type, severity, username, source_ip, message
) VALUES (
    'USER_ACTION', 'INFO', 'username', '192.168.1.1', 'User performed sensitive action'
);
```

```python
# Python Example
cursor.execute(
    """
    INSERT INTO logs.notification_log (
        event_type, severity, username, source_ip, message
    ) VALUES (%s, %s, %s, %s, %s)
    """,
    ('USER_ACTION', 'INFO', username, client_ip, 'User performed sensitive action')
)
conn.commit()
```

### 2. Querying Audit Logs

To query audit logs:

```sql
-- SQL Example
SELECT * FROM logs.notification_log
WHERE username = 'username'
ORDER BY logged_at DESC
LIMIT 100;
```

```python
# Python Example
cursor.execute(
    """
    SELECT * FROM logs.notification_log
    WHERE username = %s
    ORDER BY logged_at DESC
    LIMIT 100
    """,
    (username,)
)
audit_logs = cursor.fetchall()
```

## Monitoring Integration

### 1. Integrating with Prometheus

To expose metrics to Prometheus:

```python
# Python Example
import prometheus_client
from prometheus_client import Counter, Gauge

# Create metrics
login_attempts = Counter('app_login_attempts_total', 'Total login attempts', ['success', 'username'])
active_sessions = Gauge('app_active_sessions', 'Number of active sessions')

# Start metrics server
prometheus_client.start_http_server(8000)

# Update metrics
def track_login(username, success):
    login_attempts.labels(success=str(success), username=username).inc()

def update_session_count():
    cursor.execute("SELECT COUNT(*) FROM auth.active_sessions WHERE NOT revoked AND token_expires_at > NOW()")
    count = cursor.fetchone()[0]
    active_sessions.set(count)
```

### 2. Using the Security Monitoring Script

To run the security monitoring script:

```bash
# Bash Example
DB_HOST=localhost DB_PORT=5432 DB_NAME=db_dev DB_USER=postgres ./scripts/monitoring/security_monitoring.sh
```

```python
# Python Example
import subprocess

def run_security_monitoring():
    env = {
        'DB_HOST': 'localhost',
        'DB_PORT': '5432',
        'DB_NAME': 'db_dev',
        'DB_USER': 'postgres',
        'PROMETHEUS_PUSHGATEWAY': 'http://localhost:9091'
    }
    
    result = subprocess.run(
        ['./scripts/monitoring/security_monitoring.sh'],
        env=env,
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        print(f"Error running security monitoring: {result.stderr}")
    else:
        print(f"Security monitoring completed: {result.stdout}")
```

## Zero Trust Architecture

### 1. Integrating with the Authentication Service

To integrate with the zero trust authentication service:

```python
# Python Example
import requests

def verify_jwt_with_auth_service(jwt_token):
    try:
        response = requests.post(
            'http://postgres-auth-service:8080/api/auth/verify',
            json={'token': jwt_token},
            timeout=5
        )
        
        if response.status_code == 200:
            result = response.json()
            return result.get('valid', False)
        else:
            return False
    except requests.RequestException:
        return False

# Use in middleware
def auth_middleware(request, next_handler):
    jwt_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not jwt_token:
        return {'error': 'Unauthorized'}, 401
    
    # Verify with auth service
    if not verify_jwt_with_auth_service(jwt_token):
        return {'error': 'Invalid token'}, 401
    
    # Verify with PostgreSQL
    cursor.execute(
        "SELECT * FROM auth.validate_session(%s, %s)",
        (jwt_token, request.remote_addr)
    )
    session_result = cursor.fetchone()
    
    if not session_result or not session_result[0]:
        return {'error': 'Invalid session'}, 401
    
    # Set user context
    request.user = {
        'user_id': session_result[1],
        'username': session_result[2],
        'role': session_result[3]
    }
    
    # Set application context
    cursor.execute("SET app.current_user_id = %s", (request.user['user_id'],))
    
    return next_handler(request)
```

### 2. Using the Auth Service Connector

To use the auth service connector:

```bash
# Bash Example
AUTH_CONNECTOR_DB_HOST=localhost \
AUTH_CONNECTOR_DB_PORT=5432 \
AUTH_CONNECTOR_DB_NAME=db_dev \
AUTH_CONNECTOR_DB_USER=postgres \
AUTH_CONNECTOR_AUTH_SERVICE_URL=http://postgres-auth-service:8080 \
python3 scripts/security/auth_service_connector.py
```

## Compliance Validation

### 1. Running Compliance Checks

To run compliance checks:

```bash
# Bash Example
./scripts/compliance/check_compliance.sh --standard=pci-dss
```

```python
# Python Example
import subprocess

def check_compliance(standard):
    result = subprocess.run(
        ['./scripts/compliance/check_compliance.sh', f'--standard={standard}'],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        print(f"Compliance check failed: {result.stderr}")
        return False
    else:
        print(f"Compliance check output: {result.stdout}")
        return True

# Check PCI-DSS compliance
check_compliance('pci-dss')
```

### 2. Generating Compliance Reports

To generate compliance reports:

```bash
# Bash Example
./scripts/compliance/generate_report.sh
```

## Troubleshooting

### Common Issues and Solutions

1. **Authentication Failures**
   - Check if the user exists in `auth.users`
   - Verify the password is correct
   - Check if the account is locked due to failed attempts

2. **Row-Level Security Issues**
   - Ensure application context is set correctly (`app.current_user_id`, `app.tenant_id`)
   - Verify RLS policies are created and enabled on the table
   - Check if the user has appropriate permissions

3. **Encryption Issues**
   - Verify the encryption key is set correctly
   - Check if pgcrypto extension is installed
   - Ensure data is properly encoded/decoded

4. **Zero Trust Integration Issues**
   - Check connectivity to the authentication service
   - Verify JWT tokens are properly formatted
   - Check if the auth service connector is running

## Examples

### Example 1: Complete Authentication Flow

```python
# Python Example
import psycopg2
import uuid
from flask import Flask, request, session, redirect

app = Flask(__name__)
app.secret_key = str(uuid.uuid4())

def get_db_connection():
    return psycopg2.connect("postgresql://username:password@hostname:5432/database")

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "SELECT auth.register_user(%s, %s, %s, %s)",
            (username, email, password, "user")
        )
        user_id = cursor.fetchone()[0]
        conn.commit()
        
        return {'success': True, 'user_id': user_id}
    except Exception as e:
        conn.rollback()
        return {'success': False, 'error': str(e)}
    finally:
        cursor.close()
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "SELECT * FROM auth.authenticate_user(%s, %s, %s, %s)",
            (username, password, client_ip, user_agent)
        )
        auth_result = cursor.fetchone()
        
        if auth_result[0]:  # authenticated
            session['authenticated'] = True
            session['user_id'] = auth_result[1]
            session['username'] = auth_result[2]
            session['role'] = auth_result[3]
            session['session_id'] = auth_result[4]
            session['jwt_token'] = auth_result[5]
            
            return redirect('/dashboard')
        else:
            return {'success': False, 'error': 'Authentication failed'}
    except Exception as e:
        return {'success': False, 'error': str(e)}
    finally:
        cursor.close()
        conn.close()

@app.route('/logout', methods=['POST'])
def logout():
    if 'session_id' not in session:
        return {'success': False, 'error': 'Not logged in'}
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "SELECT auth.revoke_session(%s, %s)",
            (session['session_id'], "User logout")
        )
        success = cursor.fetchone()[0]
        conn.commit()
        
        session.clear()
        
        return {'success': success}
    except Exception as e:
        conn.rollback()
        return {'success': False, 'error': str(e)}
    finally:
        cursor.close()
        conn.close()

@app.route('/dashboard')
def dashboard():
    if 'authenticated' not in session or not session['authenticated']:
        return redirect('/login')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Validate session
        cursor.execute(
            "SELECT * FROM auth.validate_session(%s, %s)",
            (session['jwt_token'], request.remote_addr)
        )
        session_result = cursor.fetchone()
        
        if not session_result[0]:  # not valid
            session.clear()
            return redirect('/login')
        
        # Set application context
        cursor.execute("SET app.current_user_id = %s", (session['user_id'],))
        
        # Get user data (RLS will automatically filter)
        cursor.execute("SELECT * FROM inventory.customers")
        customers = cursor.fetchall()
        
        return {'success': True, 'customers': customers}
    except Exception as e:
        return {'success': False, 'error': str(e)}
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    app.run(debug=True)
```

### Example 2: Encrypted Data Storage

```python
# Python Example
import psycopg2
import os
from cryptography.fernet import Fernet

def store_sensitive_data(user_id, data):
    # Generate or retrieve encryption key
    encryption_key = os.environ.get('ENCRYPTION_KEY')
    if not encryption_key:
        encryption_key = Fernet.generate_key().decode()
        os.environ['ENCRYPTION_KEY'] = encryption_key
    
    conn = psycopg2.connect("postgresql://username:password@hostname:5432/database")
    cursor = conn.cursor()
    
    try:
        # Set encryption key in application context
        cursor.execute("SET app.encryption_key = %s", (encryption_key,))
        
        # Insert data with encryption
        cursor.execute(
            """
            INSERT INTO app.sensitive_data (user_id, plaintext_data, encrypted_data)
            VALUES (%s, %s, pgcrypto.encrypt(%s::bytea, current_setting('app.encryption_key')::bytea, 'aes'))
            RETURNING id
            """,
            (user_id, data, data)
        )
        record_id = cursor.fetchone()[0]
        conn.commit()
        
        # For security, clear plaintext data
        cursor.execute(
            "UPDATE app.sensitive_data SET plaintext_data = NULL WHERE id = %s",
            (record_id,)
        )
        conn.commit()
        
        return {'success': True, 'record_id': record_id}
    except Exception as e:
        conn.rollback()
        return {'success': False, 'error': str(e)}
    finally:
        cursor.close()
        conn.close()

def retrieve_sensitive_data(user_id, record_id):
    encryption_key = os.environ.get('ENCRYPTION_KEY')
    if not encryption_key:
        return {'success': False, 'error': 'Encryption key not found'}
    
    conn = psycopg2.connect("postgresql://username:password@hostname:5432/database")
    cursor = conn.cursor()
    
    try:
        # Set encryption key in application context
        cursor.execute("SET app.encryption_key = %s", (encryption_key,))
        
        # Set user context for RLS
        cursor.execute("SET app.current_user_id = %s", (user_id,))
        
        # Retrieve and decrypt data
        cursor.execute(
            """
            SELECT id, user_id, convert_from(
                pgcrypto.decrypt(
                    encrypted_data,
                    current_setting('app.encryption_key')::bytea,
                    'aes'
                ),
                'UTF8'
            ) AS decrypted_data
            FROM app.sensitive_data
            WHERE id = %s
            """,
            (record_id,)
        )
        result = cursor.fetchone()
        
        if not result:
            return {'success': False, 'error': 'Record not found or access denied'}
        
        return {
            'success': True,
            'record_id': result[0],
            'user_id': result[1],
            'data': result[2]
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}
    finally:
        cursor.close()
        conn.close()
```

These examples demonstrate how to integrate the PostgreSQL Security Framework with your custom applications. Adapt them to your specific requirements and programming language.

For more information, refer to the other documentation files in the `docs` directory.
