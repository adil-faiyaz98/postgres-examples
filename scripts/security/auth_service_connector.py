#!/usr/bin/env python3
"""
Authentication Service Connector
This script connects the PostgreSQL session management with the zero trust authentication service.
It synchronizes user sessions between PostgreSQL and the authentication service.
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta
import requests
import psycopg2
from psycopg2.extras import RealDictCursor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/var/log/postgres-security/auth_service_connector.log')
    ]
)
logger = logging.getLogger('auth_service_connector')

# Default configuration
DEFAULT_CONFIG = {
    'db_host': 'localhost',
    'db_port': 5432,
    'db_name': 'db_dev',
    'db_user': 'postgres',
    'db_password': '',
    'auth_service_url': 'http://postgres-auth-service:8080',
    'sync_interval': 60,  # seconds
    'jwt_expiry': 3600,  # seconds
    'log_level': 'INFO'
}

def load_config():
    """Load configuration from environment variables or use defaults"""
    config = DEFAULT_CONFIG.copy()
    
    # Override with environment variables if present
    for key in config:
        env_var = f'AUTH_CONNECTOR_{key.upper()}'
        if env_var in os.environ:
            config[key] = os.environ[env_var]
    
    # Convert numeric values
    for key in ['db_port', 'sync_interval', 'jwt_expiry']:
        config[key] = int(config[key])
    
    # Set log level
    logging.getLogger().setLevel(getattr(logging, config['log_level']))
    
    return config

def get_db_connection(config):
    """Create a database connection"""
    try:
        conn = psycopg2.connect(
            host=config['db_host'],
            port=config['db_port'],
            dbname=config['db_name'],
            user=config['db_user'],
            password=config['db_password']
        )
        conn.autocommit = True
        return conn
    except psycopg2.Error as e:
        logger.error(f"Database connection error: {e}")
        sys.exit(1)

def sync_sessions_to_auth_service(db_conn, config):
    """Synchronize active sessions from PostgreSQL to the authentication service"""
    try:
        with db_conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Get active sessions from PostgreSQL
            cursor.execute("""
                SELECT 
                    s.session_id, 
                    s.user_id, 
                    u.username, 
                    u.email,
                    u.role,
                    s.jwt_token,
                    s.token_issued_at,
                    s.token_expires_at,
                    s.client_ip
                FROM 
                    auth.active_sessions s
                JOIN 
                    auth.users u ON s.user_id = u.user_id
                WHERE 
                    NOT s.revoked
                    AND s.token_expires_at > NOW()
            """)
            active_sessions = cursor.fetchall()
            
            logger.info(f"Found {len(active_sessions)} active sessions in PostgreSQL")
            
            # Synchronize each session with the auth service
            for session in active_sessions:
                try:
                    # Convert datetime objects to ISO format strings
                    session['token_issued_at'] = session['token_issued_at'].isoformat()
                    session['token_expires_at'] = session['token_expires_at'].isoformat()
                    
                    # Send session to auth service
                    response = requests.post(
                        f"{config['auth_service_url']}/api/sessions/sync",
                        json=session,
                        headers={'Content-Type': 'application/json'},
                        timeout=5
                    )
                    
                    if response.status_code == 200:
                        logger.debug(f"Successfully synchronized session {session['session_id']}")
                    else:
                        logger.warning(f"Failed to synchronize session {session['session_id']}: {response.status_code} {response.text}")
                
                except requests.RequestException as e:
                    logger.error(f"Error communicating with auth service: {e}")
    
    except psycopg2.Error as e:
        logger.error(f"Database error during session sync: {e}")

def sync_revoked_sessions_from_auth_service(db_conn, config):
    """Synchronize revoked sessions from the authentication service to PostgreSQL"""
    try:
        # Get revoked sessions from auth service
        response = requests.get(
            f"{config['auth_service_url']}/api/sessions/revoked",
            timeout=5
        )
        
        if response.status_code != 200:
            logger.warning(f"Failed to get revoked sessions from auth service: {response.status_code} {response.text}")
            return
        
        revoked_sessions = response.json()
        logger.info(f"Found {len(revoked_sessions)} revoked sessions in auth service")
        
        if not revoked_sessions:
            return
        
        # Revoke sessions in PostgreSQL
        with db_conn.cursor() as cursor:
            for session in revoked_sessions:
                cursor.execute("""
                    UPDATE auth.active_sessions
                    SET revoked = TRUE,
                        revoked_reason = %s
                    WHERE session_id = %s
                      AND NOT revoked
                """, (session['reason'], session['session_id']))
            
            db_conn.commit()
    
    except requests.RequestException as e:
        logger.error(f"Error communicating with auth service: {e}")
    except psycopg2.Error as e:
        logger.error(f"Database error during revoked session sync: {e}")

def sync_users_to_auth_service(db_conn, config):
    """Synchronize users from PostgreSQL to the authentication service"""
    try:
        with db_conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Get users from PostgreSQL
            cursor.execute("""
                SELECT 
                    user_id, 
                    username, 
                    email,
                    role,
                    status,
                    created_at,
                    updated_at
                FROM 
                    auth.users
                WHERE 
                    status = 'active'
            """)
            users = cursor.fetchall()
            
            logger.info(f"Found {len(users)} active users in PostgreSQL")
            
            # Synchronize users with the auth service
            for user in users:
                try:
                    # Convert datetime objects to ISO format strings
                    user['created_at'] = user['created_at'].isoformat()
                    user['updated_at'] = user['updated_at'].isoformat()
                    
                    # Send user to auth service
                    response = requests.post(
                        f"{config['auth_service_url']}/api/users/sync",
                        json=user,
                        headers={'Content-Type': 'application/json'},
                        timeout=5
                    )
                    
                    if response.status_code == 200:
                        logger.debug(f"Successfully synchronized user {user['username']}")
                    else:
                        logger.warning(f"Failed to synchronize user {user['username']}: {response.status_code} {response.text}")
                
                except requests.RequestException as e:
                    logger.error(f"Error communicating with auth service: {e}")
    
    except psycopg2.Error as e:
        logger.error(f"Database error during user sync: {e}")

def cleanup_expired_sessions(db_conn):
    """Clean up expired sessions in PostgreSQL"""
    try:
        with db_conn.cursor() as cursor:
            cursor.execute("SELECT auth.cleanup_expired_sessions()")
            count = cursor.fetchone()[0]
            if count > 0:
                logger.info(f"Cleaned up {count} expired sessions")
    
    except psycopg2.Error as e:
        logger.error(f"Database error during session cleanup: {e}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Authentication Service Connector')
    parser.add_argument('--once', action='store_true', help='Run once and exit')
    args = parser.parse_args()
    
    config = load_config()
    logger.info(f"Starting Authentication Service Connector with config: {json.dumps({k: v for k, v in config.items() if k != 'db_password'})}")
    
    db_conn = get_db_connection(config)
    
    try:
        if args.once:
            # Run once
            sync_users_to_auth_service(db_conn, config)
            sync_sessions_to_auth_service(db_conn, config)
            sync_revoked_sessions_from_auth_service(db_conn, config)
            cleanup_expired_sessions(db_conn)
        else:
            # Run continuously
            while True:
                sync_users_to_auth_service(db_conn, config)
                sync_sessions_to_auth_service(db_conn, config)
                sync_revoked_sessions_from_auth_service(db_conn, config)
                cleanup_expired_sessions(db_conn)
                
                logger.debug(f"Sleeping for {config['sync_interval']} seconds")
                time.sleep(config['sync_interval'])
    
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt, shutting down")
    finally:
        db_conn.close()

if __name__ == '__main__':
    main()
