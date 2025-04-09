"""
Base Security Test Class
All security test modules should inherit from this class.
"""

import logging
import psycopg2
from sqlalchemy import create_engine, text

logger = logging.getLogger("security_tests")

class BaseSecurityTest:
    """Base class for all security tests."""
    
    def __init__(self, conn=None, engine=None):
        """Initialize the test with database connections."""
        self.conn = conn
        self.engine = engine
        self.test_name = self.__class__.__name__
        self.results = []
    
    def run(self):
        """Run the test and return results."""
        raise NotImplementedError("Subclasses must implement run()")
    
    def add_result(self, name, result, details):
        """Add a test result."""
        self.results.append({
            "name": name,
            "result": result,
            "details": details
        })
    
    def execute_query(self, query, params=None):
        """Execute a query using psycopg2."""
        try:
            with self.conn.cursor() as cursor:
                cursor.execute(query, params)
                return cursor.fetchall()
        except Exception as e:
            logger.error(f"Error executing query: {e}")
            raise
    
    def execute_sqlalchemy_query(self, query, params=None):
        """Execute a query using SQLAlchemy."""
        try:
            with self.engine.connect() as connection:
                result = connection.execute(text(query), params)
                return result.fetchall()
        except Exception as e:
            logger.error(f"Error executing SQLAlchemy query: {e}")
            raise
