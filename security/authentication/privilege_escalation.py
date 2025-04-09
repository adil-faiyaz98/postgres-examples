"""
Privilege Escalation Test Module
Tests for privilege escalation vulnerabilities in PostgreSQL.
"""

import logging
from security.base_test import BaseSecurityTest

logger = logging.getLogger("security_tests")

class PrivilegeEscalationTest(BaseSecurityTest):
    """Test for privilege escalation vulnerabilities."""
    
    def run(self):
        """Run the test and return results."""
        logger.info("Running Privilege Escalation Test")
        
        # Test 1: Check for users with excessive privileges
        self._test_excessive_privileges()
        
        # Test 2: Check for public schema permissions
        self._test_public_schema_permissions()
        
        # Test 3: Check for function security definer issues
        self._test_security_definer_functions()
        
        # Test 4: Check for role membership issues
        self._test_role_membership()
        
        return self.results
    
    def _test_excessive_privileges(self):
        """Test for users with excessive privileges."""
        try:
            # Check for users with superuser privileges
            superusers = self.execute_query("""
                SELECT rolname
                FROM pg_roles
                WHERE rolsuper = true
                AND rolname != 'postgres'
            """)
            
            if superusers:
                superuser_names = [row[0] for row in superusers]
                self.add_result(
                    "Excessive Privileges - Superusers",
                    "WARNING",
                    f"Found {len(superusers)} users with superuser privileges besides postgres: {', '.join(superuser_names)}"
                )
            else:
                self.add_result(
                    "Excessive Privileges - Superusers",
                    "PASS",
                    "No additional superusers found"
                )
            
            # Check for users with createdb privileges
            createdb_users = self.execute_query("""
                SELECT rolname
                FROM pg_roles
                WHERE rolcreatedb = true
                AND rolname != 'postgres'
            """)
            
            if createdb_users:
                createdb_names = [row[0] for row in createdb_users]
                self.add_result(
                    "Excessive Privileges - CreateDB",
                    "WARNING",
                    f"Found {len(createdb_users)} users with createdb privileges: {', '.join(createdb_names)}"
                )
            else:
                self.add_result(
                    "Excessive Privileges - CreateDB",
                    "PASS",
                    "No users with createdb privileges found"
                )
            
            # Check for users with createrole privileges
            createrole_users = self.execute_query("""
                SELECT rolname
                FROM pg_roles
                WHERE rolcreaterole = true
                AND rolname != 'postgres'
            """)
            
            if createrole_users:
                createrole_names = [row[0] for row in createrole_users]
                self.add_result(
                    "Excessive Privileges - CreateRole",
                    "WARNING",
                    f"Found {len(createrole_users)} users with createrole privileges: {', '.join(createrole_names)}"
                )
            else:
                self.add_result(
                    "Excessive Privileges - CreateRole",
                    "PASS",
                    "No users with createrole privileges found"
                )
                
        except Exception as e:
            logger.error(f"Error in _test_excessive_privileges: {e}")
            self.add_result(
                "Excessive Privileges",
                "ERROR",
                f"Error testing excessive privileges: {str(e)}"
            )
    
    def _test_public_schema_permissions(self):
        """Test for excessive permissions on public schema."""
        try:
            # Check for public schema permissions
            public_permissions = self.execute_query("""
                SELECT grantee, privilege_type
                FROM information_schema.role_table_grants
                WHERE table_schema = 'public'
                AND grantee = 'PUBLIC'
            """)
            
            if public_permissions:
                # Group permissions by table
                permissions_by_table = {}
                for grantee, privilege in public_permissions:
                    if grantee not in permissions_by_table:
                        permissions_by_table[grantee] = []
                    permissions_by_table[grantee].append(privilege)
                
                # Check for dangerous permissions
                dangerous_permissions = ['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']
                has_dangerous = any(perm in dangerous_permissions for perm in permissions_by_table.get('PUBLIC', []))
                
                if has_dangerous:
                    self.add_result(
                        "Public Schema Permissions",
                        "FAIL",
                        f"Public role has dangerous permissions on public schema: {', '.join(permissions_by_table.get('PUBLIC', []))}"
                    )
                else:
                    self.add_result(
                        "Public Schema Permissions",
                        "WARNING",
                        f"Public role has some permissions on public schema: {', '.join(permissions_by_table.get('PUBLIC', []))}"
                    )
            else:
                self.add_result(
                    "Public Schema Permissions",
                    "PASS",
                    "No excessive permissions found on public schema"
                )
                
        except Exception as e:
            logger.error(f"Error in _test_public_schema_permissions: {e}")
            self.add_result(
                "Public Schema Permissions",
                "ERROR",
                f"Error testing public schema permissions: {str(e)}"
            )
    
    def _test_security_definer_functions(self):
        """Test for security definer functions with potential issues."""
        try:
            # Check for security definer functions
            security_definer_functions = self.execute_query("""
                SELECT n.nspname as schema, p.proname as name, r.rolname as owner
                FROM pg_proc p
                JOIN pg_namespace n ON p.pronamespace = n.oid
                JOIN pg_roles r ON p.proowner = r.oid
                WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
                AND p.prosecdef = true
            """)
            
            if security_definer_functions:
                function_details = [f"{schema}.{name} (owner: {owner})" for schema, name, owner in security_definer_functions]
                
                # Check for security definer functions owned by superusers
                superuser_functions = self.execute_query("""
                    SELECT n.nspname as schema, p.proname as name, r.rolname as owner
                    FROM pg_proc p
                    JOIN pg_namespace n ON p.pronamespace = n.oid
                    JOIN pg_roles r ON p.proowner = r.oid
                    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
                    AND p.prosecdef = true
                    AND r.rolsuper = true
                """)
                
                if superuser_functions:
                    superuser_function_details = [f"{schema}.{name} (owner: {owner})" for schema, name, owner in superuser_functions]
                    self.add_result(
                        "Security Definer Functions - Superuser",
                        "WARNING",
                        f"Found {len(superuser_functions)} security definer functions owned by superusers: {', '.join(superuser_function_details)}"
                    )
                else:
                    self.add_result(
                        "Security Definer Functions - Superuser",
                        "PASS",
                        "No security definer functions owned by superusers"
                    )
                
                self.add_result(
                    "Security Definer Functions",
                    "WARNING",
                    f"Found {len(security_definer_functions)} security definer functions: {', '.join(function_details)}"
                )
            else:
                self.add_result(
                    "Security Definer Functions",
                    "PASS",
                    "No security definer functions found"
                )
                
        except Exception as e:
            logger.error(f"Error in _test_security_definer_functions: {e}")
            self.add_result(
                "Security Definer Functions",
                "ERROR",
                f"Error testing security definer functions: {str(e)}"
            )
    
    def _test_role_membership(self):
        """Test for role membership issues."""
        try:
            # Check for role membership chains that could lead to privilege escalation
            role_memberships = self.execute_query("""
                WITH RECURSIVE role_members AS (
                    SELECT oid, rolname, ARRAY[]::oid[] AS member_of
                    FROM pg_roles
                    
                    UNION ALL
                    
                    SELECT r.oid, r.rolname, m.member_of || m2.roleid
                    FROM pg_roles r
                    JOIN pg_auth_members m2 ON r.oid = m2.member
                    JOIN role_members m ON m2.roleid = m.oid
                    WHERE NOT m2.roleid = ANY(m.member_of)
                )
                SELECT r1.rolname AS role, r2.rolname AS is_member_of
                FROM role_members rm
                JOIN pg_roles r1 ON rm.oid = r1.oid
                JOIN pg_roles r2 ON rm.member_of[array_upper(rm.member_of, 1)] = r2.oid
                WHERE array_length(rm.member_of, 1) > 0
                AND r2.rolsuper = true
                AND r1.rolname != 'postgres'
            """)
            
            if role_memberships:
                role_chains = [f"{role} -> {member_of}" for role, member_of in role_memberships]
                self.add_result(
                    "Role Membership",
                    "FAIL",
                    f"Found {len(role_memberships)} role membership chains that could lead to privilege escalation: {', '.join(role_chains)}"
                )
            else:
                self.add_result(
                    "Role Membership",
                    "PASS",
                    "No problematic role membership chains found"
                )
                
        except Exception as e:
            logger.error(f"Error in _test_role_membership: {e}")
            self.add_result(
                "Role Membership",
                "ERROR",
                f"Error testing role membership: {str(e)}"
            )
