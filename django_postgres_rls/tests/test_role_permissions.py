"""
Tests to verify that roles created with auto-creation have absolutely no
permissions by default, and that all access is controlled through RLS policies.

This test suite ensures:
1. Roles are created with minimal privileges (NOLOGIN, NOCREATEDB, etc.)
2. Roles have NO table access by default
3. Only RLS policies grant table access
4. Roles cannot perform unauthorized operations
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from django.db import connection
from django.test import TestCase
from psycopg2 import sql

from django_postgres_rls.signals import auto_create_rls_roles


class TestRoleMinimalPermissions(TestCase):
    """Test that auto-created roles have absolutely minimal permissions."""

    def tearDown(self):
        """Clean up the processed flag after each test."""
        from django_postgres_rls.signals import auto_create_rls_roles
        if hasattr(auto_create_rls_roles, '_processed'):
            delattr(auto_create_rls_roles, '_processed')

    @patch('django_postgres_rls.signals.connection')
    @patch('django_postgres_rls.signals.settings')
    def test_roles_created_with_nologin(self, mock_settings, mock_connection):
        """Test that roles are created with NOLOGIN attribute."""
        from django_postgres_rls.signals import auto_create_rls_roles

        mock_settings.POSTGRES_RLS_AUTO_CREATE_ROLES = True
        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user']
        mock_connection.vendor = 'postgresql'

        mock_cursor = MagicMock()
        mock_cursor.__enter__ = Mock(return_value=mock_cursor)
        mock_cursor.__exit__ = Mock(return_value=False)
        mock_cursor.fetchall.return_value = []
        mock_connection.cursor.return_value = mock_cursor

        mock_app_config = Mock()
        mock_app_config.label = 'test'

        auto_create_rls_roles(
            sender=None,
            app_config=mock_app_config,
            verbosity=1
        )

        # Verify NOLOGIN is in the CREATE ROLE statement
        execute_calls = [str(call) for call in mock_cursor.execute.call_args_list]
        create_calls = [call for call in execute_calls if 'CREATE ROLE' in call]

        assert len(create_calls) > 0, "Should have CREATE ROLE call"
        assert 'NOLOGIN' in str(create_calls[0]), "Role should be created with NOLOGIN"

    @patch('django_postgres_rls.signals.connection')
    @patch('django_postgres_rls.signals.settings')
    def test_roles_created_with_nocreatedb(self, mock_settings, mock_connection):
        """Test that roles are created with NOCREATEDB attribute."""
        from django_postgres_rls.signals import auto_create_rls_roles

        mock_settings.POSTGRES_RLS_AUTO_CREATE_ROLES = True
        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user']
        mock_connection.vendor = 'postgresql'

        mock_cursor = MagicMock()
        mock_cursor.__enter__ = Mock(return_value=mock_cursor)
        mock_cursor.__exit__ = Mock(return_value=False)
        mock_cursor.fetchall.return_value = []
        mock_connection.cursor.return_value = mock_cursor

        mock_app_config = Mock()
        mock_app_config.label = 'test'

        auto_create_rls_roles(
            sender=None,
            app_config=mock_app_config,
            verbosity=1
        )

        # Verify NOCREATEDB is in the CREATE ROLE statement
        execute_calls = [str(call) for call in mock_cursor.execute.call_args_list]
        create_calls = [call for call in execute_calls if 'CREATE ROLE' in call]

        assert 'NOCREATEDB' in str(create_calls[0]), "Role should be created with NOCREATEDB"

    @patch('django_postgres_rls.signals.connection')
    @patch('django_postgres_rls.signals.settings')
    def test_roles_created_with_nocreaterole(self, mock_settings, mock_connection):
        """Test that roles are created with NOCREATEROLE attribute."""
        from django_postgres_rls.signals import auto_create_rls_roles

        mock_settings.POSTGRES_RLS_AUTO_CREATE_ROLES = True
        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user']
        mock_connection.vendor = 'postgresql'

        mock_cursor = MagicMock()
        mock_cursor.__enter__ = Mock(return_value=mock_cursor)
        mock_cursor.__exit__ = Mock(return_value=False)
        mock_cursor.fetchall.return_value = []
        mock_connection.cursor.return_value = mock_cursor

        mock_app_config = Mock()
        mock_app_config.label = 'test'

        auto_create_rls_roles(
            sender=None,
            app_config=mock_app_config,
            verbosity=1
        )

        # Verify NOCREATEROLE is in the CREATE ROLE statement
        execute_calls = [str(call) for call in mock_cursor.execute.call_args_list]
        create_calls = [call for call in execute_calls if 'CREATE ROLE' in call]

        assert 'NOCREATEROLE' in str(create_calls[0]), "Role should be created with NOCREATEROLE"

    @patch('django_postgres_rls.signals.connection')
    @patch('django_postgres_rls.signals.settings')
    def test_roles_created_with_nosuperuser(self, mock_settings, mock_connection):
        """Test that roles are created with NOSUPERUSER attribute."""
        from django_postgres_rls.signals import auto_create_rls_roles

        mock_settings.POSTGRES_RLS_AUTO_CREATE_ROLES = True
        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user']
        mock_connection.vendor = 'postgresql'

        mock_cursor = MagicMock()
        mock_cursor.__enter__ = Mock(return_value=mock_cursor)
        mock_cursor.__exit__ = Mock(return_value=False)
        mock_cursor.fetchall.return_value = []
        mock_connection.cursor.return_value = mock_cursor

        mock_app_config = Mock()
        mock_app_config.label = 'test'

        auto_create_rls_roles(
            sender=None,
            app_config=mock_app_config,
            verbosity=1
        )

        # Verify NOSUPERUSER is in the CREATE ROLE statement
        execute_calls = [str(call) for call in mock_cursor.execute.call_args_list]
        create_calls = [call for call in execute_calls if 'CREATE ROLE' in call]

        assert 'NOSUPERUSER' in str(create_calls[0]), "Role should be created with NOSUPERUSER"

    @patch('django_postgres_rls.signals.connection')
    @patch('django_postgres_rls.signals.settings')
    def test_roles_created_with_nobypassrls(self, mock_settings, mock_connection):
        """Test that roles are created with NOBYPASSRLS attribute."""
        from django_postgres_rls.signals import auto_create_rls_roles

        mock_settings.POSTGRES_RLS_AUTO_CREATE_ROLES = True
        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user']
        mock_connection.vendor = 'postgresql'

        mock_cursor = MagicMock()
        mock_cursor.__enter__ = Mock(return_value=mock_cursor)
        mock_cursor.__exit__ = Mock(return_value=False)
        mock_cursor.fetchall.return_value = []
        mock_connection.cursor.return_value = mock_cursor

        mock_app_config = Mock()
        mock_app_config.label = 'test'

        auto_create_rls_roles(
            sender=None,
            app_config=mock_app_config,
            verbosity=1
        )

        # Verify NOBYPASSRLS is in the CREATE ROLE statement
        execute_calls = [str(call) for call in mock_cursor.execute.call_args_list]
        create_calls = [call for call in execute_calls if 'CREATE ROLE' in call]

        assert 'NOBYPASSRLS' in str(create_calls[0]), "Role should be created with NOBYPASSRLS"

    @patch('django_postgres_rls.signals.connection')
    @patch('django_postgres_rls.signals.settings')
    def test_roles_created_with_noinherit(self, mock_settings, mock_connection):
        """Test that roles are created with NOINHERIT attribute."""
        from django_postgres_rls.signals import auto_create_rls_roles

        mock_settings.POSTGRES_RLS_AUTO_CREATE_ROLES = True
        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user']
        mock_connection.vendor = 'postgresql'

        mock_cursor = MagicMock()
        mock_cursor.__enter__ = Mock(return_value=mock_cursor)
        mock_cursor.__exit__ = Mock(return_value=False)
        mock_cursor.fetchall.return_value = []
        mock_connection.cursor.return_value = mock_cursor

        mock_app_config = Mock()
        mock_app_config.label = 'test'

        auto_create_rls_roles(
            sender=None,
            app_config=mock_app_config,
            verbosity=1
        )

        # Verify NOINHERIT is in the CREATE ROLE statement
        execute_calls = [str(call) for call in mock_cursor.execute.call_args_list]
        create_calls = [call for call in execute_calls if 'CREATE ROLE' in call]

        assert 'NOINHERIT' in str(create_calls[0]), "Role should be created with NOINHERIT"

    @patch('django_postgres_rls.signals.connection')
    @patch('django_postgres_rls.signals.settings')
    def test_roles_created_with_noreplication(self, mock_settings, mock_connection):
        """Test that roles are created with NOREPLICATION attribute."""
        from django_postgres_rls.signals import auto_create_rls_roles

        mock_settings.POSTGRES_RLS_AUTO_CREATE_ROLES = True
        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user']
        mock_connection.vendor = 'postgresql'

        mock_cursor = MagicMock()
        mock_cursor.__enter__ = Mock(return_value=mock_cursor)
        mock_cursor.__exit__ = Mock(return_value=False)
        mock_cursor.fetchall.return_value = []
        mock_connection.cursor.return_value = mock_cursor

        mock_app_config = Mock()
        mock_app_config.label = 'test'

        auto_create_rls_roles(
            sender=None,
            app_config=mock_app_config,
            verbosity=1
        )

        # Verify NOREPLICATION is in the CREATE ROLE statement
        execute_calls = [str(call) for call in mock_cursor.execute.call_args_list]
        create_calls = [call for call in execute_calls if 'CREATE ROLE' in call]

        assert 'NOREPLICATION' in str(create_calls[0]), "Role should be created with NOREPLICATION"

    @patch('django_postgres_rls.signals.connection')
    @patch('django_postgres_rls.signals.settings')
    def test_roles_created_with_all_restrictive_attributes(self, mock_settings, mock_connection):
        """Test that roles are created with ALL restrictive attributes at once."""
        from django_postgres_rls.signals import auto_create_rls_roles

        mock_settings.POSTGRES_RLS_AUTO_CREATE_ROLES = True
        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user']
        mock_connection.vendor = 'postgresql'

        mock_cursor = MagicMock()
        mock_cursor.__enter__ = Mock(return_value=mock_cursor)
        mock_cursor.__exit__ = Mock(return_value=False)
        mock_cursor.fetchall.return_value = []
        mock_connection.cursor.return_value = mock_cursor

        mock_app_config = Mock()
        mock_app_config.label = 'test'

        auto_create_rls_roles(
            sender=None,
            app_config=mock_app_config,
            verbosity=1
        )

        # Verify ALL restrictive attributes are in the CREATE ROLE statement
        execute_calls = [str(call) for call in mock_cursor.execute.call_args_list]
        create_calls = [call for call in execute_calls if 'CREATE ROLE' in call]

        assert len(create_calls) > 0, "Should have CREATE ROLE call"

        create_statement = str(create_calls[0])
        assert 'NOLOGIN' in create_statement
        assert 'NOCREATEDB' in create_statement
        assert 'NOCREATEROLE' in create_statement
        assert 'NOSUPERUSER' in create_statement
        assert 'NOREPLICATION' in create_statement
        assert 'NOBYPASSRLS' in create_statement
        assert 'NOINHERIT' in create_statement

    @patch('django_postgres_rls.signals.connection')
    @patch('django_postgres_rls.signals.settings')
    def test_roles_only_granted_to_current_user(self, mock_settings, mock_connection):
        """Test that roles are ONLY granted to CURRENT_USER, no other grants."""
        from django_postgres_rls.signals import auto_create_rls_roles

        mock_settings.POSTGRES_RLS_AUTO_CREATE_ROLES = True
        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user']
        mock_connection.vendor = 'postgresql'

        mock_cursor = MagicMock()
        mock_cursor.__enter__ = Mock(return_value=mock_cursor)
        mock_cursor.__exit__ = Mock(return_value=False)
        mock_cursor.fetchall.return_value = []
        mock_connection.cursor.return_value = mock_cursor

        mock_app_config = Mock()
        mock_app_config.label = 'test'

        auto_create_rls_roles(
            sender=None,
            app_config=mock_app_config,
            verbosity=1
        )

        # Verify there's exactly one GRANT statement (GRANT role TO CURRENT_USER)
        execute_calls = [str(call) for call in mock_cursor.execute.call_args_list]
        grant_calls = [call for call in execute_calls if 'GRANT' in call.upper()]

        # Should have exactly one GRANT call per role
        assert len(grant_calls) == 1, "Should have exactly one GRANT per role"
        assert 'CURRENT_USER' in grant_calls[0], "Should grant to CURRENT_USER only"


# Integration tests that verify role permissions with real PostgreSQL
pytestmark = pytest.mark.integration


class TestRolePermissionsIntegration:
    """Integration tests verifying roles have no permissions by default."""

    def test_role_cannot_select_from_table_without_policy(self, postgres_db, postgres_test_roles):
        """Test that a role cannot SELECT from a table without an RLS policy granting access."""
        from .integration_utils import switch_role, reset_role, enable_rls, grant_table_permissions

        # Create a test table
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_no_access (
                    id SERIAL PRIMARY KEY,
                    data TEXT
                )
            """)

            # Insert test data
            cursor.execute("INSERT INTO test_no_access (data) VALUES ('secret')")

        # Enable RLS but DO NOT create any policies
        enable_rls('test_no_access', force=True)

        # Grant basic table permissions to the role (SELECT, INSERT, etc.)
        grant_table_permissions('test_no_access', ['app_user'])

        # Switch to app_user role
        switch_role('app_user')

        # Should NOT be able to see any rows (no policy grants access)
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM test_no_access")
            count = cursor.fetchone()[0]
            assert count == 0, "Role should not see any rows without RLS policy"

        reset_role()

        # Cleanup
        with connection.cursor() as cursor:
            cursor.execute("DROP TABLE test_no_access")

    def test_role_cannot_insert_without_policy(self, postgres_db, postgres_test_roles):
        """Test that a role cannot INSERT into a table without an RLS policy allowing it."""
        from .integration_utils import switch_role, reset_role, enable_rls, grant_table_permissions

        # Create a test table
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_no_insert (
                    id SERIAL PRIMARY KEY,
                    data TEXT
                )
            """)

        # Enable RLS but DO NOT create any INSERT policies
        enable_rls('test_no_insert', force=True)
        grant_table_permissions('test_no_insert', ['app_user'])

        # Switch to app_user role
        switch_role('app_user')

        # Should NOT be able to insert (no WITH CHECK policy)
        with pytest.raises(Exception) as exc_info:
            with connection.cursor() as cursor:
                cursor.execute("INSERT INTO test_no_insert (data) VALUES ('test')")

        assert "new row violates row-level security policy" in str(exc_info.value).lower() or \
               "permission denied" in str(exc_info.value).lower()

        reset_role()

        # Cleanup
        with connection.cursor() as cursor:
            cursor.execute("DROP TABLE test_no_insert")

    def test_policy_grants_correct_access(self, postgres_db, postgres_test_roles):
        """Test that RLS policies correctly grant access to specific rows."""
        from .integration_utils import (
            switch_role, reset_role, enable_rls,
            grant_table_permissions, set_session_variable, insert_test_data
        )

        # Create a test table
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_policy_access (
                    id SERIAL PRIMARY KEY,
                    owner_id INTEGER,
                    data TEXT
                )
            """)

        # Enable RLS
        enable_rls('test_policy_access', force=True)
        grant_table_permissions('test_policy_access', ['app_user'])

        # Create policy: users can only see their own rows
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE POLICY user_own_rows ON test_policy_access
                FOR SELECT
                TO app_user
                USING (owner_id = current_setting('app.current_user_id')::int)
            """)

        # Insert test data
        insert_test_data('test_policy_access', [
            {'owner_id': 1, 'data': 'User 1 Data'},
            {'owner_id': 2, 'data': 'User 2 Data'},
            {'owner_id': 1, 'data': 'User 1 More Data'},
        ])

        # Test as user 1
        switch_role('app_user')
        set_session_variable('app.current_user_id', '1')

        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM test_policy_access")
            count = cursor.fetchone()[0]
            assert count == 2, "User 1 should see exactly 2 rows"

            cursor.execute("SELECT data FROM test_policy_access ORDER BY id")
            rows = cursor.fetchall()
            assert len(rows) == 2
            assert rows[0][0] == 'User 1 Data'
            assert rows[1][0] == 'User 1 More Data'

        # Test as user 2
        set_session_variable('app.current_user_id', '2')

        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM test_policy_access")
            count = cursor.fetchone()[0]
            assert count == 1, "User 2 should see exactly 1 row"

            cursor.execute("SELECT data FROM test_policy_access")
            rows = cursor.fetchall()
            assert rows[0][0] == 'User 2 Data'

        reset_role()

        # Cleanup
        with connection.cursor() as cursor:
            cursor.execute("DROP TABLE test_policy_access")

    def test_role_cannot_access_other_tables(self, postgres_db, postgres_test_roles):
        """Test that a role cannot access tables it hasn't been granted permissions on."""
        from .integration_utils import switch_role, reset_role

        # Create two test tables
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_table_1 (
                    id SERIAL PRIMARY KEY,
                    data TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_table_2 (
                    id SERIAL PRIMARY KEY,
                    data TEXT
                )
            """)

            cursor.execute("INSERT INTO test_table_1 (data) VALUES ('data1')")
            cursor.execute("INSERT INTO test_table_2 (data) VALUES ('data2')")

        # Grant access ONLY to test_table_1
        with connection.cursor() as cursor:
            cursor.execute("GRANT SELECT ON test_table_1 TO app_user")

        # Switch to app_user
        switch_role('app_user')

        # Should be able to access test_table_1
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM test_table_1")
            count = cursor.fetchone()[0]
            assert count == 1

        # Should NOT be able to access test_table_2
        with pytest.raises(Exception) as exc_info:
            with connection.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) FROM test_table_2")

        assert "permission denied" in str(exc_info.value).lower()

        reset_role()

        # Cleanup
        with connection.cursor() as cursor:
            cursor.execute("DROP TABLE test_table_1")
            cursor.execute("DROP TABLE test_table_2")

    def test_role_cannot_create_tables(self, postgres_db, postgres_test_roles):
        """Test that roles cannot create tables (NOCREATEDB enforcement)."""
        from .integration_utils import switch_role, reset_role

        # Switch to app_user role
        switch_role('app_user')

        # Should NOT be able to create tables
        with pytest.raises(Exception) as exc_info:
            with connection.cursor() as cursor:
                cursor.execute("CREATE TABLE unauthorized_table (id INTEGER)")

        assert "permission denied" in str(exc_info.value).lower() or \
               "must be owner" in str(exc_info.value).lower()

        reset_role()

    def test_multiple_policies_combined_correctly(self, postgres_db, postgres_test_roles):
        """Test that multiple policies are combined correctly (OR for PERMISSIVE)."""
        from .integration_utils import (
            switch_role, reset_role, enable_rls,
            grant_table_permissions, set_session_variable, insert_test_data
        )

        # Create a test table
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_multi_policy (
                    id SERIAL PRIMARY KEY,
                    owner_id INTEGER,
                    is_public BOOLEAN
                )
            """)

        enable_rls('test_multi_policy', force=True)
        grant_table_permissions('test_multi_policy', ['app_user'])

        # Policy 1: See own rows
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE POLICY own_rows ON test_multi_policy
                FOR SELECT
                TO app_user
                USING (owner_id = current_setting('app.current_user_id')::int)
            """)

        # Policy 2: See public rows
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE POLICY public_rows ON test_multi_policy
                FOR SELECT
                TO app_user
                USING (is_public = true)
            """)

        # Insert test data
        insert_test_data('test_multi_policy', [
            {'owner_id': 1, 'is_public': False},  # User 1 private
            {'owner_id': 1, 'is_public': True},   # User 1 public
            {'owner_id': 2, 'is_public': False},  # User 2 private
            {'owner_id': 2, 'is_public': True},   # User 2 public
        ])

        # Test as user 1
        switch_role('app_user')
        set_session_variable('app.current_user_id', '1')

        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM test_multi_policy")
            count = cursor.fetchone()[0]
            # Should see: own private (1) + own public (1) + other's public (1) = 3
            assert count == 3, "User 1 should see 3 rows (own + all public)"

        reset_role()

        # Cleanup
        with connection.cursor() as cursor:
            cursor.execute("DROP TABLE test_multi_policy")
