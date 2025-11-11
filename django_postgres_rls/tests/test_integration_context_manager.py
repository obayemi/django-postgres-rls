"""
Integration tests for rls_role context manager with real PostgreSQL.

Tests the context manager for explicit role switching.
"""

import pytest
from django.db import connection

from django_postgres_rls import rls_role
from .integration_utils import (
    get_current_role,
    get_session_variable,
    insert_test_data,
    enable_rls,
    reset_role,
)


pytestmark = pytest.mark.integration


class TestContextManagerRoleSwitching:
    """Test context manager role switching."""

    def test_context_manager_switches_role(self, postgres_db, postgres_test_roles):
        """Test that context manager switches and restores role."""
        initial_role = get_current_role()

        with rls_role('app_user'):
            # Role should be switched
            current_role = get_current_role()
            assert current_role == 'app_user'
            assert current_role != initial_role

        # Role should be restored
        restored_role = get_current_role()
        assert restored_role != 'app_user'

    def test_context_manager_sets_user_id(self, postgres_db, postgres_test_roles):
        """Test that context manager sets user ID session variable."""
        with rls_role('app_user', user_id=123):
            user_id = get_session_variable('app.current_user_id')
            assert user_id == '123'

    def test_context_manager_restores_role_on_exception(self, postgres_db, postgres_test_roles):
        """Test that role is restored even when exception occurs."""
        initial_role = get_current_role()

        try:
            with rls_role('app_staff'):
                assert get_current_role() == 'app_staff'
                raise ValueError("Test exception")
        except ValueError:
            pass

        # Role should still be restored
        current_role = get_current_role()
        assert current_role != 'app_staff'

    def test_nested_context_managers_raises_error(self, postgres_db, postgres_test_roles):
        """Test that nested context managers raise RuntimeError."""
        import pytest

        with rls_role('app_user', user_id=1):
            assert get_current_role() == 'app_user'
            assert get_session_variable('app.current_user_id') == '1'

            # Attempting to nest should raise RuntimeError
            with pytest.raises(RuntimeError) as exc_info:
                with rls_role('app_staff', user_id=2):
                    pass

            # Verify error message is helpful
            assert 'Cannot switch roles when already in application role' in str(exc_info.value)
            assert 'app_user' in str(exc_info.value)
            assert 'Nested rls_role() usage is not supported' in str(exc_info.value)

            # Should still be in app_user role
            assert get_current_role() == 'app_user'

    def test_context_manager_with_queries(self, postgres_db, postgres_test_roles):
        """Test context manager with actual database queries."""
        from .integration_utils import grant_table_permissions

        # Create test table
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_ctx_docs (
                    id SERIAL PRIMARY KEY,
                    owner_id INTEGER,
                    title TEXT
                )
            """)

        # Grant permissions to test roles
        grant_table_permissions('test_ctx_docs', ['app_user', 'app_staff'])

        # Enable RLS
        enable_rls('test_ctx_docs', force=True)

        # Create policies
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE POLICY user_own_docs ON test_ctx_docs
                FOR SELECT
                TO app_user
                USING (owner_id = current_setting('app.current_user_id')::int)
            """)

            cursor.execute("""
                CREATE POLICY staff_all_docs ON test_ctx_docs
                FOR SELECT
                TO app_staff
                USING (true)
            """)

        # Insert test data
        insert_test_data('test_ctx_docs', [
            {'owner_id': 1, 'title': 'User 1 Doc'},
            {'owner_id': 2, 'title': 'User 2 Doc'},
        ])

        # Query as user 1
        with rls_role('app_user', user_id=1):
            with connection.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) FROM test_ctx_docs")
                count = cursor.fetchone()[0]
                assert count == 1, "User 1 should see only their document"

        # Query as staff
        with rls_role('app_staff'):
            with connection.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) FROM test_ctx_docs")
                count = cursor.fetchone()[0]
                assert count == 2, "Staff should see all documents"

        # Cleanup
        with connection.cursor() as cursor:
            cursor.execute("DROP TABLE test_ctx_docs")

    def test_context_manager_respects_valid_roles(self, postgres_db, postgres_test_roles, settings):
        """Test that context manager validates roles."""
        settings.POSTGRES_RLS_VALID_ROLES = frozenset(['app_user', 'app_staff'])

        # Valid role should work
        with rls_role('app_user', valid_roles=settings.POSTGRES_RLS_VALID_ROLES):
            assert get_current_role() == 'app_user'

        # Invalid role should raise error
        with pytest.raises(ValueError):
            with rls_role('invalid_role', valid_roles=settings.POSTGRES_RLS_VALID_ROLES):
                pass

    def test_context_manager_custom_session_variable(self, postgres_db, postgres_test_roles):
        """Test context manager with custom session variable name."""
        with rls_role('app_user', user_id=999, session_uid_variable='custom.user_id'):
            # Should use custom variable name
            user_id = get_session_variable('custom.user_id')
            assert user_id == '999'

    def test_multiple_sequential_context_managers(self, postgres_db, postgres_test_roles):
        """Test multiple sequential context managers."""
        # First context
        with rls_role('app_user', user_id=1):
            assert get_current_role() == 'app_user'
            assert get_session_variable('app.current_user_id') == '1'

        # Second context (different role)
        with rls_role('app_staff', user_id=2):
            assert get_current_role() == 'app_staff'
            assert get_session_variable('app.current_user_id') == '2'

        # Third context (back to user)
        with rls_role('app_user', user_id=3):
            assert get_current_role() == 'app_user'
            assert get_session_variable('app.current_user_id') == '3'
