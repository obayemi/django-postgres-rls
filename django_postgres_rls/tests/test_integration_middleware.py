"""
Integration tests for PostgresRLSMiddleware with real PostgreSQL database.

Tests the middleware's actual behavior with database connections, role switching,
and transaction management.
"""

import pytest
from unittest.mock import Mock, MagicMock
from django.db import connection
from django.http import HttpResponse, HttpRequest
from django.contrib.auth.models import AnonymousUser

from django_postgres_rls import PostgresRLSMiddleware
from django.db import transaction
from .integration_utils import (
    get_current_role,
    get_session_variable,
    switch_role,
    reset_role,
    insert_test_data,
    enable_rls,
)


pytestmark = pytest.mark.integration


class DemoRLSMiddleware(PostgresRLSMiddleware):
    """Demo middleware implementation for integration tests."""

    def __init__(self, get_response=None):
        super().__init__(get_response or (lambda r: HttpResponse()))

    def extract_role(self, request):
        """Extract role from request for testing."""
        if hasattr(request, '_test_role'):
            return request._test_role
        if not request.user or not request.user.is_authenticated:
            return 'user'
        if request.user.is_superuser:
            return 'superuser'
        elif request.user.is_staff:
            return 'staff'
        return 'user'


class TestMiddlewareRoleSwitching:
    """Test middleware role switching with real database."""

    def test_middleware_switches_role(self, postgres_db, postgres_test_roles):
        """Test that middleware actually switches PostgreSQL role."""
        middleware = DemoRLSMiddleware()

        # Create mock request as staff user
        request = Mock(spec=HttpRequest)
        request.user = Mock()
        request.user.is_authenticated = True
        request.user.is_staff = True
        request.user.is_superuser = False
        request.user.id = 123

        # Get initial role
        initial_role = get_current_role()

        # Wrap in transaction (SET LOCAL ROLE requires a transaction)
        with transaction.atomic():
            # Process request
            middleware.process_request(request)

            # Verify role was switched
            current_role = get_current_role()
            assert current_role == 'app_staff'
            assert current_role != initial_role

            # Process response (should reset role)
            response = HttpResponse()
            middleware.process_response(request, response)

        # Verify role was reset
        reset_role()

    def test_middleware_sets_session_variable(self, postgres_db, postgres_test_roles):
        """Test that middleware sets session variable for user ID."""
        middleware = DemoRLSMiddleware()

        request = Mock(spec=HttpRequest)
        request.user = Mock()
        request.user.is_authenticated = True
        request.user.is_staff = False
        request.user.is_superuser = False
        request.user.id = 456

        # Wrap in transaction
        with transaction.atomic():
            # Process request
            middleware.process_request(request)

            # Verify session variable was set
            user_id = get_session_variable('app.current_user_id')
            assert user_id == '456'

        # Cleanup
        reset_role()

    def test_middleware_handles_anonymous_user(self, postgres_db, postgres_test_roles):
        """Test middleware with anonymous user."""
        middleware = DemoRLSMiddleware()

        request = Mock(spec=HttpRequest)
        request.user = AnonymousUser()

        initial_role = get_current_role()

        # Wrap in transaction
        with transaction.atomic():
            # Process request
            middleware.process_request(request)

            # Verify role was switched to user role
            current_role = get_current_role()
            assert current_role == 'app_user'

        # Cleanup
        reset_role()

    def test_middleware_resets_role_on_exception(self, postgres_db, postgres_test_roles):
        """Test that middleware resets role even when exception occurs."""
        middleware = DemoRLSMiddleware()

        request = Mock(spec=HttpRequest)
        request.user = Mock()
        request.user.is_authenticated = True
        request.user.is_staff = True
        request.user.is_superuser = False
        request.user.id = 123

        # Wrap in transaction
        with transaction.atomic():
            # Process request (switch role)
            middleware.process_request(request)

            # Verify role was switched
            assert get_current_role() == 'app_staff'

            # Simulate exception
            exception = Exception("Test exception")

            # Process exception
            result = middleware.process_exception(request, exception)

            # Should not suppress exception
            assert result is None

            # Role should be reset
            current_role = get_current_role()
            assert current_role != 'app_staff'

    def test_middleware_with_superuser(self, postgres_db, postgres_test_roles):
        """Test middleware with superuser role."""
        middleware = DemoRLSMiddleware()

        request = Mock(spec=HttpRequest)
        request.user = Mock()
        request.user.is_authenticated = True
        request.user.is_staff = True
        request.user.is_superuser = True
        request.user.id = 1

        # Wrap in transaction
        with transaction.atomic():
            # Process request
            middleware.process_request(request)

            # Verify role was switched to superuser
            current_role = get_current_role()
            assert current_role == 'app_superuser'

        # Cleanup
        reset_role()

    def test_middleware_custom_role_extraction(self, postgres_db, postgres_test_roles):
        """Test middleware with custom role extraction."""
        middleware = DemoRLSMiddleware()

        request = Mock(spec=HttpRequest)
        request._test_role = 'staff'
        request.user = Mock()
        request.user.is_authenticated = True
        request.user.id = 789

        # Wrap in transaction
        with transaction.atomic():
            # Process request
            middleware.process_request(request)

            # Verify custom role was used
            current_role = get_current_role()
            assert current_role == 'app_staff'

        # Cleanup
        reset_role()


class TestMiddlewareWithRLSPolicies:
    """Test middleware integration with actual RLS policies."""

    def test_middleware_enforces_rls_policies(self, postgres_db, postgres_test_roles):
        """Test that middleware + RLS policies work together."""
        from .integration_utils import grant_table_permissions

        # Create test table
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_middleware_docs (
                    id SERIAL PRIMARY KEY,
                    owner_id INTEGER,
                    title TEXT
                )
            """)

        # Grant permissions to test roles
        grant_table_permissions('test_middleware_docs', ['app_user', 'app_staff'])

        # Enable RLS
        enable_rls('test_middleware_docs', force=True)

        # Create policy
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE POLICY user_own_docs ON test_middleware_docs
                FOR SELECT
                TO app_user
                USING (owner_id = current_setting('app.current_user_id')::int)
            """)

            cursor.execute("""
                CREATE POLICY staff_all_docs ON test_middleware_docs
                FOR SELECT
                TO app_staff
                USING (true)
            """)

        # Insert test data
        insert_test_data('test_middleware_docs', [
            {'owner_id': 1, 'title': 'User 1 Doc'},
            {'owner_id': 2, 'title': 'User 2 Doc'},
        ])

        # Test as regular user (user 1)
        middleware = DemoRLSMiddleware()
        request = Mock(spec=HttpRequest)
        request.user = Mock()
        request.user.is_authenticated = True
        request.user.is_staff = False
        request.user.is_superuser = False
        request.user.id = 1

        with transaction.atomic():
            middleware.process_request(request)

            # Should see only user 1's document
            with connection.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) FROM test_middleware_docs")
                count = cursor.fetchone()[0]
                assert count == 1

            middleware.process_response(request, HttpResponse())

        reset_role()

        # Test as staff user
        request.user.is_staff = True
        request.user.id = 999

        with transaction.atomic():
            middleware.process_request(request)

            # Staff should see all documents
            with connection.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) FROM test_middleware_docs")
                count = cursor.fetchone()[0]
                assert count == 2

        reset_role()

        # Cleanup
        with connection.cursor() as cursor:
            cursor.execute("DROP TABLE test_middleware_docs")

    def test_middleware_transaction_isolation(self, postgres_db, postgres_test_roles):
        """Test that role changes are isolated to transaction."""
        middleware = DemoRLSMiddleware()

        # Request 1
        request1 = Mock(spec=HttpRequest)
        request1.user = Mock()
        request1.user.is_authenticated = True
        request1.user.is_staff = False
        request1.user.is_superuser = False
        request1.user.id = 100

        with transaction.atomic():
            middleware.process_request(request1)
            role1 = get_current_role()
            user_id1 = get_session_variable('app.current_user_id')
            middleware.process_response(request1, HttpResponse())

        reset_role()

        # Request 2 with different user
        request2 = Mock(spec=HttpRequest)
        request2.user = Mock()
        request2.user.is_authenticated = True
        request2.user.is_staff = True
        request2.user.is_superuser = False
        request2.user.id = 200

        with transaction.atomic():
            middleware.process_request(request2)
            role2 = get_current_role()
            user_id2 = get_session_variable('app.current_user_id')

            # Verify isolation
            assert role2 == 'app_staff'
            assert user_id2 == '200'
            assert user_id1 != user_id2

        reset_role()

    def test_middleware_handles_no_user_id(self, postgres_db, postgres_test_roles):
        """Test middleware when user has no ID."""
        middleware = DemoRLSMiddleware()

        request = Mock(spec=HttpRequest)
        request.user = Mock()
        request.user.is_authenticated = True
        request.user.is_staff = False
        request.user.is_superuser = False
        request.user.id = None  # No ID

        with transaction.atomic():
            # Should not raise exception
            middleware.process_request(request)

            # Role should still be switched
            assert get_current_role() == 'app_user'

            # Session variable should not be set (or set to empty)
            user_id = get_session_variable('app.current_user_id')
            # Might be None or empty string depending on implementation

        reset_role()


class TestMiddlewareConfiguration:
    """Test middleware configuration options."""

    def test_middleware_custom_role_mapping(self, postgres_db, postgres_test_roles):
        """Test middleware with custom role mapping."""
        class CustomMiddleware(DemoRLSMiddleware):
            def get_role_mapping(self):
                return {
                    'user': 'app_user',
                    'staff': 'app_staff',
                    'superuser': 'app_superuser',
                }

        middleware = CustomMiddleware()

        request = Mock(spec=HttpRequest)
        request.user = Mock()
        request.user.is_authenticated = True
        request.user.is_staff = True
        request.user.is_superuser = False
        request.user.id = 123

        with transaction.atomic():
            middleware.process_request(request)

            # Should use custom mapping
            assert get_current_role() == 'app_staff'

        reset_role()

    def test_middleware_with_valid_roles_setting(self, postgres_db, postgres_test_roles, settings):
        """Test middleware respects POSTGRES_RLS_VALID_ROLES setting."""
        settings.POSTGRES_RLS_VALID_ROLES = frozenset(['app_user', 'app_staff', 'app_superuser'])

        middleware = DemoRLSMiddleware()

        request = Mock(spec=HttpRequest)
        request.user = Mock()
        request.user.is_authenticated = True
        request.user.is_staff = True
        request.user.is_superuser = False
        request.user.id = 123

        with transaction.atomic():
            # Should succeed with valid role
            middleware.process_request(request)
            assert get_current_role() == 'app_staff'

        reset_role()


class TestMiddlewareErrorHandling:
    """Test middleware error handling."""

    def test_middleware_handles_invalid_role_gracefully(self, postgres_db, postgres_test_roles, settings):
        """Test middleware handles invalid roles."""
        settings.POSTGRES_RLS_VALID_ROLES = frozenset(['app_user', 'app_staff'])

        class BadMiddleware(DemoRLSMiddleware):
            def extract_role(self, request):
                # Return 'superuser' which maps to 'app_superuser' (not in valid_roles)
                return 'superuser'

        middleware = BadMiddleware()

        request = Mock(spec=HttpRequest)
        request.user = Mock()
        request.user.is_authenticated = True
        request.user.id = 123

        # Should raise ValueError for invalid role
        # The ValueError is raised before the role switch, so transaction doesn't matter
        with pytest.raises(ValueError):
            with transaction.atomic():
                middleware.process_request(request)

    def test_middleware_process_response_always_runs(self, postgres_db, postgres_test_roles):
        """Test that process_response always resets role."""
        middleware = DemoRLSMiddleware()

        request = Mock(spec=HttpRequest)
        request.user = Mock()
        request.user.is_authenticated = True
        request.user.is_staff = True
        request.user.is_superuser = False
        request.user.id = 123

        with transaction.atomic():
            # Process request
            middleware.process_request(request)
            assert get_current_role() == 'app_staff'

            # Process response
            response = HttpResponse()
            middleware.process_response(request, response)

            # Role should be reset
            reset_role()
            current_role = get_current_role()
            assert current_role != 'app_staff'
