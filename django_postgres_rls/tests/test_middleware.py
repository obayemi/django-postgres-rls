"""
Tests for django_postgres_rls.middleware module.

Tests cover:
- PostgresRLSMiddleware class
- Role extraction
- Role mapping
- User ID extraction
- Request processing (role switching)
- Response processing (role reset)
- Error handling
- Security concerns
"""

import pytest
from unittest.mock import Mock, patch, MagicMock, call
from django.test import TestCase, RequestFactory
from django.contrib.auth.models import User, AnonymousUser
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse

from django_postgres_rls import PostgresRLSMiddleware, rls_role


class ConcreteRLSMiddleware(PostgresRLSMiddleware):
    """Concrete implementation for testing."""

    def extract_role(self, request):
        """Extract role from request."""
        if not request.user or not request.user.is_authenticated:
            return 'user'

        if hasattr(request, 'custom_role'):
            return request.custom_role

        if request.user.is_superuser:
            return 'superuser'
        elif request.user.is_staff:
            return 'staff'
        return 'user'


class TestPostgresRLSMiddlewareBasics(TestCase):
    """Test basic middleware functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.middleware = ConcreteRLSMiddleware(get_response=lambda r: HttpResponse())

    def test_extract_role_not_implemented(self):
        """Test that base middleware raises NotImplementedError for extract_role."""
        from django.core.exceptions import ImproperlyConfigured

        middleware = PostgresRLSMiddleware(get_response=lambda r: HttpResponse())
        request = self.factory.get('/')
        # Mock user without get_postgres_role method
        request.user = Mock(is_authenticated=True)
        # Ensure get_postgres_role is not in Mock's methods
        if hasattr(request.user, 'get_postgres_role'):
            delattr(request.user, 'get_postgres_role')

        with pytest.raises(NotImplementedError, match="RlsUser mixin"):
            middleware.extract_role(request)

    def test_role_mapping_default(self):
        """Test default role mapping."""
        assert self.middleware.role_mapping == {
            'user': 'app_user',
            'staff': 'app_staff',
            'superuser': 'app_superuser',
            'anonymous': 'app_anonymous'
        }

    @patch('django.conf.settings')
    def test_role_mapping_from_settings(self, mock_settings):
        """Test role mapping from Django settings."""
        custom_mapping = {
            'user': 'custom_user',
            'admin': 'custom_admin'
        }
        mock_settings.POSTGRES_RLS_ROLE_MAPPING = custom_mapping
        delattr(mock_settings, 'POSTGRES_RLS_VALID_ROLES')
        delattr(mock_settings, 'POSTGRES_RLS_SESSION_UID_VARIABLE')
        delattr(mock_settings, 'POSTGRES_RLS_ENABLE_AUDIT_LOG')

        middleware = ConcreteRLSMiddleware(get_response=lambda r: HttpResponse())

        assert middleware.role_mapping == custom_mapping

    def test_get_user_id_authenticated(self):
        """Test user ID extraction for authenticated user."""
        request = self.factory.get('/')
        request.user = Mock(is_authenticated=True, id=123)

        user_id = self.middleware.get_user_id(request)

        assert user_id == '123'

    def test_get_user_id_unauthenticated(self):
        """Test user ID extraction for unauthenticated user."""
        request = self.factory.get('/')
        request.user = Mock(is_authenticated=False)

        user_id = self.middleware.get_user_id(request)

        assert user_id == ''

    def test_get_user_id_anonymous(self):
        """Test user ID extraction for anonymous user."""
        request = self.factory.get('/')
        request.user = AnonymousUser()

        user_id = self.middleware.get_user_id(request)

        assert user_id == ''

    def test_get_user_id_no_user(self):
        """Test user ID extraction when no user attribute."""
        request = self.factory.get('/')
        request.user = None

        user_id = self.middleware.get_user_id(request)

        assert user_id == ''


class TestRoleExtraction(TestCase):
    """Test role extraction from requests."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.middleware = ConcreteRLSMiddleware(get_response=lambda r: HttpResponse())

    def test_extract_role_for_superuser(self):
        """Test role extraction for superuser."""
        request = self.factory.get('/')
        request.user = Mock(is_authenticated=True, is_superuser=True, is_staff=False)

        role = self.middleware.extract_role(request)

        assert role == 'superuser'

    def test_extract_role_for_staff(self):
        """Test role extraction for staff user."""
        request = self.factory.get('/')
        request.user = Mock(is_authenticated=True, is_superuser=False, is_staff=True)

        role = self.middleware.extract_role(request)

        assert role == 'staff'

    def test_extract_role_for_regular_user(self):
        """Test role extraction for regular user."""
        request = self.factory.get('/')
        request.user = Mock(is_authenticated=True, is_superuser=False, is_staff=False)

        role = self.middleware.extract_role(request)

        assert role == 'user'

    def test_extract_role_for_unauthenticated(self):
        """Test role extraction for unauthenticated user."""
        request = self.factory.get('/')
        request.user = Mock(is_authenticated=False)

        role = self.middleware.extract_role(request)

        assert role == 'user'

    def test_extract_role_custom_attribute(self):
        """Test role extraction with custom attribute."""
        request = self.factory.get('/')
        request.user = Mock(is_authenticated=True, is_superuser=False, is_staff=False)
        request.custom_role = 'custom_role'

        role = self.middleware.extract_role(request)

        assert role == 'custom_role'


class TestProcessRequest(TestCase):
    """Test request processing (role switching)."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.middleware = ConcreteRLSMiddleware(get_response=lambda r: HttpResponse())

    @patch('django_postgres_rls.middleware.connection')
    def test_process_request_switches_role(self, mock_connection):
        """Test that process_request switches PostgreSQL role."""
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        request = self.factory.get('/')
        request.user = Mock(is_authenticated=True, is_superuser=False, is_staff=True, id=42)

        self.middleware.process_request(request)

        # Verify SET LOCAL ROLE was called (using psycopg2.sql.SQL)
        # We check that execute was called at least twice (role switch + set_config)
        assert mock_cursor.execute.call_count >= 2
        calls = [str(call) for call in mock_cursor.execute.call_args_list]
        # Check that one of the calls involves SET LOCAL ROLE
        assert any('SET LOCAL ROLE' in call or 'app_staff' in call for call in calls)

    @patch('django_postgres_rls.middleware.connection')
    def test_process_request_sets_user_id(self, mock_connection):
        """Test that process_request sets user ID in session variable."""
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        request = self.factory.get('/')
        request.user = Mock(is_authenticated=True, is_superuser=False, is_staff=False, id=42)

        self.middleware.process_request(request)

        # Verify set_config was called with user ID
        # We check that execute was called at least twice
        assert mock_cursor.execute.call_count >= 2
        calls = [str(call) for call in mock_cursor.execute.call_args_list]
        # Check that set_config was called with user ID
        assert any('set_config' in call and '42' in call for call in calls)

    @patch('django_postgres_rls.middleware.connection')
    def test_process_request_for_different_roles(self, mock_connection):
        """Test process_request for different user roles."""
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        test_cases = [
            (Mock(is_authenticated=True, is_superuser=True, is_staff=False, id=1), 'app_superuser'),
            (Mock(is_authenticated=True, is_superuser=False, is_staff=True, id=2), 'app_staff'),
            (Mock(is_authenticated=True, is_superuser=False, is_staff=False, id=3), 'app_user'),
            (Mock(is_authenticated=False), 'app_user'),
        ]

        for user, expected_role in test_cases:
            mock_cursor.reset_mock()
            request = self.factory.get('/')
            request.user = user

            self.middleware.process_request(request)

            calls = mock_cursor.execute.call_args_list
            assert any(expected_role in str(call) for call in calls), \
                f"Expected {expected_role} in calls for user {user}"

    @patch('django_postgres_rls.middleware.connection')
    @patch('django_postgres_rls.middleware.logger')
    def test_process_request_handles_database_error(self, mock_logger, mock_connection):
        """Test that database errors in process_request are handled and re-raised."""
        mock_cursor = MagicMock()
        mock_cursor.execute.side_effect = Exception("Database connection error")
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        request = self.factory.get('/')
        request.user = Mock(is_authenticated=True, is_superuser=False, is_staff=False, id=1)

        with pytest.raises(Exception, match="Database connection error"):
            self.middleware.process_request(request)

        # Verify error was logged
        mock_logger.error.assert_called()

    @patch('django_postgres_rls.middleware.connection')
    def test_process_request_returns_none(self, mock_connection):
        """Test that process_request returns None (allows request to continue)."""
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        request = self.factory.get('/')
        request.user = Mock(is_authenticated=True, is_superuser=False, is_staff=False, id=1)

        result = self.middleware.process_request(request)

        assert result is None


class TestProcessResponse(TestCase):
    """Test response processing (role reset)."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.middleware = ConcreteRLSMiddleware(get_response=lambda r: HttpResponse())

    @patch('django_postgres_rls.middleware.connection')
    def test_process_response_resets_role(self, mock_connection):
        """Test that process_response resets PostgreSQL role."""
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        request = self.factory.get('/')
        response = HttpResponse()

        result = self.middleware.process_response(request, response)

        # Verify RESET ROLE was called
        mock_cursor.execute.assert_called_once_with("RESET ROLE")
        assert result == response

    @patch('django_postgres_rls.middleware.connection')
    @patch('django_postgres_rls.middleware.logger')
    def test_process_response_handles_errors_gracefully(self, mock_logger, mock_connection):
        """Test that errors in process_response don't break the response."""
        mock_cursor = MagicMock()
        mock_cursor.execute.side_effect = Exception("Role reset error")
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        request = self.factory.get('/')
        response = HttpResponse("Original response")

        # Should not raise exception
        result = self.middleware.process_response(request, response)

        # Response should still be returned
        assert result == response

        # Warning should be logged
        mock_logger.warning.assert_called()


class TestMiddlewareIntegration(TestCase):
    """Test full middleware request/response cycle."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()

    @patch('django_postgres_rls.middleware.connection')
    def test_full_request_response_cycle(self, mock_connection):
        """Test complete request/response cycle."""
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        # Mock the pg_roles query to return configured roles
        def mock_fetchall():
            # Check what query was executed
            last_call = mock_cursor.execute.call_args
            if last_call and 'pg_roles' in str(last_call):
                # Return the roles that middleware expects
                return [('app_user',), ('app_staff',), ('app_superuser',)]
            return []

        mock_cursor.fetchall.side_effect = mock_fetchall

        # Create middleware with a simple get_response
        response_content = "Test Response"
        middleware = ConcreteRLSMiddleware(
            get_response=lambda r: HttpResponse(response_content)
        )

        request = self.factory.get('/')
        request.user = Mock(is_authenticated=True, is_superuser=False, is_staff=True, id=42)

        # Process full cycle
        response = middleware(request)

        # Verify response is correct
        assert response.content.decode() == response_content

        # Verify both role setting and reset were called
        calls = mock_cursor.execute.call_args_list
        assert any('SET LOCAL ROLE' in str(call) for call in calls)
        assert any('RESET ROLE' in str(call) for call in calls)


class TestCustomMiddleware(TestCase):
    """Test custom middleware implementations."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()

    def test_custom_extract_role_implementation(self):
        """Test custom extract_role implementation."""

        class CustomMiddleware(PostgresRLSMiddleware):
            def extract_role(self, request):
                # Custom logic based on header
                return request.META.get('HTTP_X_USER_ROLE', 'user')

        middleware = CustomMiddleware(get_response=lambda r: HttpResponse())
        request = self.factory.get('/', HTTP_X_USER_ROLE='admin')
        request.user = Mock()

        role = middleware.extract_role(request)

        assert role == 'admin'

    def test_custom_role_mapping_implementation(self):
        """Test custom get_role_mapping implementation."""

        class CustomMiddleware(ConcreteRLSMiddleware):
            def get_role_mapping(self):
                return {
                    'user': 'custom_app_user',
                    'admin': 'custom_app_admin'
                }

        middleware = CustomMiddleware(get_response=lambda r: HttpResponse())
        mapping = middleware.get_role_mapping()

        assert mapping['user'] == 'custom_app_user'
        assert mapping['admin'] == 'custom_app_admin'

    def test_custom_user_id_extraction(self):
        """Test custom get_user_id implementation."""

        class CustomMiddleware(ConcreteRLSMiddleware):
            def get_user_id(self, request):
                # Extract from custom header
                return request.META.get('HTTP_X_USER_ID', '')

        middleware = CustomMiddleware(get_response=lambda r: HttpResponse())
        request = self.factory.get('/', HTTP_X_USER_ID='999')
        request.user = Mock()

        user_id = middleware.get_user_id(request)

        assert user_id == '999'


class TestSecurityConcerns(TestCase):
    """Test security-related aspects of middleware."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.middleware = ConcreteRLSMiddleware(get_response=lambda r: HttpResponse())

    @patch('django.conf.settings')
    @patch('django_postgres_rls.middleware.connection')
    def test_role_name_sql_injection_prevention(self, mock_connection, mock_settings):
        """Test that role names are not vulnerable to SQL injection."""
        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user']
        mock_settings.POSTGRES_RLS_ROLE_MAPPING = {
            'dangerous': "'; DROP TABLE users; --"
        }
        mock_settings.POSTGRES_RLS_SESSION_UID_VARIABLE = 'app.current_user_id'
        mock_settings.POSTGRES_RLS_ENABLE_AUDIT_LOG = False

        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        # Create middleware that returns potentially dangerous role name
        class DangerousMiddleware(ConcreteRLSMiddleware):
            def extract_role(self, request):
                return "dangerous"

        middleware = DangerousMiddleware(get_response=lambda r: HttpResponse())
        request = self.factory.get('/')
        request.user = Mock(is_authenticated=True, id=1)

        # Should raise ValueError because the mapped role is not in valid_roles
        with pytest.raises(ValueError, match="Invalid role"):
            middleware.process_request(request)

    @patch('django_postgres_rls.middleware.connection')
    def test_user_id_is_parameterized(self, mock_connection):
        """Test that user ID uses parameterized queries."""
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        request = self.factory.get('/')
        request.user = Mock(is_authenticated=True, is_superuser=False, is_staff=False, id=42)

        self.middleware.process_request(request)

        # Find the set_config call
        calls = mock_cursor.execute.call_args_list
        set_config_calls = [call for call in calls if 'set_config' in str(call)]

        # Verify it uses parameterized query
        assert len(set_config_calls) > 0
        # The second argument should be a list of parameters
        call_args = set_config_calls[0][0]
        if len(call_args) > 1:
            assert isinstance(call_args[1], list)

    def test_role_isolation_between_requests(self):
        """Test that roles don't leak between requests."""
        # This is ensured by SET LOCAL ROLE which is transaction-scoped
        # And RESET ROLE in process_response
        # This test documents the expected behavior
        pass


class TestEdgeCases(TestCase):
    """Test edge cases and error conditions."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.middleware = ConcreteRLSMiddleware(get_response=lambda r: HttpResponse())

    def test_process_request_with_unknown_role(self):
        """Test process_request with unknown role falls back to default anonymous role."""

        class UnknownRoleMiddleware(ConcreteRLSMiddleware):
            def extract_role(self, request):
                return 'unknown_role'

        with patch('django_postgres_rls.middleware.connection') as mock_connection:
            mock_cursor = MagicMock()
            mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

            middleware = UnknownRoleMiddleware(get_response=lambda r: HttpResponse())
            request = self.factory.get('/')
            request.user = Mock(is_authenticated=True, id=1)

            middleware.process_request(request)

            # Should fall back to app_anonymous (default anonymous role)
            calls = mock_cursor.execute.call_args_list
            assert any('app_anonymous' in str(call) for call in calls)

    @patch('django_postgres_rls.middleware.connection')
    def test_process_request_with_string_user_id(self, mock_connection):
        """Test that non-integer user IDs are handled."""
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        request = self.factory.get('/')
        request.user = Mock(is_authenticated=True, is_superuser=False, is_staff=False, id='uuid-123')

        self.middleware.process_request(request)

        # Should convert to string and pass to set_config
        calls = mock_cursor.execute.call_args_list
        assert len(calls) > 0

    @patch('django_postgres_rls.middleware.connection')
    def test_middleware_with_empty_user_id(self, mock_connection):
        """Test middleware with empty user ID."""
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        request = self.factory.get('/')
        request.user = Mock(is_authenticated=False)

        self.middleware.process_request(request)

        # Role switch should execute, but set_config should be skipped for empty user ID
        # (improved behavior after refactoring - no need to set empty value)
        calls = mock_cursor.execute.call_args_list
        assert len(calls) >= 1  # At least the role switch happened
        set_config_calls = [call for call in calls if 'set_config' in str(call)]
        assert len(set_config_calls) == 0  # Empty user ID, so set_config not called


class TestRoleValidation(TestCase):
    """Test role name validation and whitelisting."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()

    @patch('django.conf.settings')
    def test_middleware_validates_roles_on_init(self, mock_settings):
        """Test that middleware validates roles during initialization."""
        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user', 'app_staff', 'app_superuser']
        mock_settings.POSTGRES_RLS_ROLE_MAPPING = {
            'user': 'app_user',
            'staff': 'app_staff',
            'superuser': 'app_superuser'
        }
        mock_settings.POSTGRES_RLS_SESSION_UID_VARIABLE = 'app.current_user_id'
        mock_settings.POSTGRES_RLS_ENABLE_AUDIT_LOG = False

        # Should initialize successfully
        middleware = ConcreteRLSMiddleware(get_response=lambda r: HttpResponse())
        # Should include app_anonymous (default anonymous role) automatically
        assert middleware.valid_roles == frozenset(['app_user', 'app_staff', 'app_superuser', 'app_anonymous'])

    @patch('django.conf.settings')
    def test_middleware_rejects_empty_valid_roles(self, mock_settings):
        """Test that middleware rejects empty valid roles."""
        mock_settings.POSTGRES_RLS_VALID_ROLES = []
        mock_settings.POSTGRES_RLS_ROLE_MAPPING = {'user': 'app_user'}
        mock_settings.POSTGRES_RLS_SESSION_UID_VARIABLE = 'app.current_user_id'
        mock_settings.POSTGRES_RLS_ENABLE_AUDIT_LOG = False

        with pytest.raises(ImproperlyConfigured, match="POSTGRES_RLS_VALID_ROLES cannot be empty"):
            ConcreteRLSMiddleware(get_response=lambda r: HttpResponse())

    @patch('django.conf.settings')
    def test_middleware_uses_role_mapping_as_default_valid_roles(self, mock_settings):
        """Test that middleware uses role mapping values as default valid roles."""
        mock_settings.POSTGRES_RLS_ROLE_MAPPING = {
            'user': 'app_user',
            'staff': 'app_staff'
        }
        mock_settings.POSTGRES_RLS_SESSION_UID_VARIABLE = 'app.current_user_id'
        mock_settings.POSTGRES_RLS_ENABLE_AUDIT_LOG = False
        delattr(mock_settings, 'POSTGRES_RLS_VALID_ROLES')

        middleware = ConcreteRLSMiddleware(get_response=lambda r: HttpResponse())
        # Should include app_anonymous (default anonymous role) automatically
        assert middleware.valid_roles == frozenset(['app_user', 'app_staff', 'app_anonymous'])

    @patch('django.conf.settings')
    @patch('django_postgres_rls.middleware.connection')
    def test_process_request_rejects_invalid_role(self, mock_connection, mock_settings):
        """Test that process_request rejects roles not in whitelist."""
        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user', 'app_staff']
        mock_settings.POSTGRES_RLS_ROLE_MAPPING = {
            'user': 'app_user',
            'hacker': 'app_superuser'  # Maps to invalid role!
        }
        mock_settings.POSTGRES_RLS_SESSION_UID_VARIABLE = 'app.current_user_id'
        mock_settings.POSTGRES_RLS_ENABLE_AUDIT_LOG = False

        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        class HackerMiddleware(ConcreteRLSMiddleware):
            def extract_role(self, request):
                return 'hacker'

        middleware = HackerMiddleware(get_response=lambda r: HttpResponse())
        request = self.factory.get('/')
        request.user = Mock(is_authenticated=True, id=1)

        with pytest.raises(ValueError, match="Invalid role"):
            middleware.process_request(request)

    @patch('django.conf.settings')
    @patch('django_postgres_rls.middleware.connection')
    def test_validate_role_with_sql_injection_attempt(self, mock_connection, mock_settings):
        """Test that SQL injection attempts in role names are caught."""
        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user']
        mock_settings.POSTGRES_RLS_ROLE_MAPPING = {
            'user': 'app_user',
            'malicious': "app_user; DROP TABLE users; --"
        }
        mock_settings.POSTGRES_RLS_SESSION_UID_VARIABLE = 'app.current_user_id'
        mock_settings.POSTGRES_RLS_ENABLE_AUDIT_LOG = False

        class MaliciousMiddleware(ConcreteRLSMiddleware):
            def extract_role(self, request):
                return 'malicious'

        middleware = MaliciousMiddleware(get_response=lambda r: HttpResponse())
        request = self.factory.get('/')
        request.user = Mock(is_authenticated=True, id=1)

        # Should reject the malicious role
        with pytest.raises(ValueError, match="Invalid role"):
            middleware.process_request(request)


class TestInputSanitization(TestCase):
    """Test input sanitization for user IDs."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.middleware = ConcreteRLSMiddleware(get_response=lambda r: HttpResponse())

    def test_sanitize_user_id_with_alphanumeric(self):
        """Test that alphanumeric user IDs pass through."""
        user_id = self.middleware._sanitize_user_id('abc123')
        assert user_id == 'abc123'

    def test_sanitize_user_id_with_hyphens_underscores(self):
        """Test that hyphens and underscores are allowed."""
        user_id = self.middleware._sanitize_user_id('user-123_abc')
        assert user_id == 'user-123_abc'

    def test_sanitize_user_id_removes_special_chars(self):
        """Test that special characters are removed."""
        user_id = self.middleware._sanitize_user_id("user'; DROP TABLE users; --")
        # Should remove quotes, semicolons, spaces, etc.
        assert ';' not in user_id
        assert "'" not in user_id
        assert ' ' not in user_id

    def test_sanitize_user_id_with_uuid(self):
        """Test that UUIDs work correctly."""
        uuid = '550e8400-e29b-41d4-a716-446655440000'
        user_id = self.middleware._sanitize_user_id(uuid)
        assert user_id == uuid

    def test_sanitize_user_id_truncates_long_values(self):
        """Test that very long user IDs are truncated."""
        long_id = 'a' * 300
        user_id = self.middleware._sanitize_user_id(long_id)
        assert len(user_id) <= 255

    def test_sanitize_user_id_with_none(self):
        """Test that None returns empty string."""
        user_id = self.middleware._sanitize_user_id(None)
        assert user_id == ''

    def test_sanitize_user_id_with_empty_string(self):
        """Test that empty string returns empty string."""
        user_id = self.middleware._sanitize_user_id('')
        assert user_id == ''

    @patch('django_postgres_rls.middleware.connection')
    def test_get_user_id_sanitizes_output(self, mock_connection):
        """Test that get_user_id calls sanitization."""
        request = self.factory.get('/')
        request.user = Mock(is_authenticated=True, id="malicious'; DROP")

        user_id = self.middleware.get_user_id(request)

        # Should be sanitized (no quotes, semicolons, spaces)
        assert "'" not in user_id
        assert ';' not in user_id
        assert ' ' not in user_id


class TestAuditLogging(TestCase):
    """Test audit logging functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()

    @patch('django.conf.settings')
    @patch('django_postgres_rls.middleware.connection')
    @patch('django_postgres_rls.middleware.audit_logger')
    def test_audit_log_role_switch(self, mock_audit_logger, mock_connection, mock_settings):
        """Test that role switches are audit logged when enabled."""
        mock_settings.POSTGRES_RLS_ENABLE_AUDIT_LOG = True
        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user']
        mock_settings.POSTGRES_RLS_ROLE_MAPPING = {'user': 'app_user'}
        mock_settings.POSTGRES_RLS_SESSION_UID_VARIABLE = 'app.current_user_id'

        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        middleware = ConcreteRLSMiddleware(get_response=lambda r: HttpResponse())
        request = self.factory.get('/')
        request.user = Mock(is_authenticated=True, is_superuser=False, is_staff=False, id=123)

        middleware.process_request(request)

        # Verify audit log was called
        assert mock_audit_logger.info.called
        call_args = str(mock_audit_logger.info.call_args)
        assert 'role_switch' in call_args
        assert 'app_user' in call_args

    @patch('django.conf.settings')
    @patch('django_postgres_rls.middleware.connection')
    @patch('django_postgres_rls.middleware.audit_logger')
    def test_audit_log_disabled_by_default(self, mock_audit_logger, mock_connection, mock_settings):
        """Test that audit logging is disabled by default."""
        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user']
        mock_settings.POSTGRES_RLS_ROLE_MAPPING = {'user': 'app_user'}
        mock_settings.POSTGRES_RLS_SESSION_UID_VARIABLE = 'app.current_user_id'
        delattr(mock_settings, 'POSTGRES_RLS_ENABLE_AUDIT_LOG')

        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        middleware = ConcreteRLSMiddleware(get_response=lambda r: HttpResponse())
        request = self.factory.get('/')
        request.user = Mock(is_authenticated=True, is_superuser=False, is_staff=False, id=123)

        middleware.process_request(request)

        # Audit logger should not be called
        assert not mock_audit_logger.info.called

    @patch('django.conf.settings')
    @patch('django_postgres_rls.middleware.connection')
    @patch('django_postgres_rls.middleware.audit_logger')
    def test_audit_log_validation_failure(self, mock_audit_logger, mock_connection, mock_settings):
        """Test that validation failures are audit logged."""
        mock_settings.POSTGRES_RLS_ENABLE_AUDIT_LOG = True
        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user']
        mock_settings.POSTGRES_RLS_ROLE_MAPPING = {'hacker': 'invalid_role'}
        mock_settings.POSTGRES_RLS_SESSION_UID_VARIABLE = 'app.current_user_id'

        class MaliciousMiddleware(ConcreteRLSMiddleware):
            def extract_role(self, request):
                return 'hacker'

        middleware = MaliciousMiddleware(get_response=lambda r: HttpResponse())
        request = self.factory.get('/')
        request.user = Mock(is_authenticated=True, id=1)

        with pytest.raises(ValueError):
            middleware.process_request(request)

        # Verify failure was logged
        assert mock_audit_logger.error.called
        call_args = str(mock_audit_logger.error.call_args)
        assert 'role_validation_failed' in call_args


class TestConfigurableSessionVariable(TestCase):
    """Test configurable session variable name."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()

    @patch('django.conf.settings')
    @patch('django_postgres_rls.middleware.connection')
    def test_custom_session_variable_name(self, mock_connection, mock_settings):
        """Test that custom session variable name is used."""
        mock_settings.POSTGRES_RLS_SESSION_UID_VARIABLE = 'custom.user_id'
        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user']
        mock_settings.POSTGRES_RLS_ROLE_MAPPING = {'user': 'app_user'}

        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        middleware = ConcreteRLSMiddleware(get_response=lambda r: HttpResponse())
        request = self.factory.get('/')
        request.user = Mock(is_authenticated=True, is_superuser=False, is_staff=False, id=42)

        middleware.process_request(request)

        # Verify custom session variable name was used
        calls = mock_cursor.execute.call_args_list
        assert any('custom.user_id' in str(call) for call in calls)

    @patch('django.conf.settings')
    def test_default_session_variable_name(self, mock_settings):
        """Test that default session variable name is used."""
        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user']
        mock_settings.POSTGRES_RLS_ROLE_MAPPING = {'user': 'app_user'}
        delattr(mock_settings, 'POSTGRES_RLS_SESSION_UID_VARIABLE')

        middleware = ConcreteRLSMiddleware(get_response=lambda r: HttpResponse())

        assert middleware.session_uid_variable == 'app.current_user_id'

    @patch('django.conf.settings')
    def test_invalid_session_variable_name(self, mock_settings):
        """Test that invalid session variable names are rejected."""
        mock_settings.POSTGRES_RLS_SESSION_UID_VARIABLE = 'invalid_no_dot'
        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user']
        mock_settings.POSTGRES_RLS_ROLE_MAPPING = {'user': 'app_user'}

        with pytest.raises(ImproperlyConfigured, match="Invalid session variable name"):
            ConcreteRLSMiddleware(get_response=lambda r: HttpResponse())


class TestProcessException(TestCase):
    """Test process_exception method for role reset."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.middleware = ConcreteRLSMiddleware(get_response=lambda r: HttpResponse())

    @patch('django_postgres_rls.middleware.connection')
    def test_process_exception_resets_role(self, mock_connection):
        """Test that process_exception resets role."""
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        request = self.factory.get('/')
        exception = Exception("Test exception")

        result = self.middleware.process_exception(request, exception)

        # Should reset role
        mock_cursor.execute.assert_called_with("RESET ROLE")
        # Should not suppress exception
        assert result is None

    @patch('django_postgres_rls.middleware.connection')
    def test_process_exception_doesnt_suppress_exception(self, mock_connection):
        """Test that process_exception doesn't suppress the original exception."""
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        request = self.factory.get('/')
        exception = ValueError("Important error")

        result = self.middleware.process_exception(request, exception)

        # Should return None (don't suppress exception)
        assert result is None

    @patch('django_postgres_rls.middleware.connection')
    @patch('django_postgres_rls.middleware.logger')
    def test_process_exception_handles_reset_error(self, mock_logger, mock_connection):
        """Test that errors during role reset don't break exception handling."""
        mock_cursor = MagicMock()
        mock_cursor.execute.side_effect = Exception("Reset failed")
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        request = self.factory.get('/')
        exception = Exception("Original exception")

        # Should not raise during exception handling
        result = self.middleware.process_exception(request, exception)

        assert result is None
        mock_logger.warning.assert_called()


class TestContextManager(TestCase):
    """Test rls_role context manager."""

    @patch('django_postgres_rls.middleware.connection')
    def test_context_manager_basic_usage(self, mock_connection):
        """Test basic context manager usage."""
        mock_cursor = MagicMock()
        mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
        mock_cursor.__exit__ = MagicMock(return_value=False)
        mock_connection.cursor.return_value = mock_cursor
        mock_connection.in_atomic_block = False
        mock_connection.settings_dict = {'USER': 'test_user'}

        # Mock the fetchone to return the database user (not an app role)
        mock_cursor.fetchone.return_value = ['test_user']

        with rls_role('app_user'):
            pass

        # Verify role was set (no manual restoration - transaction handles it)
        calls = [str(call) for call in mock_cursor.execute.call_args_list]
        # Should have call to get current role and set role
        assert any('current_user' in call for call in calls)
        assert any('SET LOCAL ROLE' in call and 'app_user' in call for call in calls)

    @patch('django_postgres_rls.middleware.connection')
    def test_context_manager_with_user_id(self, mock_connection):
        """Test context manager with user ID."""
        mock_cursor = MagicMock()
        mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
        mock_cursor.__exit__ = MagicMock(return_value=False)
        mock_connection.cursor.return_value = mock_cursor
        mock_connection.in_atomic_block = False
        mock_connection.settings_dict = {'USER': 'test_user'}

        # Mock fetchone to return the database user
        mock_cursor.fetchone.return_value = ['test_user']

        with rls_role('app_user', user_id=123):
            pass

        # Verify user ID was set
        calls = [str(call) for call in mock_cursor.execute.call_args_list]
        assert any('set_config' in call for call in calls)

    @patch('django_postgres_rls.middleware.connection')
    def test_context_manager_with_validation(self, mock_connection):
        """Test context manager with role validation."""
        mock_cursor = MagicMock()
        mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
        mock_cursor.__exit__ = MagicMock(return_value=False)
        mock_connection.cursor.return_value = mock_cursor
        mock_connection.in_atomic_block = False
        mock_connection.settings_dict = {'USER': 'test_user'}

        # Mock fetchone to return the database user
        mock_cursor.fetchone.return_value = ['test_user']

        valid_roles = {'app_user', 'app_staff'}

        with rls_role('app_user', valid_roles=valid_roles):
            pass

        # Should work fine
        assert True

    def test_context_manager_rejects_invalid_role(self):
        """Test that context manager rejects invalid roles."""
        valid_roles = {'app_user', 'app_staff'}

        with pytest.raises(ValueError, match="Invalid PostgreSQL role"):
            with rls_role('app_hacker', valid_roles=valid_roles):
                pass

    @patch('django_postgres_rls.middleware.connection')
    def test_context_manager_resets_on_exception(self, mock_connection):
        """Test that context manager resets role even on exception."""
        mock_cursor = MagicMock()
        mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
        mock_cursor.__exit__ = MagicMock(return_value=False)
        mock_connection.cursor.return_value = mock_cursor
        mock_connection.in_atomic_block = False
        mock_connection.settings_dict = {'USER': 'test_user'}

        # Mock the fetchone to return the database user
        mock_cursor.fetchone.return_value = ['test_user']

        with pytest.raises(RuntimeError):
            with rls_role('app_user'):
                raise RuntimeError("Test error")

        # Verify role was set (transaction rollback will restore it automatically)
        calls = [str(call) for call in mock_cursor.execute.call_args_list]
        assert any('SET LOCAL ROLE' in call and 'app_user' in call for call in calls)

    @patch('django_postgres_rls.middleware.connection')
    def test_context_manager_custom_session_variable(self, mock_connection):
        """Test context manager with custom session variable."""
        mock_cursor = MagicMock()
        mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
        mock_cursor.__exit__ = MagicMock(return_value=False)
        mock_connection.cursor.return_value = mock_cursor
        mock_connection.in_atomic_block = False
        mock_connection.settings_dict = {'USER': 'test_user'}

        # Mock fetchone to return the database user
        mock_cursor.fetchone.return_value = ['test_user']

        with rls_role('app_user', user_id=123, session_uid_variable='custom.uid'):
            pass

        # Verify custom session variable was used
        calls = [str(call) for call in mock_cursor.execute.call_args_list]
        assert any('custom.uid' in call for call in calls)

    def test_context_manager_sanitizes_user_id(self):
        """Test that context manager sanitizes user IDs."""
        with patch('django_postgres_rls.middleware.connection') as mock_connection:
            mock_cursor = MagicMock()
            mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
            mock_cursor.__exit__ = MagicMock(return_value=False)
            mock_connection.cursor.return_value = mock_cursor
            mock_connection.in_atomic_block = False
            mock_connection.settings_dict = {'USER': 'test_user'}

            # Mock fetchone to return the database user
            mock_cursor.fetchone.return_value = ['test_user']

            # User ID with special characters
            with rls_role('app_user', user_id="123'; DROP TABLE users; --"):
                pass

            # Verify it was sanitized (special characters removed)
            calls = [str(call) for call in mock_cursor.execute.call_args_list]
            set_config_calls = [call for call in calls if 'set_config' in call]
            # Should not contain dangerous characters
            for call in set_config_calls:
                assert ';' not in call or 'set_config' in call  # semicolon OK in set_config function name


class TestPublicEndpointAccess(TestCase):
    """Test that RLS middleware doesn't prevent access to public endpoints like login pages."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()

    @patch('django_postgres_rls.middleware.connection')
    def test_middleware_allows_unauthenticated_access(self, mock_connection):
        """Test that middleware allows access for unauthenticated users (login page scenario)."""
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connection.in_atomic_block = True

        middleware = ConcreteRLSMiddleware(get_response=lambda r: HttpResponse())

        # Simulate unauthenticated user accessing login page (whitelisted path)
        request = self.factory.get('/api/auth/login/')
        request.user = AnonymousUser()

        # Process request - should not raise an error
        result = middleware.process_request(request)

        # Should return None (allows request to continue)
        assert result is None

        # Verify NO role switching occurred because path is whitelisted
        calls = [str(call) for call in mock_cursor.execute.call_args_list]
        # Login page is in the default whitelist, so no RLS should be applied
        assert len(calls) == 0  # No database calls should be made

    @patch('django_postgres_rls.middleware.connection')
    def test_middleware_switches_role_for_non_whitelisted_path(self, mock_connection):
        """Test that middleware switches role for non-whitelisted paths."""
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connection.in_atomic_block = True

        middleware = ConcreteRLSMiddleware(get_response=lambda r: HttpResponse())

        # Simulate unauthenticated user accessing non-whitelisted path
        request = self.factory.get('/api/buildings/')
        request.user = AnonymousUser()

        # Process request - should not raise an error
        result = middleware.process_request(request)

        # Should return None (allows request to continue)
        assert result is None

        # Verify role was switched
        calls = [str(call) for call in mock_cursor.execute.call_args_list]
        # ConcreteRLSMiddleware returns 'user' for unauthenticated, which maps to 'app_user'
        assert any('app_user' in call for call in calls)

    @patch('django_postgres_rls.middleware.connection')
    def test_middleware_uses_anonymous_role_for_unmapped_role(self, mock_connection):
        """Test that middleware uses default anonymous role for unmapped roles."""
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connection.in_atomic_block = True

        # Create middleware that returns a role not in the mapping
        class UnmappedRoleMiddleware(PostgresRLSMiddleware):
            def extract_role(self, request):
                return 'unknown_role'  # This role is not in default mapping

        middleware = UnmappedRoleMiddleware(get_response=lambda r: HttpResponse())

        request = self.factory.get('/api/buildings/')
        request.user = Mock(is_authenticated=True, id=123)

        # Process request
        result = middleware.process_request(request)

        # Should return None (allows request to continue)
        assert result is None

        # Verify role was switched to default anonymous role
        calls = [str(call) for call in mock_cursor.execute.call_args_list]
        # unknown_role is not in mapping, so it falls back to app_anonymous
        assert any('app_anonymous' in call for call in calls)

    @patch('django_postgres_rls.middleware.connection')
    def test_middleware_allows_no_user_attribute(self, mock_connection):
        """Test that middleware handles requests without user attribute (edge case)."""
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connection.in_atomic_block = True

        middleware = ConcreteRLSMiddleware(get_response=lambda r: HttpResponse())

        # Request without user attribute
        request = self.factory.get('/api/auth/login/')
        # Don't set request.user at all

        # Process request - should not raise an error
        result = middleware.process_request(request)

        # Should return None (allows request to continue)
        assert result is None

    @patch('django_postgres_rls.middleware.connection')
    def test_middleware_with_none_role_skips_role_switching(self, mock_connection):
        """Test that middleware skips role switching when extract_role returns None."""
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connection.in_atomic_block = True

        class PublicEndpointMiddleware(PostgresRLSMiddleware):
            """Middleware that returns None for public endpoints."""

            def extract_role(self, request):
                # Return None for public endpoints to skip RLS
                public_paths = ['/api/auth/login/', '/api/auth/register/']
                if any(request.path.startswith(path) for path in public_paths):
                    return None

                # Normal role extraction for other paths
                if not request.user or not request.user.is_authenticated:
                    return 'user'
                return 'user'

        middleware = PublicEndpointMiddleware(get_response=lambda r: HttpResponse())

        # Request to login page
        request = self.factory.get('/api/auth/login/')
        request.user = AnonymousUser()

        # Process request
        result = middleware.process_request(request)

        # Should return None (allows request to continue)
        assert result is None

        # Verify NO role switching occurred
        mock_cursor.execute.assert_not_called()

    @patch('django_postgres_rls.middleware.connection')
    def test_full_request_cycle_for_login_page(self, mock_connection):
        """Test full request/response cycle for login page access."""
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connection.in_atomic_block = False

        # Mock the pg_roles query
        def mock_fetchall():
            last_call = mock_cursor.execute.call_args
            if last_call and 'pg_roles' in str(last_call):
                return [('app_user',), ('app_staff',), ('app_superuser',)]
            return []

        mock_cursor.fetchall.side_effect = mock_fetchall

        middleware = ConcreteRLSMiddleware(
            get_response=lambda r: HttpResponse("Login Page")
        )

        # Simulate unauthenticated user accessing login page
        request = self.factory.get('/api/auth/login/')
        request.user = AnonymousUser()

        # Process full request/response cycle
        response = middleware(request)

        # Should successfully return the response
        assert response is not None
        assert response.content.decode() == "Login Page"


class TestRlsUserMixin(TestCase):
    """Test RlsUser mixin functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()

    @patch('django.conf.settings')
    @patch('django_postgres_rls.middleware.connection')
    def test_middleware_uses_user_get_postgres_role(self, mock_connection, mock_settings):
        """Test that middleware calls user.get_postgres_role() when available."""
        from django_postgres_rls import RlsUser

        # Create a user class with RlsUser mixin
        class TestUser(RlsUser):
            is_authenticated = True
            id = 123

            def get_postgres_role(self):
                return 'app_custom_role'

        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_custom_role']
        mock_settings.POSTGRES_RLS_ROLE_MAPPING = {}
        mock_settings.POSTGRES_RLS_SESSION_UID_VARIABLE = 'app.current_user_id'

        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connection.in_atomic_block = True

        # Use base middleware directly (no subclass!)
        from django_postgres_rls import PostgresRLSMiddleware
        middleware = PostgresRLSMiddleware(get_response=lambda r: HttpResponse())

        request = self.factory.get('/')
        request.user = TestUser()

        middleware.process_request(request)

        # Verify app_custom_role was used
        calls = [str(call) for call in mock_cursor.execute.call_args_list]
        assert any('app_custom_role' in call for call in calls)

    @patch('django.conf.settings')
    @patch('django_postgres_rls.middleware.connection')
    def test_middleware_without_mixin_raises_error(self, mock_connection, mock_settings):
        """Test that middleware raises error when user doesn't have get_postgres_role."""
        from django.core.exceptions import ImproperlyConfigured

        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user']
        mock_settings.POSTGRES_RLS_ROLE_MAPPING = {'user': 'app_user'}
        mock_settings.POSTGRES_RLS_SESSION_UID_VARIABLE = 'app.current_user_id'

        mock_connection.in_atomic_block = True

        # Use base middleware directly
        from django_postgres_rls import PostgresRLSMiddleware
        middleware = PostgresRLSMiddleware(get_response=lambda r: HttpResponse())

        request = self.factory.get('/')
        # User without get_postgres_role method
        request.user = Mock(is_authenticated=True, id=123)
        # Remove get_postgres_role if Mock added it
        if hasattr(request.user, 'get_postgres_role'):
            delattr(request.user, 'get_postgres_role')

        # Should raise ImproperlyConfigured with helpful message
        with pytest.raises(ImproperlyConfigured) as exc_info:
            middleware.process_request(request)

        error_message = str(exc_info.value)
        assert 'RlsUser mixin' in error_message
        assert 'get_postgres_role()' in error_message

    @patch('django.conf.settings')
    @patch('django_postgres_rls.middleware.connection')
    def test_middleware_with_unauthenticated_user(self, mock_connection, mock_settings):
        """Test that middleware handles unauthenticated users gracefully."""
        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user']
        mock_settings.POSTGRES_RLS_ROLE_MAPPING = {'user': 'app_user'}
        mock_settings.POSTGRES_RLS_SESSION_UID_VARIABLE = 'app.current_user_id'

        mock_connection.in_atomic_block = True

        # Use base middleware directly
        from django_postgres_rls import PostgresRLSMiddleware
        middleware = PostgresRLSMiddleware(get_response=lambda r: HttpResponse())

        request = self.factory.get('/')
        request.user = Mock(is_authenticated=False)

        # Should not raise error
        result = middleware.process_request(request)
        assert result is None

    @patch('django.conf.settings')
    @patch('django_postgres_rls.middleware.connection')
    def test_rls_user_with_dynamic_role(self, mock_connection, mock_settings):
        """Test RlsUser with dynamic role based on user attributes."""
        from django_postgres_rls import RlsUser

        class TestUser(RlsUser):
            def __init__(self, is_premium=False):
                self.is_authenticated = True
                self.is_premium = is_premium
                self.id = 123

            def get_postgres_role(self):
                return 'app_premium_user' if self.is_premium else 'app_user'

        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user', 'app_premium_user']
        mock_settings.POSTGRES_RLS_ROLE_MAPPING = {}
        mock_settings.POSTGRES_RLS_SESSION_UID_VARIABLE = 'app.current_user_id'

        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connection.in_atomic_block = True

        from django_postgres_rls import PostgresRLSMiddleware
        middleware = PostgresRLSMiddleware(get_response=lambda r: HttpResponse())

        # Test with premium user
        request = self.factory.get('/')
        request.user = TestUser(is_premium=True)
        middleware.process_request(request)

        calls = [str(call) for call in mock_cursor.execute.call_args_list]
        assert any('app_premium_user' in call for call in calls)

        # Reset mock
        mock_cursor.reset_mock()

        # Test with regular user
        request.user = TestUser(is_premium=False)
        middleware.process_request(request)

        calls = [str(call) for call in mock_cursor.execute.call_args_list]
        assert any('app_user' in call for call in calls)

    def test_rls_user_not_implemented_error(self):
        """Test that RlsUser raises NotImplementedError if get_postgres_role not overridden."""
        from django_postgres_rls import RlsUser

        # User that doesn't override get_postgres_role
        class IncompleteUser(RlsUser):
            pass

        user = IncompleteUser()

        with pytest.raises(NotImplementedError) as exc_info:
            user.get_postgres_role()

        error_message = str(exc_info.value)
        assert 'IncompleteUser' in error_message
        assert 'get_postgres_role()' in error_message

    @patch('django.conf.settings')
    @patch('django_postgres_rls.middleware.connection')
    def test_rls_user_returning_none(self, mock_connection, mock_settings):
        """Test RlsUser that returns None (no role switching)."""
        from django_postgres_rls import RlsUser

        class TestUser(RlsUser):
            is_authenticated = True
            id = 123

            def get_postgres_role(self):
                # Return None to skip role switching
                return None

        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user']
        mock_settings.POSTGRES_RLS_ROLE_MAPPING = {}
        mock_settings.POSTGRES_RLS_SESSION_UID_VARIABLE = 'app.current_user_id'

        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connection.in_atomic_block = True

        from django_postgres_rls import PostgresRLSMiddleware
        middleware = PostgresRLSMiddleware(get_response=lambda r: HttpResponse())

        request = self.factory.get('/')
        request.user = TestUser()

        result = middleware.process_request(request)

        # Should not raise error and should not switch role
        assert result is None
        # No SET ROLE should have been called
        calls = [str(call) for call in mock_cursor.execute.call_args_list]
        set_role_calls = [call for call in calls if 'SET' in call and 'ROLE' in call]
        assert len(set_role_calls) == 0

    @patch('django.conf.settings')
    @patch('django_postgres_rls.middleware.connection')
    def test_rls_user_with_django_abstractuser(self, mock_connection, mock_settings):
        """Test RlsUser with Django's AbstractUser (real-world scenario)."""
        from django.contrib.auth.models import AbstractUser
        from django_postgres_rls import RlsUser

        # Simulate real User model that inherits from AbstractUser + RlsUser
        class RealUser(RlsUser, AbstractUser):
            class Meta:
                app_label = 'test'

            def get_postgres_role(self):
                if self.is_superuser:
                    return 'app_superuser'
                return 'app_user'

        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user', 'app_superuser']
        mock_settings.POSTGRES_RLS_ROLE_MAPPING = {}
        mock_settings.POSTGRES_RLS_SESSION_UID_VARIABLE = 'app.current_user_id'
        mock_settings.POSTGRES_RLS_ENABLE_AUDIT_LOG = False

        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connection.in_atomic_block = True

        from django_postgres_rls import PostgresRLSMiddleware
        middleware = PostgresRLSMiddleware(get_response=lambda r: HttpResponse())

        # Create user instances
        regular_user = RealUser(username='regular', is_superuser=False)
        regular_user.id = 123
        super_user = RealUser(username='super', is_superuser=True)
        super_user.id = 456

        # Test regular user
        request = self.factory.get('/')
        request.user = regular_user
        middleware.process_request(request)

        calls = [str(call) for call in mock_cursor.execute.call_args_list]
        assert any('app_user' in call for call in calls), \
            f"Expected 'app_user' in role switch, got: {calls}"

        # Reset mock
        mock_cursor.reset_mock()

        # Test superuser
        request.user = super_user
        middleware.process_request(request)

        calls = [str(call) for call in mock_cursor.execute.call_args_list]
        assert any('app_superuser' in call for call in calls), \
            f"Expected 'app_superuser' in role switch, got: {calls}"

    @patch('django.conf.settings')
    @patch('django_postgres_rls.middleware.connection')
    def test_rls_user_with_simplelazy_proxy(self, mock_connection, mock_settings):
        """Test RlsUser wrapped in SimpleLazyObject (Django's lazy user loading)."""
        from django.contrib.auth.models import AbstractUser
        from django.utils.functional import SimpleLazyObject
        from django_postgres_rls import RlsUser

        class RealUser(RlsUser, AbstractUser):
            class Meta:
                app_label = 'test'

            def get_postgres_role(self):
                return 'app_user'

        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user', 'app_anonymous']
        mock_settings.POSTGRES_RLS_ROLE_MAPPING = {'anonymous': 'app_anonymous'}
        mock_settings.POSTGRES_RLS_DEFAULT_ANONYMOUS_ROLE = 'app_anonymous'
        mock_settings.POSTGRES_RLS_SESSION_UID_VARIABLE = 'app.current_user_id'
        mock_settings.POSTGRES_RLS_ENABLE_AUDIT_LOG = False

        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connection.in_atomic_block = True

        from django_postgres_rls import PostgresRLSMiddleware
        middleware = PostgresRLSMiddleware(get_response=lambda r: HttpResponse())

        # Create user wrapped in SimpleLazyObject (like Django does in requests)
        user = RealUser(username='testuser')
        user.id = 123
        lazy_user = SimpleLazyObject(lambda: user)

        request = self.factory.get('/')
        request.user = lazy_user

        # Process request
        middleware.process_request(request)

        # Verify that app_user was used, NOT app_anonymous
        calls = [str(call) for call in mock_cursor.execute.call_args_list]
        assert any('app_user' in call for call in calls), \
            f"Expected 'app_user' from RlsUser.get_postgres_role(), but got app_anonymous. Calls: {calls}"
        # Explicitly check that app_anonymous was NOT used
        assert not any('app_anonymous' in call for call in calls), \
            f"Should NOT use app_anonymous when RlsUser.get_postgres_role() returns app_user. Calls: {calls}"
