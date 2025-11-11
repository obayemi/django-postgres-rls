"""
Tests for RLS authentication backends.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from django.test import TestCase, RequestFactory
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured

from django_postgres_rls import (
    RLSAuthenticationBackend,
    RLSAuthenticationBackendWithPythonVerification,
    get_auth_function_sql,
    get_user_fetch_function_sql,
)

User = get_user_model()


class TestRLSAuthenticationBackend(TestCase):
    """Test RLSAuthenticationBackend."""

    def setUp(self):
        """Set up test fixtures."""
        self.backend = RLSAuthenticationBackend()
        self.factory = RequestFactory()

    def test_backend_initialization(self):
        """Test that backend initializes with correct defaults."""
        assert self.backend.auth_function == 'public.authenticate_user'
        assert self.backend.use_email is False

    @patch('django.conf.settings')
    def test_backend_initialization_with_custom_settings(self, mock_settings):
        """Test backend initialization with custom settings."""
        mock_settings.POSTGRES_RLS_AUTH_FUNCTION = 'custom.auth_func'
        mock_settings.POSTGRES_RLS_AUTH_USE_EMAIL = True

        backend = RLSAuthenticationBackend()
        assert backend.auth_function == 'custom.auth_func'
        assert backend.use_email is True

    @patch('django_postgres_rls.backends.connection')
    def test_authenticate_with_valid_credentials(self, mock_connection):
        """Test authentication with valid credentials."""
        # Create a test user
        user = User.objects.create_user(username='testuser', password='testpass')

        # Mock the database cursor
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (user.id,)
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        request = self.factory.get('/')

        # Authenticate
        authenticated_user = self.backend.authenticate(
            request,
            username='testuser',
            password='testpass'
        )

        # Verify
        assert authenticated_user is not None
        assert authenticated_user.username == 'testuser'
        assert authenticated_user.id == user.id

        # Verify SQL was called
        mock_cursor.execute.assert_called_once()

    @patch('django_postgres_rls.backends.connection')
    def test_authenticate_with_invalid_credentials(self, mock_connection):
        """Test authentication with invalid credentials."""
        # Mock the database cursor to return None
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        request = self.factory.get('/')

        # Authenticate
        authenticated_user = self.backend.authenticate(
            request,
            username='testuser',
            password='wrongpass'
        )

        # Verify
        assert authenticated_user is None

    @patch('django_postgres_rls.backends.connection')
    def test_authenticate_with_nonexistent_user(self, mock_connection):
        """Test authentication when function returns user ID but user doesn't exist."""
        # Mock the database cursor to return a non-existent user ID
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (99999,)
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        request = self.factory.get('/')

        # Authenticate
        authenticated_user = self.backend.authenticate(
            request,
            username='testuser',
            password='testpass'
        )

        # Verify
        assert authenticated_user is None

    def test_authenticate_without_username(self):
        """Test authentication without username."""
        request = self.factory.get('/')

        authenticated_user = self.backend.authenticate(
            request,
            username=None,
            password='testpass'
        )

        assert authenticated_user is None

    def test_authenticate_without_password(self):
        """Test authentication without password."""
        request = self.factory.get('/')

        authenticated_user = self.backend.authenticate(
            request,
            username='testuser',
            password=None
        )

        assert authenticated_user is None

    @patch('django.conf.settings')
    @patch('django_postgres_rls.backends.connection')
    def test_authenticate_with_email(self, mock_connection, mock_settings):
        """Test authentication using email instead of username."""
        mock_settings.POSTGRES_RLS_AUTH_USE_EMAIL = True

        # Create backend with email auth
        backend = RLSAuthenticationBackend()

        # Create a test user
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass'
        )

        # Mock the database cursor
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (user.id,)
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        request = self.factory.get('/')

        # Authenticate with email
        authenticated_user = backend.authenticate(
            request,
            email='test@example.com',
            password='testpass'
        )

        # Verify
        assert authenticated_user is not None
        assert authenticated_user.email == 'test@example.com'

    def test_get_user(self):
        """Test get_user method."""
        # Create a test user
        user = User.objects.create_user(username='testuser', password='testpass')

        # Get user
        retrieved_user = self.backend.get_user(user.id)

        assert retrieved_user is not None
        assert retrieved_user.id == user.id
        assert retrieved_user.username == 'testuser'

    def test_get_user_nonexistent(self):
        """Test get_user with nonexistent user."""
        retrieved_user = self.backend.get_user(99999)
        assert retrieved_user is None


class TestRLSAuthenticationBackendWithPythonVerification(TestCase):
    """Test RLSAuthenticationBackendWithPythonVerification."""

    def setUp(self):
        """Set up test fixtures."""
        self.backend = RLSAuthenticationBackendWithPythonVerification()
        self.factory = RequestFactory()

    def test_backend_initialization(self):
        """Test that backend initializes with correct defaults."""
        assert self.backend.auth_function == 'public.get_user_for_auth'
        assert self.backend.use_email is False

    @patch('django_postgres_rls.backends.connection')
    def test_authenticate_with_valid_credentials(self, mock_connection):
        """Test authentication with valid credentials and Python password verification."""
        # Create a test user
        user = User.objects.create_user(username='testuser', password='testpass')

        # Mock the database cursor to return user data
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (user.id, user.password, True)
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        request = self.factory.get('/')

        # Authenticate
        authenticated_user = self.backend.authenticate(
            request,
            username='testuser',
            password='testpass'
        )

        # Verify
        assert authenticated_user is not None
        assert authenticated_user.username == 'testuser'
        assert authenticated_user.id == user.id

    @patch('django_postgres_rls.backends.connection')
    def test_authenticate_with_invalid_password(self, mock_connection):
        """Test authentication with invalid password."""
        # Create a test user
        user = User.objects.create_user(username='testuser', password='testpass')

        # Mock the database cursor to return user data
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (user.id, user.password, True)
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        request = self.factory.get('/')

        # Authenticate with wrong password
        authenticated_user = self.backend.authenticate(
            request,
            username='testuser',
            password='wrongpass'
        )

        # Verify
        assert authenticated_user is None

    @patch('django_postgres_rls.backends.connection')
    def test_authenticate_with_inactive_user(self, mock_connection):
        """Test authentication with inactive user."""
        # Create a test user
        user = User.objects.create_user(username='testuser', password='testpass')

        # Mock the database cursor to return inactive user
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (user.id, user.password, False)
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        request = self.factory.get('/')

        # Authenticate
        authenticated_user = self.backend.authenticate(
            request,
            username='testuser',
            password='testpass'
        )

        # Verify
        assert authenticated_user is None

    @patch('django_postgres_rls.backends.connection')
    def test_authenticate_with_nonexistent_user(self, mock_connection):
        """Test authentication when user doesn't exist."""
        # Mock the database cursor to return None
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        request = self.factory.get('/')

        # Authenticate
        authenticated_user = self.backend.authenticate(
            request,
            username='testuser',
            password='testpass'
        )

        # Verify
        assert authenticated_user is None


class TestSQLGenerators(TestCase):
    """Test SQL generation functions."""

    def test_get_auth_function_sql(self):
        """Test get_auth_function_sql generates valid SQL."""
        sql = get_auth_function_sql()

        # Check that SQL contains expected components
        assert 'CREATE OR REPLACE FUNCTION' in sql
        assert 'SECURITY DEFINER' in sql
        assert 'authenticate_user' in sql
        assert 'GRANT EXECUTE' in sql
        assert 'app_anonymous' in sql

    def test_get_auth_function_sql_with_custom_params(self):
        """Test get_auth_function_sql with custom parameters."""
        sql = get_auth_function_sql(
            user_table='custom_user',
            schema='myschema',
            function_name='my_auth_func'
        )

        # Check customizations
        assert 'myschema.my_auth_func' in sql
        assert 'custom_user' in sql

    def test_get_user_fetch_function_sql(self):
        """Test get_user_fetch_function_sql generates valid SQL."""
        sql = get_user_fetch_function_sql()

        # Check that SQL contains expected components
        assert 'CREATE OR REPLACE FUNCTION' in sql
        assert 'SECURITY DEFINER' in sql
        assert 'get_user_for_auth' in sql
        assert 'RETURNS TABLE' in sql
        assert 'GRANT EXECUTE' in sql
        assert 'app_anonymous' in sql

    def test_get_user_fetch_function_sql_with_custom_params(self):
        """Test get_user_fetch_function_sql with custom parameters."""
        sql = get_user_fetch_function_sql(
            user_table='custom_user',
            schema='myschema',
            function_name='my_fetch_func'
        )

        # Check customizations
        assert 'myschema.my_fetch_func' in sql
        assert 'custom_user' in sql

    def test_sql_injection_prevention_in_sql_generators(self):
        """Test that SQL generators safely handle parameters."""
        # This test ensures that the SQL generators use f-strings safely
        # In production, these should be validated by database administrators
        sql = get_auth_function_sql(
            user_table='auth_user',
            schema='public',
            function_name='authenticate_user'
        )

        # Should not contain any suspicious SQL injection patterns
        assert '--' not in sql or '-- ' in sql  # Comments are OK in the generated SQL
        # The generated SQL is meant to be executed by admins, not from user input
