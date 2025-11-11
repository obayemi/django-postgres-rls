"""
Tests for django_postgres_rls.checks module.

Tests cover:
- Database backend checks
- ATOMIC_REQUESTS validation
- Middleware ordering checks
- Valid roles configuration
- Session variable configuration
- Role mapping validation
- Compatibility checks
"""

import pytest
from django.core.checks import Error, Warning, Info
from django.test import TestCase, override_settings

from django_postgres_rls.checks import (
    check_postgres_rls_security,
    check_postgres_rls_compatibility,
    _is_middleware_installed,
    _check_postgresql_backend,
    _check_atomic_requests,
    _check_middleware_ordering,
    _check_valid_roles,
    _check_session_variable,
    _check_role_mapping,
    _check_connection_pooling,
    _check_multiple_databases,
)


class TestMiddlewareDetection(TestCase):
    """Test middleware detection logic."""

    @override_settings(MIDDLEWARE=[])
    def test_middleware_not_installed(self):
        """Test detection when middleware is not installed."""
        assert not _is_middleware_installed()

    @override_settings(MIDDLEWARE=['django_postgres_rls.middleware.PostgresRLSMiddleware'])
    def test_middleware_installed(self):
        """Test detection when middleware is installed."""
        assert _is_middleware_installed()

    @override_settings(MIDDLEWARE=['myapp.middleware.CustomPostgresRLSMiddleware'])
    def test_custom_middleware_installed(self):
        """Test detection of custom middleware subclass."""
        assert _is_middleware_installed()


class TestPostgreSQLBackendCheck(TestCase):
    """Test PostgreSQL backend validation."""

    @override_settings(DATABASES={})
    def test_no_default_database(self):
        """Test error when no default database is configured."""
        errors = _check_postgresql_backend()
        assert len(errors) == 1
        assert errors[0].id == 'postgres_rls.E001'
        assert isinstance(errors[0], Error)
        assert 'No default database' in errors[0].msg

    @override_settings(DATABASES={'default': {'ENGINE': 'django.db.backends.sqlite3'}})
    def test_non_postgresql_backend(self):
        """Test error when database is not PostgreSQL."""
        errors = _check_postgresql_backend()
        assert len(errors) == 1
        assert errors[0].id == 'postgres_rls.E002'
        assert isinstance(errors[0], Error)
        assert 'PostgreSQL database backend' in errors[0].msg

    @override_settings(DATABASES={'default': {'ENGINE': 'django.db.backends.postgresql'}})
    def test_postgresql_backend(self):
        """Test no errors with PostgreSQL backend."""
        errors = _check_postgresql_backend()
        assert len(errors) == 0

    @override_settings(DATABASES={'default': {'ENGINE': 'django.db.backends.postgresql_psycopg2'}})
    def test_postgresql_psycopg2_backend(self):
        """Test no errors with legacy psycopg2 backend name."""
        errors = _check_postgresql_backend()
        assert len(errors) == 0


class TestAtomicRequestsCheck(TestCase):
    """Test ATOMIC_REQUESTS validation."""

    @override_settings(DATABASES={'default': {'ENGINE': 'django.db.backends.postgresql'}})
    def test_atomic_requests_not_set(self):
        """Test error when ATOMIC_REQUESTS is not set."""
        errors = _check_atomic_requests()
        assert len(errors) == 1
        assert errors[0].id == 'postgres_rls.E003'
        assert isinstance(errors[0], Error)
        assert 'ATOMIC_REQUESTS=True' in errors[0].msg

    @override_settings(DATABASES={'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'ATOMIC_REQUESTS': False
    }})
    def test_atomic_requests_false(self):
        """Test error when ATOMIC_REQUESTS is explicitly False."""
        errors = _check_atomic_requests()
        assert len(errors) == 1
        assert errors[0].id == 'postgres_rls.E003'

    @override_settings(DATABASES={'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'ATOMIC_REQUESTS': True
    }})
    def test_atomic_requests_true(self):
        """Test no errors when ATOMIC_REQUESTS is True."""
        errors = _check_atomic_requests()
        assert len(errors) == 0


class TestMiddlewareOrderingCheck(TestCase):
    """Test middleware ordering validation."""

    @override_settings(MIDDLEWARE=[
        'django.contrib.auth.middleware.AuthenticationMiddleware',
        'django_postgres_rls.middleware.PostgresRLSMiddleware',
    ])
    def test_correct_ordering(self):
        """Test no errors with correct middleware ordering."""
        errors = _check_middleware_ordering()
        assert len(errors) == 0

    @override_settings(MIDDLEWARE=[
        'django_postgres_rls.middleware.PostgresRLSMiddleware',
        'django.contrib.auth.middleware.AuthenticationMiddleware',
    ])
    def test_incorrect_ordering(self):
        """Test error when RLS middleware comes before AuthenticationMiddleware."""
        errors = _check_middleware_ordering()
        assert len(errors) == 1
        assert errors[0].id == 'postgres_rls.E004'
        assert isinstance(errors[0], Error)
        assert 'must come after' in errors[0].msg

    @override_settings(MIDDLEWARE=[
        'django_postgres_rls.middleware.PostgresRLSMiddleware',
    ])
    def test_no_auth_middleware(self):
        """Test warning when AuthenticationMiddleware is not present."""
        errors = _check_middleware_ordering()
        assert len(errors) == 1
        assert errors[0].id == 'postgres_rls.W001'
        assert isinstance(errors[0], Warning)
        assert 'AuthenticationMiddleware not found' in errors[0].msg

    @override_settings(MIDDLEWARE=[])
    def test_no_rls_middleware(self):
        """Test no checks when RLS middleware is not installed."""
        errors = _check_middleware_ordering()
        assert len(errors) == 0


class TestValidRolesCheck(TestCase):
    """Test valid roles configuration validation."""

    @override_settings()
    def test_valid_roles_not_configured(self):
        """Test error when POSTGRES_RLS_VALID_ROLES is not configured."""
        if hasattr(TestValidRolesCheck, 'POSTGRES_RLS_VALID_ROLES'):
            delattr(TestValidRolesCheck, 'POSTGRES_RLS_VALID_ROLES')

        errors = _check_valid_roles()
        assert len(errors) == 1
        assert errors[0].id == 'postgres_rls.E005'
        assert isinstance(errors[0], Error)
        assert 'not configured' in errors[0].msg

    @override_settings(POSTGRES_RLS_VALID_ROLES='app_user')
    def test_valid_roles_is_string(self):
        """Test error when POSTGRES_RLS_VALID_ROLES is a string instead of collection."""
        errors = _check_valid_roles()
        assert len(errors) == 1
        assert errors[0].id == 'postgres_rls.E006'
        assert isinstance(errors[0], Error)
        assert 'must be a set, frozenset, or list' in errors[0].msg

    @override_settings(POSTGRES_RLS_VALID_ROLES=[])
    def test_valid_roles_empty(self):
        """Test error when POSTGRES_RLS_VALID_ROLES is empty."""
        errors = _check_valid_roles()
        assert len(errors) == 1
        assert errors[0].id == 'postgres_rls.E007'
        assert isinstance(errors[0], Error)
        assert 'cannot be empty' in errors[0].msg

    @override_settings(POSTGRES_RLS_VALID_ROLES=['app_user', 123, 'app_staff'])
    def test_valid_roles_non_string_values(self):
        """Test error when POSTGRES_RLS_VALID_ROLES contains non-string values."""
        errors = _check_valid_roles()
        assert len(errors) == 1
        assert errors[0].id == 'postgres_rls.E008'
        assert isinstance(errors[0], Error)
        assert 'non-string values' in errors[0].msg

    @override_settings(POSTGRES_RLS_VALID_ROLES=frozenset(['app_user', 'app_staff', 'app_admin']))
    def test_valid_roles_frozenset(self):
        """Test no errors with proper frozenset configuration."""
        errors = _check_valid_roles()
        assert len(errors) == 0

    @override_settings(POSTGRES_RLS_VALID_ROLES=['app_user', 'app_staff'])
    def test_valid_roles_list(self):
        """Test no errors with list configuration."""
        errors = _check_valid_roles()
        assert len(errors) == 0

    @override_settings(POSTGRES_RLS_VALID_ROLES={'app_user', 'app_staff'})
    def test_valid_roles_set(self):
        """Test no errors with set configuration."""
        errors = _check_valid_roles()
        assert len(errors) == 0

    @override_settings(POSTGRES_RLS_VALID_ROLES=['123invalid', 'app user'])
    def test_invalid_role_names(self):
        """Test warning for invalid PostgreSQL role name format."""
        errors = _check_valid_roles()
        assert len(errors) == 1
        assert errors[0].id == 'postgres_rls.W002'
        assert isinstance(errors[0], Warning)
        assert 'invalid role names' in errors[0].msg

    @override_settings(POSTGRES_RLS_VALID_ROLES=['_valid', 'app_user', 'my_role$123'])
    def test_valid_role_name_formats(self):
        """Test that various valid PostgreSQL role name formats are accepted."""
        errors = _check_valid_roles()
        assert len(errors) == 0


class TestSessionVariableCheck(TestCase):
    """Test session variable configuration validation."""

    @override_settings(POSTGRES_RLS_SESSION_UID_VARIABLE='app.current_user_id')
    def test_namespaced_session_variable(self):
        """Test no issues with properly namespaced session variable."""
        errors = _check_session_variable()
        assert len(errors) == 0

    @override_settings(POSTGRES_RLS_SESSION_UID_VARIABLE='current_user_id')
    def test_non_namespaced_session_variable(self):
        """Test info message for non-namespaced session variable."""
        errors = _check_session_variable()
        assert len(errors) == 1
        assert errors[0].id == 'postgres_rls.I001'
        assert isinstance(errors[0], Info)
        assert 'does not use namespacing' in errors[0].msg

    @override_settings()
    def test_default_session_variable(self):
        """Test default session variable is accepted."""
        errors = _check_session_variable()
        # Default is 'app.current_user_id' which is properly namespaced
        assert len(errors) == 0


class TestRoleMappingCheck(TestCase):
    """Test role mapping configuration validation."""

    @override_settings()
    def test_no_role_mapping(self):
        """Test no errors when role mapping is not configured (optional)."""
        errors = _check_role_mapping()
        assert len(errors) == 0

    @override_settings(POSTGRES_RLS_ROLE_MAPPING='invalid')
    def test_role_mapping_not_dict(self):
        """Test error when role mapping is not a dictionary."""
        errors = _check_role_mapping()
        assert len(errors) == 1
        assert errors[0].id == 'postgres_rls.E009'
        assert isinstance(errors[0], Error)
        assert 'must be a dictionary' in errors[0].msg

    @override_settings(
        POSTGRES_RLS_VALID_ROLES=['app_user', 'app_staff'],
        POSTGRES_RLS_ROLE_MAPPING={
            'is_staff': 'app_staff',
            'is_superuser': 'app_user',
        }
    )
    def test_valid_role_mapping(self):
        """Test no errors with valid role mapping."""
        errors = _check_role_mapping()
        assert len(errors) == 0

    @override_settings(
        POSTGRES_RLS_VALID_ROLES=['app_user'],
        POSTGRES_RLS_ROLE_MAPPING={
            'is_staff': 'app_staff',  # Not in valid roles
            'is_superuser': 'app_admin',  # Not in valid roles
        }
    )
    def test_role_mapping_with_invalid_roles(self):
        """Test error when role mapping contains roles not in valid roles."""
        errors = _check_role_mapping()
        assert len(errors) == 1
        assert errors[0].id == 'postgres_rls.E010'
        assert isinstance(errors[0], Error)
        assert 'not in POSTGRES_RLS_VALID_ROLES' in errors[0].msg


class TestConnectionPoolingCheck(TestCase):
    """Test connection pooling compatibility checks."""

    @override_settings(DATABASES={'default': {'ENGINE': 'django.db.backends.postgresql'}})
    def test_no_persistent_connections(self):
        """Test no warnings when CONN_MAX_AGE is not set."""
        errors = _check_connection_pooling()
        assert len(errors) == 0

    @override_settings(DATABASES={'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'CONN_MAX_AGE': 0
    }})
    def test_conn_max_age_zero(self):
        """Test no warnings when CONN_MAX_AGE is 0 (no persistence)."""
        errors = _check_connection_pooling()
        assert len(errors) == 0

    @override_settings(DATABASES={'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'CONN_MAX_AGE': 600
    }})
    def test_persistent_connections(self):
        """Test info message with persistent connections."""
        errors = _check_connection_pooling()
        assert len(errors) == 1
        assert errors[0].id == 'postgres_rls.I002'
        assert isinstance(errors[0], Info)
        assert 'Persistent database connections' in errors[0].msg
        assert 'pgBouncer' in errors[0].hint


class TestMultipleDatabasesCheck(TestCase):
    """Test multiple databases compatibility checks."""

    @override_settings(DATABASES={'default': {'ENGINE': 'django.db.backends.postgresql'}})
    def test_single_database(self):
        """Test no warnings with single database."""
        errors = _check_multiple_databases()
        assert len(errors) == 0

    @override_settings(DATABASES={
        'default': {'ENGINE': 'django.db.backends.postgresql'},
        'replica': {'ENGINE': 'django.db.backends.postgresql'},
    })
    def test_multiple_databases(self):
        """Test info message with multiple databases."""
        errors = _check_multiple_databases()
        assert len(errors) == 1
        assert errors[0].id == 'postgres_rls.I003'
        assert isinstance(errors[0], Info)
        assert 'Multiple databases detected' in errors[0].msg


class TestIntegratedSecurityChecks(TestCase):
    """Test integrated security checks with various configurations."""

    @override_settings(
        MIDDLEWARE=[],
    )
    def test_no_checks_when_middleware_not_installed(self):
        """Test that checks are skipped when middleware is not installed."""
        errors = check_postgres_rls_security(app_configs=None)
        assert len(errors) == 0

    @override_settings(
        MIDDLEWARE=['django_postgres_rls.middleware.PostgresRLSMiddleware'],
        DATABASES={'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'ATOMIC_REQUESTS': True,
        }},
        POSTGRES_RLS_VALID_ROLES=frozenset(['app_user', 'app_staff']),
    )
    def test_minimal_valid_configuration(self):
        """Test minimal valid configuration passes all checks."""
        errors = check_postgres_rls_security(app_configs=None)
        # Should only have warning about missing AuthenticationMiddleware
        assert len(errors) == 1
        assert errors[0].id == 'postgres_rls.W001'

    @override_settings(
        MIDDLEWARE=[
            'django.contrib.auth.middleware.AuthenticationMiddleware',
            'django_postgres_rls.middleware.PostgresRLSMiddleware',
        ],
        DATABASES={'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'ATOMIC_REQUESTS': True,
        }},
        POSTGRES_RLS_VALID_ROLES=frozenset(['app_user', 'app_staff', 'app_admin']),
        POSTGRES_RLS_ROLE_MAPPING={
            'is_staff': 'app_staff',
            'is_superuser': 'app_admin',
        },
        POSTGRES_RLS_SESSION_UID_VARIABLE='myapp.user_id',
    )
    def test_complete_valid_configuration(self):
        """Test complete valid configuration passes all checks."""
        errors = check_postgres_rls_security(app_configs=None)
        assert len(errors) == 0

    @override_settings(
        MIDDLEWARE=[
            'django_postgres_rls.middleware.PostgresRLSMiddleware',
            'django.contrib.auth.middleware.AuthenticationMiddleware',
        ],
        DATABASES={'default': {
            'ENGINE': 'django.db.backends.sqlite3',
        }},
    )
    def test_multiple_errors_reported(self):
        """Test that multiple configuration errors are reported together."""
        errors = check_postgres_rls_security(app_configs=None)

        # Should have multiple errors
        assert len(errors) >= 3

        # Check for specific error IDs
        error_ids = [e.id for e in errors]
        assert 'postgres_rls.E002' in error_ids  # Wrong database backend
        assert 'postgres_rls.E003' in error_ids  # No ATOMIC_REQUESTS
        assert 'postgres_rls.E004' in error_ids  # Wrong middleware ordering
        assert 'postgres_rls.E005' in error_ids  # No valid roles


class TestIntegratedCompatibilityChecks(TestCase):
    """Test integrated compatibility checks."""

    @override_settings(MIDDLEWARE=[])
    def test_no_checks_when_middleware_not_installed(self):
        """Test that checks are skipped when middleware is not installed."""
        warnings = check_postgres_rls_compatibility(app_configs=None)
        assert len(warnings) == 0

    @override_settings(
        MIDDLEWARE=['django_postgres_rls.middleware.PostgresRLSMiddleware'],
        DATABASES={
            'default': {
                'ENGINE': 'django.db.backends.postgresql',
                'CONN_MAX_AGE': 600,
            },
            'replica': {
                'ENGINE': 'django.db.backends.postgresql',
            },
        }
    )
    def test_compatibility_warnings(self):
        """Test that compatibility warnings are reported."""
        warnings = check_postgres_rls_compatibility(app_configs=None)

        # Should have warnings about persistent connections and multiple databases
        assert len(warnings) == 2

        warning_ids = [w.id for w in warnings]
        assert 'postgres_rls.I002' in warning_ids  # Persistent connections
        assert 'postgres_rls.I003' in warning_ids  # Multiple databases
