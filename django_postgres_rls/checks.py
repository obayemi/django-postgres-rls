"""
Django system checks for django-postgres-rls.

These checks validate the configuration and environment to ensure proper
operation of PostgreSQL Row-Level Security middleware.
"""

from django.conf import settings
from django.core.checks import Error, Warning, Info, register, Tags


@register(Tags.security)
def check_postgres_rls_security(app_configs, **kwargs):
    """
    Validate PostgreSQL RLS security configuration.

    Checks:
    - Database backend is PostgreSQL
    - ATOMIC_REQUESTS is enabled
    - Middleware ordering is correct
    - Valid roles are configured
    - Session variable name is configured

    Returns:
        list: List of Error, Warning, or Info instances
    """
    errors = []

    # Only run checks if the middleware is actually being used
    if not _is_middleware_installed():
        return errors

    # Check 1: PostgreSQL backend
    errors.extend(_check_postgresql_backend())

    # Check 2: ATOMIC_REQUESTS setting
    errors.extend(_check_atomic_requests())

    # Check 3: Middleware ordering
    errors.extend(_check_middleware_ordering())

    # Check 4: Valid roles configuration
    errors.extend(_check_valid_roles())

    # Check 5: Session variable configuration
    errors.extend(_check_session_variable())

    # Check 6: Role mapping configuration
    errors.extend(_check_role_mapping())

    return errors


def _is_middleware_installed():
    """Check if PostgresRLSMiddleware is in MIDDLEWARE setting."""
    middleware = getattr(settings, 'MIDDLEWARE', [])
    return any('PostgresRLSMiddleware' in m for m in middleware)


def _check_postgresql_backend():
    """Check that the default database uses PostgreSQL."""
    errors = []

    if 'default' not in settings.DATABASES:
        errors.append(Error(
            'No default database configured',
            hint='Add a "default" database to DATABASES in settings.py',
            id='postgres_rls.E001',
        ))
        return errors

    db_engine = settings.DATABASES['default'].get('ENGINE', '')

    # Check for both modern 'postgresql' and legacy 'postgresql_psycopg2' backend names
    if not ('postgresql' in db_engine):
        errors.append(Error(
            'PostgreSQL RLS requires PostgreSQL database backend',
            hint='Set ENGINE to "django.db.backends.postgresql" in DATABASES["default"]',
            obj='DATABASES["default"]["ENGINE"]',
            id='postgres_rls.E002',
        ))

    return errors


def _check_atomic_requests():
    """Check that ATOMIC_REQUESTS is enabled."""
    errors = []

    if 'default' not in settings.DATABASES:
        return errors

    atomic_requests = settings.DATABASES['default'].get('ATOMIC_REQUESTS', False)

    if not atomic_requests:
        errors.append(Error(
            'PostgreSQL RLS requires ATOMIC_REQUESTS=True',
            hint=(
                'Set ATOMIC_REQUESTS=True in DATABASES["default"]. '
                'Without transactions, SET LOCAL ROLE becomes SET ROLE and persists '
                'across requests, causing serious security issues.'
            ),
            obj='DATABASES["default"]["ATOMIC_REQUESTS"]',
            id='postgres_rls.E003',
        ))

    return errors


def _check_middleware_ordering():
    """Check that PostgresRLSMiddleware comes after AuthenticationMiddleware."""
    errors = []

    middleware = list(getattr(settings, 'MIDDLEWARE', []))

    auth_middleware = 'django.contrib.auth.middleware.AuthenticationMiddleware'
    rls_middleware_candidates = [m for m in middleware if 'PostgresRLSMiddleware' in m]

    if not rls_middleware_candidates:
        return errors

    rls_middleware = rls_middleware_candidates[0]

    # Check if AuthenticationMiddleware exists
    if auth_middleware not in middleware:
        errors.append(Warning(
            'AuthenticationMiddleware not found in MIDDLEWARE',
            hint=(
                'PostgresRLSMiddleware typically requires AuthenticationMiddleware. '
                'Add "django.contrib.auth.middleware.AuthenticationMiddleware" to MIDDLEWARE '
                'before PostgresRLSMiddleware.'
            ),
            obj='MIDDLEWARE',
            id='postgres_rls.W001',
        ))
        return errors

    # Check ordering
    auth_index = middleware.index(auth_middleware)
    rls_index = middleware.index(rls_middleware)

    if rls_index < auth_index:
        errors.append(Error(
            'PostgresRLSMiddleware must come after AuthenticationMiddleware',
            hint=(
                'In MIDDLEWARE, move PostgresRLSMiddleware to a position after '
                'AuthenticationMiddleware. The middleware needs access to '
                'request.user which is set by AuthenticationMiddleware.'
            ),
            obj='MIDDLEWARE',
            id='postgres_rls.E004',
        ))

    return errors


def _check_valid_roles():
    """Check that POSTGRES_RLS_VALID_ROLES is properly configured."""
    errors = []

    valid_roles = getattr(settings, 'POSTGRES_RLS_VALID_ROLES', None)

    if valid_roles is None:
        errors.append(Error(
            'POSTGRES_RLS_VALID_ROLES not configured',
            hint=(
                'Define POSTGRES_RLS_VALID_ROLES in settings.py as a set or frozenset '
                'of valid PostgreSQL role names. Example: '
                'POSTGRES_RLS_VALID_ROLES = frozenset([\'app_user\', \'app_staff\', \'app_superuser\'])'
            ),
            obj='POSTGRES_RLS_VALID_ROLES',
            id='postgres_rls.E005',
        ))
        return errors

    # Check that it's a collection
    if not hasattr(valid_roles, '__iter__') or isinstance(valid_roles, (str, bytes)):
        errors.append(Error(
            'POSTGRES_RLS_VALID_ROLES must be a set, frozenset, or list',
            hint='Change POSTGRES_RLS_VALID_ROLES to a set, frozenset, or list of role names',
            obj='POSTGRES_RLS_VALID_ROLES',
            id='postgres_rls.E006',
        ))
        return errors

    # Check that it's not empty
    if not valid_roles:
        errors.append(Error(
            'POSTGRES_RLS_VALID_ROLES cannot be empty',
            hint='Add at least one PostgreSQL role name to POSTGRES_RLS_VALID_ROLES',
            obj='POSTGRES_RLS_VALID_ROLES',
            id='postgres_rls.E007',
        ))
        return errors

    # Check that all roles are strings
    non_string_roles = [r for r in valid_roles if not isinstance(r, str)]
    if non_string_roles:
        errors.append(Error(
            f'POSTGRES_RLS_VALID_ROLES contains non-string values: {non_string_roles}',
            hint='All role names in POSTGRES_RLS_VALID_ROLES must be strings',
            obj='POSTGRES_RLS_VALID_ROLES',
            id='postgres_rls.E008',
        ))

    # Check for valid role name format (PostgreSQL identifier rules)
    invalid_roles = []
    for role in valid_roles:
        if isinstance(role, str):
            # PostgreSQL identifiers: start with letter or underscore,
            # contain only letters, digits, underscores, and $
            if not role or not (role[0].isalpha() or role[0] == '_'):
                invalid_roles.append(role)
            elif not all(c.isalnum() or c in ('_', '$') for c in role):
                invalid_roles.append(role)

    if invalid_roles:
        errors.append(Warning(
            f'POSTGRES_RLS_VALID_ROLES contains potentially invalid role names: {invalid_roles}',
            hint=(
                'PostgreSQL role names should start with a letter or underscore and '
                'contain only letters, digits, underscores, and dollar signs'
            ),
            obj='POSTGRES_RLS_VALID_ROLES',
            id='postgres_rls.W002',
        ))

    return errors


def _check_session_variable():
    """Check session variable configuration."""
    errors = []

    session_var = getattr(settings, 'POSTGRES_RLS_SESSION_UID_VARIABLE', 'app.current_user_id')

    # Check format (should contain a dot for proper namespacing)
    if '.' not in session_var:
        errors.append(Info(
            f'Session variable "{session_var}" does not use namespacing',
            hint=(
                'Consider using a namespaced format like "app.current_user_id" to avoid '
                'conflicts with other PostgreSQL session variables'
            ),
            obj='POSTGRES_RLS_SESSION_UID_VARIABLE',
            id='postgres_rls.I001',
        ))

    return errors


def _check_role_mapping():
    """Check role mapping configuration."""
    errors = []

    role_mapping = getattr(settings, 'POSTGRES_RLS_ROLE_MAPPING', None)

    if role_mapping is None:
        # Role mapping is optional, so just provide info
        return errors

    # Check that it's a dictionary
    if not isinstance(role_mapping, dict):
        errors.append(Error(
            'POSTGRES_RLS_ROLE_MAPPING must be a dictionary',
            hint='Change POSTGRES_RLS_ROLE_MAPPING to a dictionary mapping user attributes to roles',
            obj='POSTGRES_RLS_ROLE_MAPPING',
            id='postgres_rls.E009',
        ))
        return errors

    # Check that mapped roles are in valid roles (if configured)
    valid_roles = getattr(settings, 'POSTGRES_RLS_VALID_ROLES', None)
    if valid_roles:
        invalid_mapped_roles = [
            role for role in role_mapping.values()
            if isinstance(role, str) and role not in valid_roles
        ]

        if invalid_mapped_roles:
            errors.append(Error(
                f'POSTGRES_RLS_ROLE_MAPPING contains roles not in POSTGRES_RLS_VALID_ROLES: {invalid_mapped_roles}',
                hint='Ensure all roles in POSTGRES_RLS_ROLE_MAPPING are also listed in POSTGRES_RLS_VALID_ROLES',
                obj='POSTGRES_RLS_ROLE_MAPPING',
                id='postgres_rls.E010',
            ))

    return errors


@register(Tags.compatibility)
def check_postgres_rls_compatibility(app_configs, **kwargs):
    """
    Check for potential compatibility issues.

    Returns:
        list: List of Warning or Info instances
    """
    warnings = []

    if not _is_middleware_installed():
        return warnings

    # Check for connection pooling configuration
    warnings.extend(_check_connection_pooling())

    # Check for multiple databases
    warnings.extend(_check_multiple_databases())

    return warnings


def _check_connection_pooling():
    """Check for potential connection pooling issues."""
    warnings = []

    # Check for common connection pooling settings
    db_config = settings.DATABASES.get('default', {})
    conn_max_age = db_config.get('CONN_MAX_AGE', 0)

    if conn_max_age > 0:
        warnings.append(Info(
            f'Persistent database connections enabled (CONN_MAX_AGE={conn_max_age})',
            hint=(
                'PostgreSQL RLS middleware uses SET LOCAL ROLE which is transaction-scoped. '
                'With persistent connections, ensure ATOMIC_REQUESTS=True to prevent role leakage. '
                'Note: This middleware is not compatible with pgBouncer in transaction pooling mode.'
            ),
            obj='DATABASES["default"]["CONN_MAX_AGE"]',
            id='postgres_rls.I002',
        ))

    return warnings


def _check_multiple_databases():
    """Check for multiple database configuration."""
    warnings = []

    if len(settings.DATABASES) > 1:
        warnings.append(Info(
            'Multiple databases detected',
            hint=(
                'PostgreSQL RLS middleware only affects the default database. '
                'If you need RLS on other databases, you will need custom implementation.'
            ),
            obj='DATABASES',
            id='postgres_rls.I003',
        ))

    return warnings
