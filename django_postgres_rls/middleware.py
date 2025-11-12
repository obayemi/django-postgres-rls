"""
PostgreSQL Row-Level Security (RLS) Middleware for Django.

This middleware switches PostgreSQL roles based on user authentication and
sets session variables for RLS policy enforcement.
"""

import logging
import re
from contextlib import contextmanager
from django.db import connection, transaction
from django.utils.deprecation import MiddlewareMixin
from django.core.exceptions import ImproperlyConfigured

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger('django_postgres_rls.audit')

# Cache for PostgreSQL role validation
_pg_roles_cache = None
_pg_roles_cache_checked = False


def _execute_set_role(cursor, pg_role, user_id=None, session_uid_variable='app.current_user_id'):
    """
    Execute SQL to set PostgreSQL role and optionally user ID.

    This is shared core logic used by both the middleware and context manager.

    Args:
        cursor: Database cursor
        pg_role: PostgreSQL role name (must be already validated)
        user_id: Optional user ID to set in session variable
        session_uid_variable: Session variable name for user ID

    Raises:
        Exception: If SQL execution fails
    """
    from psycopg2 import sql

    # Switch to the appropriate PostgreSQL role using safe identifier quoting
    # SET LOCAL ROLE ensures the role change is transaction-scoped
    cursor.execute(
        sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(pg_role))
    )

    # Set user ID in session variable if provided
    if user_id is not None and user_id != '':
        cursor.execute(
            sql.SQL("SELECT set_config({}, %s, true)").format(
                sql.Literal(session_uid_variable)
            ),
            [user_id]
        )

    logger.debug(f"RLS: Set role={pg_role}, user_id={user_id if user_id else 'none'}")


def _execute_reset_role(cursor):
    """
    Execute SQL to reset PostgreSQL role.

    This is shared core logic used by both the middleware and context manager.

    Args:
        cursor: Database cursor

    Raises:
        Exception: If SQL execution fails
    """
    cursor.execute("RESET ROLE")
    logger.debug("RLS: Role reset")


def _validate_role_name(role_name, valid_roles):
    """
    Validate that a PostgreSQL role is in the whitelist.

    This is shared validation logic used by both the middleware and context manager.

    Args:
        role_name: PostgreSQL role name to validate
        valid_roles: Set/frozenset of valid role names

    Raises:
        ValueError: If role is not in whitelist or is invalid

    Returns:
        str: The validated role name
    """
    if not role_name:
        raise ValueError("PostgreSQL role cannot be empty")

    if role_name not in valid_roles:
        logger.error(
            f"Invalid PostgreSQL role attempted: '{role_name}'. "
            f"Valid roles: {', '.join(sorted(valid_roles))}"
        )
        raise ValueError(
            f"Invalid PostgreSQL role: '{role_name}'. "
            f"Role must be one of: {', '.join(sorted(valid_roles))}"
        )

    return role_name


def _sanitize_user_id(user_id):
    """
    Sanitize user ID to prevent SQL injection.

    This is shared sanitization logic used by both the middleware and context manager.

    Args:
        user_id: Raw user ID value

    Returns:
        str: Sanitized user ID as string, or empty string if invalid
    """
    if user_id is None or user_id == '':
        return ''

    # Convert to string and validate it's a reasonable value
    user_id_str = str(user_id)

    # Check for reasonable length (prevent extremely long values)
    if len(user_id_str) > 255:
        logger.warning(f"User ID too long (>{255} chars), truncating")
        user_id_str = user_id_str[:255]

    # For security, only allow alphanumeric, hyphens, and underscores
    # This covers UUIDs, integers, and most common ID formats
    if not re.match(r'^[a-zA-Z0-9_-]+$', user_id_str):
        logger.warning(
            f"User ID contains invalid characters: '{user_id_str}'. "
            f"Only alphanumeric, hyphens, and underscores are allowed."
        )
        # Remove invalid characters
        user_id_str = re.sub(r'[^a-zA-Z0-9_-]', '', user_id_str)

    return user_id_str


def _get_postgresql_roles():
    """
    Query PostgreSQL to get list of available roles.

    Note: Django system checks already ensure we're using PostgreSQL,
    so no need to verify the database engine here.

    Returns:
        frozenset: Set of role names available in PostgreSQL, or None if validation is skipped

    Raises:
        Exception: If database query fails
    """
    global _pg_roles_cache, _pg_roles_cache_checked

    # Return cached result if available
    if _pg_roles_cache_checked:
        return _pg_roles_cache

    # Check if user explicitly disabled validation
    from django.conf import settings
    skip_validation = getattr(settings, 'POSTGRES_RLS_SKIP_ROLE_VALIDATION', False)
    if skip_validation:
        logger.info("Role validation explicitly disabled via POSTGRES_RLS_SKIP_ROLE_VALIDATION")
        _pg_roles_cache = None
        _pg_roles_cache_checked = True
        return None

    # Perform validation (system checks already verified PostgreSQL)
    try:
        with connection.cursor() as cursor:
            # Query pg_roles to get all available roles
            cursor.execute(
                "SELECT rolname FROM pg_roles WHERE rolcanlogin = false OR rolcanlogin = true"
            )
            roles = frozenset(row[0] for row in cursor.fetchall())
            _pg_roles_cache = roles
            _pg_roles_cache_checked = True
            logger.debug(f"Loaded {len(roles)} PostgreSQL roles from database")
            return roles
    except Exception as e:
        # Query failed - this is a real PostgreSQL error
        logger.error(f"Failed to query PostgreSQL roles: {e}")
        _pg_roles_cache_checked = True
        _pg_roles_cache = None
        raise


def _validate_roles_exist_in_postgres(configured_roles):
    """
    Validate that configured roles exist in PostgreSQL database.

    Args:
        configured_roles: Set of role names to validate

    Returns:
        tuple: (valid_roles, missing_roles) or (configured_roles, set()) if validation skipped

    Raises:
        ImproperlyConfigured: If validation fails or roles are missing
    """
    try:
        pg_roles = _get_postgresql_roles()
    except Exception as e:
        raise ImproperlyConfigured(
            f"Failed to validate PostgreSQL roles: {e}\n"
            f"Hint: Ensure the database connection is properly configured and PostgreSQL is accessible.\n"
            f"Database settings: {connection.settings_dict.get('NAME', 'unknown')}"
        )

    # Skip validation if in test mode or roles couldn't be fetched
    if pg_roles is None:
        logger.info("Skipping PostgreSQL role validation (test mode or unavailable)")
        return configured_roles, set()

    missing_roles = configured_roles - pg_roles

    if missing_roles:
        missing_list = ', '.join(sorted(missing_roles))
        available_list = ', '.join(sorted(pg_roles)) if pg_roles else 'none'

        raise ImproperlyConfigured(
            f"PostgreSQL RLS Configuration Error: The following roles do not exist in PostgreSQL:\n"
            f"  Missing roles: {missing_list}\n\n"
            f"Available PostgreSQL roles: {available_list}\n\n"
            f"To fix this issue, create the missing roles in PostgreSQL:\n"
            f"  psql -d your_database -c \"CREATE ROLE {next(iter(missing_roles))} NOLOGIN;\"\n\n"
            f"Or update your Django settings to use existing roles:\n"
            f"  POSTGRES_RLS_VALID_ROLES = frozenset({list(pg_roles & configured_roles)})\n\n"
            f"For more information, see: https://www.postgresql.org/docs/current/sql-createrole.html"
        )

    valid_roles = configured_roles & pg_roles
    return valid_roles, missing_roles


class PostgresRLSMiddleware(MiddlewareMixin):
    """
    Middleware that switches PostgreSQL roles and sets session variables
    for Row-Level Security enforcement.

    This middleware should be placed after authentication middleware in your
    MIDDLEWARE settings, and after any middleware that sets user roles.

    The middleware performs the following actions:
    1. Calls extract_role() to get the user's role from the request
    2. Maps the role to a PostgreSQL role (app_user, app_staff, app_superuser)
    3. Executes SET ROLE to switch to the appropriate PostgreSQL role
    4. Sets the user ID in a session variable for policy filtering
    5. Resets the role after request processing

    Usage Option 1 (Recommended): Create a middleware subclass and override extract_role()
        class MyRLSMiddleware(PostgresRLSMiddleware):
            def extract_role(self, request):
                if not request.user or not request.user.is_authenticated:
                    return None

                # Default role based on user attributes
                if request.user.is_superuser:
                    return 'superuser'
                elif request.user.is_staff:
                    return 'staff'
                return 'user'

    Alternative Option: Add RlsUser mixin to your User model
        Note: This approach is less flexible than middleware override since the role logic
        is tied to the User model. However, it can be useful for simple use cases.

        from django.contrib.auth.models import AbstractUser
        from django_postgres_rls import RlsUser

        class User(RlsUser, AbstractUser):
            def get_postgres_role(self):
                # Returns PostgreSQL role directly (not application role)
                if self.is_superuser:
                    return 'app_superuser'  # Note: PostgreSQL role, not 'superuser'
                elif self.is_staff:
                    return 'app_staff'
                return 'app_user'

        # In settings.py - use base middleware
        MIDDLEWARE = [
            ...
            'django.contrib.auth.middleware.AuthenticationMiddleware',
            'django_postgres_rls.PostgresRLSMiddleware',  # No subclass needed
            ...
        ]

    Configuration:
        POSTGRES_RLS_ROLE_MAPPING (optional): Dict mapping role names to PostgreSQL roles
            Default: {
                'user': 'app_user',
                'staff': 'app_staff',
                'superuser': 'app_superuser',
                'anonymous': 'app_anonymous'
            }

        POSTGRES_RLS_DEFAULT_ANONYMOUS_ROLE (optional): Default role for unauthenticated users
            Default: 'app_anonymous'
            This role is used when:
            - User is not authenticated
            - extract_role() returns a role not in the mapping
            - As a fallback for unknown roles

        POSTGRES_RLS_WHITELIST (optional): List of URL paths that bypass RLS middleware
            Default: [
                '/api/auth/login/',
                '/api/auth/register/',
                '/api/auth/token/',
                '/api-auth/login/',
                '/admin/login/',
            ]
            Paths are matched using startswith(), so '/api/auth/login/' matches
            '/api/auth/login/reset/' as well. Used primarily for authentication endpoints.

        POSTGRES_RLS_VALID_ROLES (optional): Frozenset or list of valid PostgreSQL roles
            If not provided, roles from POSTGRES_RLS_ROLE_MAPPING are used
            Example: frozenset(['app_user', 'app_staff', 'app_superuser', 'app_anonymous'])

        POSTGRES_RLS_SESSION_UID_VARIABLE (optional): Session variable name for user ID
            Default: 'app.current_user_id'

        POSTGRES_RLS_ENABLE_AUDIT_LOG (optional): Enable audit logging of role switches
            Default: False

        POSTGRES_RLS_SKIP_ROLE_VALIDATION (optional): Skip PostgreSQL role validation at startup
            Default: False
            Set to True to disable automatic verification that roles exist in PostgreSQL.

            Use cases:
            - CI/CD pipelines where roles are created after Django starts
            - External role management systems (e.g., Terraform, Ansible)
            - Deliberately avoiding the startup query for performance reasons

            Warning: Disabling validation may cause runtime errors if roles don't exist.
    """

    def __init__(self, get_response):
        """
        Initialize the middleware and validate configuration.

        Args:
            get_response: The next middleware or view in the chain

        Raises:
            ImproperlyConfigured: If configuration is invalid
        """
        super().__init__(get_response)
        self._load_configuration()
        self._validate_configuration()
        self._roles_validated = False  # Lazy validation on first request

    def _load_configuration(self):
        """Load configuration from Django settings."""
        from django.conf import settings

        # Load role mapping
        self.role_mapping = getattr(settings, 'POSTGRES_RLS_ROLE_MAPPING', {
            'user': 'app_user',
            'staff': 'app_staff',
            'superuser': 'app_superuser',
            'anonymous': 'app_anonymous'  # Default for unauthenticated users
        })

        # Load default anonymous role for unauthenticated users or fallback
        default_anon = getattr(settings, 'POSTGRES_RLS_DEFAULT_ANONYMOUS_ROLE', 'app_anonymous')
        # Handle MagicMock from tests
        if isinstance(default_anon, str):
            self.default_anonymous_role = default_anon
        else:
            self.default_anonymous_role = 'app_anonymous'

        # Load RLS whitelist - endpoints that bypass RLS middleware
        whitelist = getattr(settings, 'POSTGRES_RLS_WHITELIST', None)
        # Handle MagicMock from tests
        if isinstance(whitelist, (list, tuple)):
            self.rls_whitelist = whitelist
        else:
            self.rls_whitelist = [
                '/api/auth/login/',
                '/api/auth/register/',
                '/api/auth/token/',
                '/api-auth/login/',
                '/admin/login/',
            ]

        # Load valid roles (whitelist)
        # Use hasattr to distinguish between "not set" and "set to empty"
        if hasattr(settings, 'POSTGRES_RLS_VALID_ROLES'):
            valid_roles_setting = settings.POSTGRES_RLS_VALID_ROLES
            self.valid_roles = frozenset(valid_roles_setting) if valid_roles_setting else frozenset()
        else:
            # Use roles from mapping as valid roles if not explicitly set
            # Include the default anonymous role
            mapped_roles = set(self.role_mapping.values())
            mapped_roles.add(self.default_anonymous_role)
            self.valid_roles = frozenset(mapped_roles)

        # Load session variable name
        self.session_uid_variable = getattr(
            settings,
            'POSTGRES_RLS_SESSION_UID_VARIABLE',
            'app.current_user_id'
        )

        # Load audit logging flag
        self.enable_audit_log = getattr(
            settings,
            'POSTGRES_RLS_ENABLE_AUDIT_LOG',
            False
        )

    def _validate_configuration(self):
        """
        Validate the loaded configuration.

        Raises:
            ImproperlyConfigured: If configuration is invalid
        """
        if not self.valid_roles:
            raise ImproperlyConfigured(
                "PostgreSQL RLS Configuration Error: POSTGRES_RLS_VALID_ROLES cannot be empty.\n\n"
                "Please define valid PostgreSQL roles in your Django settings:\n\n"
                "Example configuration:\n"
                "  POSTGRES_RLS_VALID_ROLES = frozenset(['app_user', 'app_staff', 'app_superuser', 'app_anonymous'])\n\n"
                "Or let the middleware infer from role mapping:\n"
                "  POSTGRES_RLS_ROLE_MAPPING = {\n"
                "      'user': 'app_user',\n"
                "      'staff': 'app_staff',\n"
                "      'superuser': 'app_superuser',\n"
                "      'anonymous': 'app_anonymous',\n"
                "  }\n\n"
                "For security, only whitelisted roles can be used for role switching."
            )

        # Validate that all role names are non-empty strings
        for role in self.valid_roles:
            if not role or not isinstance(role, str):
                raise ImproperlyConfigured(
                    f"PostgreSQL RLS Configuration Error: Invalid role in POSTGRES_RLS_VALID_ROLES: {role!r}\n\n"
                    f"All roles must be non-empty strings.\n\n"
                    f"Current valid roles: {self.valid_roles}\n\n"
                    f"Please update your settings to only include valid role name strings:\n"
                    f"  POSTGRES_RLS_VALID_ROLES = frozenset(['app_user', 'app_staff'])"
                )

        # Validate default anonymous role
        if not self.default_anonymous_role or not isinstance(self.default_anonymous_role, str):
            raise ImproperlyConfigured(
                f"PostgreSQL RLS Configuration Error: Invalid default anonymous role: {self.default_anonymous_role!r}\n\n"
                f"The default anonymous role must be a non-empty string.\n\n"
                f"Example configuration:\n"
                f"  POSTGRES_RLS_DEFAULT_ANONYMOUS_ROLE = 'app_anonymous'\n\n"
                f"This role is used for unauthenticated users and as a fallback."
            )

        # Ensure default anonymous role is in valid_roles
        # If not present, add it automatically
        if self.default_anonymous_role not in self.valid_roles:
            logger.warning(
                f"RLS: Default anonymous role '{self.default_anonymous_role}' not in POSTGRES_RLS_VALID_ROLES. "
                f"Adding it automatically."
            )
            self.valid_roles = self.valid_roles | frozenset([self.default_anonymous_role])

        # Validate RLS whitelist is a list
        if not isinstance(self.rls_whitelist, (list, tuple)):
            raise ImproperlyConfigured(
                f"PostgreSQL RLS Configuration Error: POSTGRES_RLS_WHITELIST must be a list or tuple.\n\n"
                f"Current value: {self.rls_whitelist!r}\n\n"
                f"Example configuration:\n"
                f"  POSTGRES_RLS_WHITELIST = ['/api/auth/login/', '/api/auth/register/']"
            )

        # Validate session variable name format (schema.variable)
        if not self.session_uid_variable or '.' not in self.session_uid_variable:
            raise ImproperlyConfigured(
                f"PostgreSQL RLS Configuration Error: Invalid session variable name: '{self.session_uid_variable}'\n\n"
                f"Session variable must be in format 'schema.variable' (e.g., 'app.current_user_id')\n\n"
                f"Example configuration:\n"
                f"  POSTGRES_RLS_SESSION_UID_VARIABLE = 'app.current_user_id'\n\n"
                f"The schema prefix prevents conflicts with other PostgreSQL extensions."
            )

    def _validate_roles_in_database(self):
        """
        Validate that configured roles exist in PostgreSQL database.

        This is called lazily on first request to avoid connection issues during startup.

        Raises:
            ImproperlyConfigured: If roles don't exist in PostgreSQL
        """
        if self._roles_validated:
            return

        logger.info(f"Validating {len(self.valid_roles)} PostgreSQL roles exist in database...")

        try:
            _validate_roles_exist_in_postgres(self.valid_roles)
            self._roles_validated = True
            logger.info("PostgreSQL RLS roles validated successfully")
        except ImproperlyConfigured:
            # Re-raise with additional context
            raise
        except Exception as e:
            raise ImproperlyConfigured(
                f"PostgreSQL RLS Startup Error: Failed to validate roles in database: {e}\n\n"
                f"This usually indicates a database connection problem.\n\n"
                f"Troubleshooting steps:\n"
                f"1. Verify PostgreSQL is running and accessible\n"
                f"2. Check database credentials in settings.DATABASES\n"
                f"3. Ensure the database exists and migrations have been applied\n"
                f"4. Verify network connectivity to the database server\n\n"
                f"Database: {connection.settings_dict.get('NAME', 'unknown')}\n"
                f"Host: {connection.settings_dict.get('HOST', 'localhost')}"
            )

    def __call__(self, request):
        """
        Handle the request, ensuring it runs within a transaction.

        This method wraps the entire request/response cycle in a transaction
        if one doesn't already exist, ensuring SET LOCAL ROLE works correctly.

        Args:
            request: The Django HttpRequest object

        Returns:
            HttpResponse: The response object
        """
        # Validate roles exist in PostgreSQL on first request (lazy validation)
        self._validate_roles_in_database()

        # Check if we're already in a transaction
        if connection.in_atomic_block:
            # Already in a transaction, use normal middleware flow
            logger.debug("RLS: Already in transaction, using normal flow")
            return super().__call__(request)

        # Not in a transaction - we need to create one
        # This ensures SET LOCAL ROLE is transaction-scoped
        logger.debug("RLS: Not in transaction, creating atomic block")

        try:
            with transaction.atomic():
                # Process request within transaction
                response = super().__call__(request)
                return response
        except Exception as e:
            # Log the error for debugging
            logger.error(
                f"RLS: Exception during request processing: {e.__class__.__name__}: {e}"
            )
            # Re-raise - Django will handle it
            raise

    def extract_role(self, request):
        """
        Extract the user's role from the request.

        Recommended: Override this method in a middleware subclass (see class docstring).

        Alternative: If the user model has a `get_postgres_role()` method (from the
        RlsUser mixin), it will be called automatically. However, this approach is less
        flexible and ties authorization logic to the User model.

        Args:
            request: The Django HttpRequest object

        Returns:
            str: The role name (e.g., 'user', 'staff', 'superuser'), or None if no role

        Raises:
            NotImplementedError: If user doesn't have get_postgres_role() and method not overridden

        Example (Recommended) - Middleware override:
            class MyRLSMiddleware(PostgresRLSMiddleware):
                def extract_role(self, request):
                    if not request.user or not request.user.is_authenticated:
                        return None
                    return 'superuser' if request.user.is_superuser else 'user'

        Example (Alternative) - RlsUser mixin:
            from django_postgres_rls import RlsUser

            class User(RlsUser, AbstractUser):
                def get_postgres_role(self):
                    return 'app_superuser' if self.is_superuser else 'app_user'
        """
        # Check if user exists and is authenticated
        if not hasattr(request, 'user') or not request.user or not request.user.is_authenticated:
            return None

        # Check if user has get_postgres_role method (from RlsUser mixin)
        if hasattr(request.user, 'get_postgres_role') and callable(request.user.get_postgres_role):
            return request.user.get_postgres_role()

        # If no get_postgres_role method, require subclass to override extract_role
        raise NotImplementedError(
            "Either:\n"
            "1. Add the RlsUser mixin to your User model and implement get_postgres_role(), or\n"
            "2. Override extract_role() in your PostgresRLSMiddleware subclass.\n\n"
            "Example 1 (RlsUser mixin):\n"
            "    from django_postgres_rls import RlsUser\n"
            "    class User(RlsUser, AbstractUser):\n"
            "        def get_postgres_role(self):\n"
            "            return 'app_superuser' if self.is_superuser else 'app_user'\n\n"
            "Example 2 (Override extract_role):\n"
            "    class MyRLSMiddleware(PostgresRLSMiddleware):\n"
            "        def extract_role(self, request):\n"
            "            return 'app_superuser' if request.user.is_superuser else 'app_user'"
        )

    def _validate_role(self, pg_role):
        """
        Validate that a PostgreSQL role is in the whitelist.

        Delegates to the module-level function for consistency.

        Args:
            pg_role: PostgreSQL role name to validate

        Raises:
            ValueError: If role is not in whitelist or is invalid

        Returns:
            str: The validated role name
        """
        return _validate_role_name(pg_role, self.valid_roles)

    def _sanitize_user_id(self, user_id):
        """
        Sanitize user ID to prevent SQL injection.

        Delegates to the module-level function for consistency.

        Args:
            user_id: Raw user ID value

        Returns:
            str: Sanitized user ID as string, or empty string if invalid
        """
        return _sanitize_user_id(user_id)

    def get_user_id(self, request):
        """
        Extract the user ID from the request.

        Can be overridden to customize user ID extraction.

        Args:
            request: The Django HttpRequest object

        Returns:
            str: The user ID as a string, or empty string if not authenticated
        """
        if request.user and request.user.is_authenticated:
            user_id = getattr(request.user, 'id', None)
            return self._sanitize_user_id(user_id)
        return ''

    def _audit_log(self, action, pg_role, user_id, request=None, error=None):
        """
        Log role switching actions for audit trail.

        Args:
            action: Action being performed (e.g., 'role_switch', 'role_reset')
            pg_role: PostgreSQL role name
            user_id: User ID
            request: Optional Django request object
            error: Optional error message
        """
        if not self.enable_audit_log:
            return

        log_data = {
            'action': action,
            'pg_role': pg_role,
            'user_id': user_id,
        }

        if request:
            log_data.update({
                'path': request.path,
                'method': request.method,
                'remote_addr': request.META.get('REMOTE_ADDR'),
                'user_agent': request.META.get('HTTP_USER_AGENT'),
            })

        if error:
            log_data['error'] = str(error)
            audit_logger.error(f"RLS Audit: {log_data}")
        else:
            audit_logger.info(f"RLS Audit: {log_data}")

    def _set_role_sql(self, cursor, pg_role, user_id=None):
        """
        Execute SQL to set PostgreSQL role and optionally user ID.

        Delegates to the module-level function with the configured session variable.

        Args:
            cursor: Database cursor
            pg_role: PostgreSQL role name (must be already validated)
            user_id: Optional user ID to set in session variable

        Raises:
            Exception: If SQL execution fails
        """
        _execute_set_role(cursor, pg_role, user_id, self.session_uid_variable)

    def _reset_role_sql(self, cursor):
        """
        Execute SQL to reset PostgreSQL role.

        Delegates to the module-level function.

        Args:
            cursor: Database cursor

        Raises:
            Exception: If SQL execution fails
        """
        _execute_reset_role(cursor)

    def _is_whitelisted_path(self, request):
        """
        Check if the request path is in the RLS whitelist.

        Paths in the whitelist bypass RLS role switching entirely.

        Args:
            request: The Django HttpRequest object

        Returns:
            bool: True if the path is whitelisted, False otherwise
        """
        path = getattr(request, 'path', '')
        if not path:
            return False

        # Check if path matches any whitelist entry (prefix match)
        for whitelist_path in self.rls_whitelist:
            if path.startswith(whitelist_path):
                logger.debug(f"RLS: Path '{path}' is whitelisted (matched '{whitelist_path}')")
                return True

        return False

    def process_request(self, request):
        """
        Switch PostgreSQL role and set user ID before processing the request.

        This method is called before Django processes the request.

        Args:
            request: The Django HttpRequest object

        Returns:
            None

        Raises:
            ValueError: If role validation fails
            ImproperlyConfigured: If configuration is invalid
        """
        # Check if the request path is whitelisted (bypass RLS for auth endpoints)
        if self._is_whitelisted_path(request):
            logger.debug(f"RLS: Skipping role switching for whitelisted path: {request.path}")
            return None

        # Get the role from the subclass implementation
        try:
            role = self.extract_role(request)
        except Exception as e:
            raise ImproperlyConfigured(
                f"PostgreSQL RLS Error: Failed to extract role from request: {e}\n\n"
                f"The extract_role() method raised an exception.\n\n"
                f"Please check your middleware implementation:\n"
                f"  class YourMiddleware(PostgresRLSMiddleware):\n"
                f"      def extract_role(self, request):\n"
                f"          # Your role extraction logic here\n"
                f"          return 'user'  # or 'staff', 'superuser', etc.\n\n"
                f"Error details: {e}"
            )

        # If no role extracted, skip role switching
        if not role:
            return None

        # Check if role came from RlsUser mixin (returns PostgreSQL role directly)
        # vs middleware subclass extract_role override (returns app role that needs mapping)
        # We check if get_postgres_role is actually defined (not just from Mock.__getattr__)
        user_has_get_postgres_role = False
        if hasattr(request, 'user') and request.user:
            user_obj = request.user

            # Handle Django's SimpleLazyObject and other proxy objects
            # Force lazy evaluation by accessing any attribute (is_authenticated is always safe)
            if hasattr(user_obj, '_wrapped'):
                try:
                    # This triggers lazy evaluation for SimpleLazyObject
                    _ = user_obj.is_authenticated
                except (AttributeError, TypeError):
                    pass

            # Get the actual user class (unwrap SimpleLazyObject if needed)
            if hasattr(user_obj, '_wrapped') and hasattr(user_obj.__dict__.get('_wrapped'), '__class__'):
                # SimpleLazyObject that has been evaluated
                actual_class = type(user_obj._wrapped)
            else:
                # Regular object or unevaluated lazy object
                actual_class = type(user_obj)

            # Check if get_postgres_role is defined in the class hierarchy
            # This works correctly with Django's AbstractUser and RlsUser mixin
            user_has_get_postgres_role = any(
                'get_postgres_role' in getattr(cls, '__dict__', {})
                for cls in actual_class.__mro__
            )

        if user_has_get_postgres_role:
            # Role came from RlsUser.get_postgres_role() - it's already a PostgreSQL role name
            pg_role = role
        else:
            # Role came from middleware subclass - map it to PostgreSQL role
            # Use default anonymous role as fallback instead of hardcoded 'app_user'
            pg_role = self.role_mapping.get(role, self.default_anonymous_role)

        # Validate the role is in whitelist
        try:
            pg_role = self._validate_role(pg_role)
        except ValueError as e:
            self._audit_log('role_validation_failed', pg_role, '', request, error=e)
            # Enhance the error message with more context
            raise ValueError(
                f"PostgreSQL RLS Security Error: Invalid role '{pg_role}'\n\n"
                f"The role '{pg_role}' (mapped from '{role}') is not in the whitelist.\n\n"
                f"Valid roles: {', '.join(sorted(self.valid_roles))}\n\n"
                f"To fix this:\n"
                f"1. Add the role to POSTGRES_RLS_VALID_ROLES in settings.py:\n"
                f"   POSTGRES_RLS_VALID_ROLES = frozenset({sorted(self.valid_roles | {pg_role})})\n\n"
                f"2. Or update your role mapping:\n"
                f"   POSTGRES_RLS_ROLE_MAPPING = {{\n"
                f"       '{role}': 'app_user',  # Map to an existing valid role\n"
                f"   }}\n\n"
                f"3. Or update your extract_role() method to return a valid role name."
            ) from e

        # Get and sanitize user ID
        user_id = self.get_user_id(request)

        try:
            with connection.cursor() as cursor:
                # Use shared SQL execution logic
                self._set_role_sql(cursor, pg_role, user_id)
                self._audit_log('role_switch', pg_role, user_id, request)

        except Exception as e:
            error_msg = (
                f"PostgreSQL RLS Error: Failed to set role '{pg_role}'\n\n"
                f"Database error during role switch: {e.__class__.__name__}: {e}\n\n"
                f"Troubleshooting:\n"
                f"1. Verify the PostgreSQL role exists:\n"
                f"   SELECT rolname FROM pg_roles WHERE rolname = '{pg_role}';\n\n"
                f"2. Verify the application role has permission to switch:\n"
                f"   GRANT {pg_role} TO {connection.settings_dict.get('USER', 'app_role')};\n\n"
                f"3. Check PostgreSQL logs for more details\n\n"
                f"4. Ensure PostgreSQL version supports RLS (9.5+)"
            )
            logger.error(error_msg)
            self._audit_log('role_switch_failed', pg_role, user_id, request, error=e)
            # Re-raise with enhanced message
            raise type(e)(error_msg) from e

        return None

    def process_response(self, request, response):
        """
        Reset the PostgreSQL role after request processing.

        This method is called after Django has processed the request.

        Args:
            request: The Django HttpRequest object
            response: The Django HttpResponse object

        Returns:
            HttpResponse: The response object
        """
        self._reset_role(request)
        return response

    def process_exception(self, request, exception):
        """
        Reset the PostgreSQL role when an exception occurs.

        This ensures the role is reset even if the view raises an exception,
        preventing role leakage in connection pools.

        Args:
            request: The Django HttpRequest object
            exception: The exception that was raised

        Returns:
            None (doesn't suppress the exception)
        """
        self._reset_role(request)
        return None  # Don't suppress the exception

    def _reset_role(self, request=None):
        """
        Helper method to reset the PostgreSQL role.

        Args:
            request: Optional Django request object for audit logging
        """
        try:
            with connection.cursor() as cursor:
                # Use shared SQL execution logic
                self._reset_role_sql(cursor)
                if self.enable_audit_log:
                    self._audit_log('role_reset', '', '', request)
        except Exception as e:
            logger.warning(f"Error resetting PostgreSQL role: {e}")
            if self.enable_audit_log:
                self._audit_log('role_reset_failed', '', '', request, error=e)
            # Don't fail the response if role reset fails


@contextmanager
def rls_role(role_name, user_id=None, session_uid_variable='app.current_user_id',
             valid_roles=None):
    """
    Context manager for explicit PostgreSQL role switching with RLS.

    This allows you to temporarily switch to a specific PostgreSQL role
    and optionally set a user ID for the duration of a code block.

    IMPORTANT: Nested usage is not supported. This context manager will raise
    an error if you attempt to switch roles when already in an application role
    (e.g., app_user, app_staff). Role switching should only happen from the
    database owner/connection user.

    Implementation Note:
    ---------------------
    The context manager creates a transaction/savepoint and uses SET LOCAL ROLE.
    When the transaction ends (commit or rollback), PostgreSQL automatically
    restores the role. No manual cleanup is needed.

    Args:
        role_name: PostgreSQL role name to switch to
        user_id: Optional user ID to set in session variable
        session_uid_variable: Session variable name for user ID (default: 'app.current_user_id')
        valid_roles: Optional set/list of valid roles for validation
                     If None, no validation is performed

    Yields:
        None

    Raises:
        ValueError: If role_name is not in valid_roles (when provided)
        RuntimeError: If attempting to switch roles when already in an application role
        ImproperlyConfigured: If configuration is invalid

    Example:
        # Basic usage (automatically creates transaction)
        with rls_role('app_user'):
            # All queries here execute as app_user
            MyModel.objects.all()

        # With user ID
        with rls_role('app_user', user_id=123):
            # Queries execute as app_user with user_id=123 in session
            MyModel.objects.filter(owner_id=123)

        # With validation
        valid_roles = {'app_user', 'app_staff', 'app_superuser'}
        with rls_role('app_user', valid_roles=valid_roles):
            MyModel.objects.all()

        # INVALID - Nested usage not allowed
        with rls_role('app_user'):
            with rls_role('app_staff'):  # Raises RuntimeError!
                pass
    """
    # Validate role if valid_roles provided - use shared validation logic
    if valid_roles is not None:
        role_name = _validate_role_name(role_name, valid_roles)

    # Sanitize user_id - use shared sanitization logic
    user_id_str = _sanitize_user_id(user_id)

    # Always use atomic with savepoint=True to ensure SET LOCAL ROLE works
    with transaction.atomic(savepoint=True):
        with connection.cursor() as cursor:
            # Check current role - prevent nested role switching
            cursor.execute("SELECT current_user")
            current_role = cursor.fetchone()[0]

            # Get database user from settings for comparison
            db_user = connection.settings_dict.get('USER', '')

            # If we're not the database owner, we're likely in an application role
            # Application roles (app_user, app_staff, etc.) should not be able to switch roles
            if current_role != db_user and current_role.startswith('app_'):
                raise RuntimeError(
                    f"Cannot switch roles when already in application role '{current_role}'. "
                    f"Nested rls_role() usage is not supported. "
                    f"Role switching should only happen from the database owner role ('{db_user}')."
                )

            logger.debug(
                f"RLS Context: Switching from '{current_role}' to '{role_name}' "
                f"(in_transaction={connection.in_atomic_block})"
            )

            # Use shared SQL execution logic for consistency with middleware
            _execute_set_role(cursor, role_name, user_id_str, session_uid_variable)
            logger.debug(f"RLS Context: Role set to '{role_name}'")

        # Yield control to the caller
        # When transaction/savepoint ends, role is automatically restored by PostgreSQL
        yield

    # No manual cleanup needed - transaction end handles role restoration
    logger.debug(f"RLS Context: Exited, role automatically restored by transaction end")
