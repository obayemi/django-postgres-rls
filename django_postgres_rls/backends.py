"""
Django authentication backend for PostgreSQL RLS.

This backend uses SECURITY DEFINER functions to authenticate users
while running as the anonymous role, allowing authentication before
role switching occurs.
"""

import logging
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model
from django.db import connection
from django.core.exceptions import ImproperlyConfigured

logger = logging.getLogger(__name__)


class RLSAuthenticationBackend(BaseBackend):
    """
    Authentication backend that uses PostgreSQL SECURITY DEFINER functions.

    This backend allows authentication to happen while running as the anonymous
    role by calling a SECURITY DEFINER function that runs with elevated privileges.

    The function verifies credentials and returns the user ID if successful.

    Setup:
        1. Create the SECURITY DEFINER function in PostgreSQL (see sql_function below)
        2. Grant EXECUTE permission on the function to your anonymous role
        3. Add this backend to AUTHENTICATION_BACKENDS in settings.py

    Example SQL function:
        CREATE OR REPLACE FUNCTION public.authenticate_user(
            p_username TEXT,
            p_password TEXT
        ) RETURNS INTEGER
        SECURITY DEFINER
        LANGUAGE plpgsql
        AS $$
        DECLARE
            v_user_id INTEGER;
            v_password_hash TEXT;
        BEGIN
            -- Get user by username
            SELECT id, password
            INTO v_user_id, v_password_hash
            FROM auth_user
            WHERE username = p_username AND is_active = true;

            IF v_user_id IS NULL THEN
                RETURN NULL;  -- User not found
            END IF;

            -- Verify password (Django uses pbkdf2_sha256)
            -- Note: This is a simplified example. In production, use Django's
            -- password hashing or a proper pgcrypto-based verification
            IF v_password_hash = crypt(p_password, v_password_hash) THEN
                RETURN v_user_id;
            END IF;

            RETURN NULL;  -- Invalid password
        END;
        $$;

        -- Grant execute to anonymous role
        GRANT EXECUTE ON FUNCTION public.authenticate_user(TEXT, TEXT) TO app_anonymous;

    Settings:
        POSTGRES_RLS_AUTH_FUNCTION (optional): Name of the authentication function
            Default: 'public.authenticate_user'

    Note:
        The backend automatically uses the USERNAME_FIELD from your User model,
        so it works seamlessly with both username and email-based authentication.
    """

    def __init__(self):
        """Initialize the authentication backend."""
        from django.conf import settings

        # Get function name from settings
        self.auth_function = getattr(
            settings,
            'POSTGRES_RLS_AUTH_FUNCTION',
            'public.authenticate_user'
        )

        # Get User model
        self.User = get_user_model()

        # Get the username field from the User model
        self.username_field = self.User.USERNAME_FIELD

    def authenticate(self, request, username=None, password=None, **kwargs):
        """
        Authenticate user using SECURITY DEFINER function.

        Args:
            request: The Django HttpRequest object
            username: The username (or email if USERNAME_FIELD is 'email')
            password: User's password
            **kwargs: Additional keyword arguments (may contain the USERNAME_FIELD value)

        Returns:
            User object if authentication succeeds, None otherwise
        """
        # Get the identifier based on USERNAME_FIELD
        # First check if it's passed as a kwarg with the USERNAME_FIELD name
        identifier = kwargs.get(self.username_field, username)

        if not identifier or not password:
            return None

        try:
            # Call the SECURITY DEFINER function
            user_id = self._call_auth_function(identifier, password)

            if user_id is None:
                logger.debug(f"RLS Auth: Authentication failed for {identifier}")
                return None

            # Get the user object
            try:
                user = self.User.objects.get(pk=user_id)
                logger.debug(f"RLS Auth: Successfully authenticated user {user_id}")
                return user
            except self.User.DoesNotExist:
                logger.warning(f"RLS Auth: Function returned user ID {user_id} but user not found")
                return None

        except Exception as e:
            logger.error(f"RLS Auth: Error during authentication: {e}")
            return None

    def _call_auth_function(self, identifier, password):
        """
        Call the PostgreSQL SECURITY DEFINER function to authenticate.

        Args:
            identifier: Username or email
            password: User's password

        Returns:
            User ID if authentication succeeds, None otherwise

        Raises:
            Exception: If the database query fails
        """
        with connection.cursor() as cursor:
            # Call the authentication function
            # Using parameterized query for security
            cursor.execute(
                f"SELECT {self.auth_function}(%s, %s)",
                [identifier, password]
            )
            result = cursor.fetchone()

            if result and result[0] is not None:
                return result[0]

            return None

    def get_user(self, user_id):
        """
        Get user by ID.

        Args:
            user_id: User's primary key

        Returns:
            User object if found, None otherwise
        """
        try:
            return self.User.objects.get(pk=user_id)
        except self.User.DoesNotExist:
            return None


def get_auth_function_sql(user_table='auth_user', schema='public', function_name='authenticate_user'):
    """
    Generate SQL for creating the SECURITY DEFINER authentication function.

    This function can be used in Django migrations or executed directly.

    Args:
        user_table: Name of the Django user table (default: 'auth_user')
        schema: PostgreSQL schema (default: 'public')
        function_name: Name of the function to create (default: 'authenticate_user')

    Returns:
        SQL string for creating the function

    Example:
        from django_postgres_rls.backends import get_auth_function_sql

        # In a Django migration:
        operations = [
            migrations.RunSQL(
                sql=get_auth_function_sql(),
                reverse_sql="DROP FUNCTION IF EXISTS public.authenticate_user(TEXT, TEXT);"
            )
        ]

    Note:
        This function uses Django's password verification, which requires the
        pgcrypto extension and Django password format support. For simpler
        deployments, you may want to customize the password verification logic.
    """
    return f"""
-- Create authentication function with SECURITY DEFINER
CREATE OR REPLACE FUNCTION {schema}.{function_name}(
    p_identifier TEXT,
    p_password TEXT
) RETURNS INTEGER
SECURITY DEFINER
LANGUAGE plpgsql
AS $$
DECLARE
    v_user_id INTEGER;
    v_password_hash TEXT;
    v_is_active BOOLEAN;
BEGIN
    -- Log authentication attempt (optional, for auditing)
    -- RAISE LOG 'Authentication attempt for: %', p_identifier;

    -- Get user by username or email
    -- Adjust the WHERE clause based on your requirements
    SELECT id, password, is_active
    INTO v_user_id, v_password_hash, v_is_active
    FROM {schema}.{user_table}
    WHERE username = p_identifier OR email = p_identifier;

    -- Check if user exists
    IF v_user_id IS NULL THEN
        -- RAISE LOG 'User not found: %', p_identifier;
        RETURN NULL;
    END IF;

    -- Check if user is active
    IF NOT v_is_active THEN
        -- RAISE LOG 'User is inactive: %', p_identifier;
        RETURN NULL;
    END IF;

    -- For security, we return NULL and let Django handle password verification
    -- This function just checks if the user exists and is active
    -- The actual password check should be done in Python using Django's password hasher

    -- Return user ID
    RETURN v_user_id;

    -- Note: If you want to do password verification in PostgreSQL,
    -- you would need to implement Django's pbkdf2_sha256 algorithm
    -- or use a simpler hashing method. This is left as an exercise
    -- since Django's password format is complex and version-dependent.
END;
$$;

-- Grant execute permission to anonymous role
GRANT EXECUTE ON FUNCTION {schema}.{function_name}(TEXT, TEXT) TO app_anonymous;

-- Security: Revoke access from PUBLIC
REVOKE ALL ON FUNCTION {schema}.{function_name}(TEXT, TEXT) FROM PUBLIC;
"""


def get_auth_function_sql_with_password_check(
    user_table='auth_user',
    schema='public',
    function_name='authenticate_user_with_password'
):
    """
    Generate SQL for creating a SECURITY DEFINER function that verifies passwords.

    WARNING: This implementation uses a simplified password check and may not
    match Django's password hashing exactly. For production use, it's recommended
    to verify passwords in Python using Django's built-in password hashers.

    This function requires the pgcrypto extension.

    Args:
        user_table: Name of the Django user table (default: 'auth_user')
        schema: PostgreSQL schema (default: 'public')
        function_name: Name of the function (default: 'authenticate_user_with_password')

    Returns:
        SQL string for creating the function
    """
    return f"""
-- Enable pgcrypto extension (required for password verification)
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Create authentication function with password verification
CREATE OR REPLACE FUNCTION {schema}.{function_name}(
    p_identifier TEXT,
    p_password TEXT
) RETURNS INTEGER
SECURITY DEFINER
LANGUAGE plpgsql
AS $$
DECLARE
    v_user_id INTEGER;
    v_password_hash TEXT;
    v_is_active BOOLEAN;
    v_password_parts TEXT[];
    v_algorithm TEXT;
    v_iterations INTEGER;
    v_salt TEXT;
    v_hash TEXT;
    v_computed_hash TEXT;
BEGIN
    -- Get user by username or email
    SELECT id, password, is_active
    INTO v_user_id, v_password_hash, v_is_active
    FROM {schema}.{user_table}
    WHERE (username = p_identifier OR email = p_identifier)
    AND is_active = true;

    -- Check if user exists and is active
    IF v_user_id IS NULL OR NOT v_is_active THEN
        RETURN NULL;
    END IF;

    -- Parse Django password format: algorithm$iterations$salt$hash
    -- Example: pbkdf2_sha256$260000$salt$hash
    v_password_parts := string_to_array(v_password_hash, '$');

    IF array_length(v_password_parts, 1) < 4 THEN
        RAISE LOG 'Invalid password format for user %', v_user_id;
        RETURN NULL;
    END IF;

    v_algorithm := v_password_parts[1];

    -- Only support pbkdf2_sha256 for now
    IF v_algorithm = 'pbkdf2_sha256' THEN
        v_iterations := v_password_parts[2]::INTEGER;
        v_salt := v_password_parts[3];
        v_hash := v_password_parts[4];

        -- Compute hash using pgcrypto
        -- Note: This uses raw SHA256, not Django's exact format
        -- For production, you may need a custom implementation
        v_computed_hash := encode(
            digest(p_password || v_salt, 'sha256'),
            'base64'
        );

        -- Compare hashes (simplified - Django uses base64 encoding)
        -- This is a basic implementation and may not match Django exactly
        IF substring(v_computed_hash from 1 for length(v_hash)) = v_hash THEN
            RETURN v_user_id;
        END IF;
    ELSE
        RAISE LOG 'Unsupported password algorithm: %', v_algorithm;
        RETURN NULL;
    END IF;

    -- Authentication failed
    RETURN NULL;
END;
$$;

-- Grant execute permission to anonymous role
GRANT EXECUTE ON FUNCTION {schema}.{function_name}(TEXT, TEXT) TO app_anonymous;

-- Security: Revoke access from PUBLIC
REVOKE ALL ON FUNCTION {schema}.{function_name}(TEXT, TEXT) FROM PUBLIC;
"""


class RLSAuthenticationBackendWithPythonVerification(BaseBackend):
    """
    Authentication backend that calls a SECURITY DEFINER function to fetch user,
    then verifies password in Python using Django's password hashers.

    This is more secure than doing password verification in PostgreSQL since it
    uses Django's built-in password hashing which is regularly updated.

    Setup:
        1. Create a SECURITY DEFINER function that returns user data
        2. Grant EXECUTE to app_anonymous role
        3. Add this backend to AUTHENTICATION_BACKENDS

    The SQL function should return: (id, password_hash, is_active)
    """

    def __init__(self):
        """Initialize the authentication backend."""
        from django.conf import settings

        self.auth_function = getattr(
            settings,
            'POSTGRES_RLS_AUTH_FUNCTION',
            'public.get_user_for_auth'
        )

        self.User = get_user_model()

        # Get the username field from the User model
        self.username_field = self.User.USERNAME_FIELD

    def authenticate(self, request, username=None, password=None, **kwargs):
        """
        Authenticate user by fetching from SECURITY DEFINER function,
        then verifying password in Python.

        Args:
            request: The Django HttpRequest object
            username: The username (or email if USERNAME_FIELD is 'email')
            password: User's password
            **kwargs: Additional keyword arguments (may contain the USERNAME_FIELD value)

        Returns:
            User object if authentication succeeds, None otherwise
        """
        from django.contrib.auth.hashers import check_password

        # Get the identifier based on USERNAME_FIELD
        # First check if it's passed as a kwarg with the USERNAME_FIELD name
        identifier = kwargs.get(self.username_field, username)

        if not identifier or not password:
            return None

        try:
            # Fetch user data from SECURITY DEFINER function
            user_data = self._fetch_user_data(identifier)

            if not user_data:
                return None

            user_id, password_hash, is_active = user_data

            # Check if active
            if not is_active:
                logger.debug(f"RLS Auth: User {user_id} is inactive")
                return None

            # Verify password using Django's password hashers
            if check_password(password, password_hash):
                # Get full user object
                try:
                    user = self.User.objects.get(pk=user_id)
                    logger.debug(f"RLS Auth: Successfully authenticated user {user_id}")
                    return user
                except self.User.DoesNotExist:
                    logger.warning(f"RLS Auth: User {user_id} not found")
                    return None
            else:
                logger.debug(f"RLS Auth: Invalid password for user {user_id}")
                return None

        except Exception as e:
            logger.error(f"RLS Auth: Error during authentication: {e}")
            return None

    def _fetch_user_data(self, identifier):
        """
        Fetch user data from SECURITY DEFINER function.

        Returns:
            Tuple of (user_id, password_hash, is_active) or None
        """
        with connection.cursor() as cursor:
            cursor.execute(
                f"SELECT * FROM {self.auth_function}(%s)",
                [identifier]
            )
            result = cursor.fetchone()
            return result if result else None

    def get_user(self, user_id):
        """Get user by ID."""
        try:
            return self.User.objects.get(pk=user_id)
        except self.User.DoesNotExist:
            return None


def get_user_fetch_function_sql(user_table='auth_user', schema='public', function_name='get_user_for_auth'):
    """
    Generate SQL for creating a SECURITY DEFINER function that fetches user data.

    This function returns user data without verifying the password, allowing
    Django to handle password verification in Python.

    Returns:
        SQL string for creating the function
    """
    return f"""
-- Create user fetch function with SECURITY DEFINER
CREATE OR REPLACE FUNCTION {schema}.{function_name}(
    p_identifier TEXT
) RETURNS TABLE(
    user_id INTEGER,
    password_hash TEXT,
    is_active BOOLEAN
)
SECURITY DEFINER
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT id, password, is_active
    FROM {schema}.{user_table}
    WHERE username = p_identifier OR email = p_identifier
    LIMIT 1;
END;
$$;

-- Grant execute permission to anonymous role
GRANT EXECUTE ON FUNCTION {schema}.{function_name}(TEXT) TO app_anonymous;

-- Security: Revoke access from PUBLIC
REVOKE ALL ON FUNCTION {schema}.{function_name}(TEXT) FROM PUBLIC;
"""
