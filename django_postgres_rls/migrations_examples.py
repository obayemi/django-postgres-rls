"""
Example Django migrations for setting up RLS authentication functions.

These examples show how to create SECURITY DEFINER functions for authentication
that can be called by the anonymous role before role switching occurs.

Usage:
    Copy the appropriate migration code to your Django app's migrations folder
    and customize as needed.
"""

from django.db import migrations
from django_postgres_rls import get_auth_function_sql, get_user_fetch_function_sql


class Migration(migrations.Migration):
    """
    Example migration for creating RLS authentication function.

    This migration creates a SECURITY DEFINER function that allows
    the anonymous role to authenticate users.
    """

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),  # Adjust based on your Django version
    ]

    operations = [
        # Option 1: Simple authentication function (just checks if user exists)
        migrations.RunSQL(
            sql=get_auth_function_sql(
                user_table='auth_user',
                schema='public',
                function_name='authenticate_user'
            ),
            reverse_sql="""
                DROP FUNCTION IF EXISTS public.authenticate_user(TEXT, TEXT);
            """
        ),

        # Option 2: User fetch function (returns user data for Python password verification)
        migrations.RunSQL(
            sql=get_user_fetch_function_sql(
                user_table='auth_user',
                schema='public',
                function_name='get_user_for_auth'
            ),
            reverse_sql="""
                DROP FUNCTION IF EXISTS public.get_user_for_auth(TEXT);
            """
        ),
    ]


# Example: Custom migration with additional security
class MigrationWithAuditLog(migrations.Migration):
    """
    Example migration that includes audit logging for authentication attempts.
    """

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        # Create audit log table
        migrations.RunSQL(
            sql="""
                CREATE TABLE IF NOT EXISTS public.auth_audit_log (
                    id SERIAL PRIMARY KEY,
                    username TEXT NOT NULL,
                    success BOOLEAN NOT NULL,
                    ip_address INET,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                -- Grant insert permission to anonymous role
                GRANT INSERT ON public.auth_audit_log TO app_anonymous;
                GRANT USAGE, SELECT ON SEQUENCE public.auth_audit_log_id_seq TO app_anonymous;
            """,
            reverse_sql="""
                DROP TABLE IF EXISTS public.auth_audit_log;
            """
        ),

        # Create authentication function with audit logging
        migrations.RunSQL(
            sql="""
                CREATE OR REPLACE FUNCTION public.authenticate_user_with_audit(
                    p_username TEXT,
                    p_password TEXT,
                    p_ip_address INET DEFAULT NULL
                ) RETURNS INTEGER
                SECURITY DEFINER
                LANGUAGE plpgsql
                AS $$
                DECLARE
                    v_user_id INTEGER;
                    v_is_active BOOLEAN;
                    v_success BOOLEAN := false;
                BEGIN
                    -- Get user by username or email
                    SELECT id, is_active
                    INTO v_user_id, v_is_active
                    FROM public.auth_user
                    WHERE (username = p_username OR email = p_username)
                    LIMIT 1;

                    -- Check if user exists and is active
                    IF v_user_id IS NOT NULL AND v_is_active THEN
                        v_success := true;
                    END IF;

                    -- Log authentication attempt
                    INSERT INTO public.auth_audit_log (username, success, ip_address)
                    VALUES (p_username, v_success, p_ip_address);

                    -- Return user ID if successful
                    IF v_success THEN
                        RETURN v_user_id;
                    ELSE
                        RETURN NULL;
                    END IF;
                END;
                $$;

                -- Grant execute permission to anonymous role
                GRANT EXECUTE ON FUNCTION public.authenticate_user_with_audit(TEXT, TEXT, INET) TO app_anonymous;
                REVOKE ALL ON FUNCTION public.authenticate_user_with_audit(TEXT, TEXT, INET) FROM PUBLIC;
            """,
            reverse_sql="""
                DROP FUNCTION IF EXISTS public.authenticate_user_with_audit(TEXT, TEXT, INET);
            """
        ),
    ]


# Example: Migration for custom user model
class MigrationForCustomUserModel(migrations.Migration):
    """
    Example migration for projects using a custom user model.
    """

    dependencies = [
        ('myapp', '0001_initial'),  # Your custom user model migration
    ]

    operations = [
        migrations.RunSQL(
            sql=get_user_fetch_function_sql(
                user_table='myapp_customuser',  # Your custom user table name
                schema='public',
                function_name='get_user_for_auth'
            ),
            reverse_sql="""
                DROP FUNCTION IF EXISTS public.get_user_for_auth(TEXT);
            """
        ),
    ]


# Example: Migration with rate limiting
class MigrationWithRateLimiting(migrations.Migration):
    """
    Example migration with rate limiting for authentication attempts.
    """

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        # Create rate limit tracking table
        migrations.RunSQL(
            sql="""
                CREATE TABLE IF NOT EXISTS public.auth_rate_limit (
                    username TEXT NOT NULL,
                    attempt_count INTEGER DEFAULT 0,
                    last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    locked_until TIMESTAMP,
                    PRIMARY KEY (username)
                );

                GRANT SELECT, INSERT, UPDATE, DELETE ON public.auth_rate_limit TO app_anonymous;
            """,
            reverse_sql="""
                DROP TABLE IF EXISTS public.auth_rate_limit;
            """
        ),

        # Create authentication function with rate limiting
        migrations.RunSQL(
            sql="""
                CREATE OR REPLACE FUNCTION public.authenticate_user_with_rate_limit(
                    p_username TEXT,
                    p_password TEXT
                ) RETURNS INTEGER
                SECURITY DEFINER
                LANGUAGE plpgsql
                AS $$
                DECLARE
                    v_user_id INTEGER;
                    v_is_active BOOLEAN;
                    v_attempt_count INTEGER;
                    v_locked_until TIMESTAMP;
                    v_max_attempts INTEGER := 5;
                    v_lockout_minutes INTEGER := 15;
                BEGIN
                    -- Check rate limit
                    SELECT attempt_count, locked_until
                    INTO v_attempt_count, v_locked_until
                    FROM public.auth_rate_limit
                    WHERE username = p_username;

                    -- Check if account is locked
                    IF v_locked_until IS NOT NULL AND v_locked_until > CURRENT_TIMESTAMP THEN
                        RAISE LOG 'Account locked for user: %', p_username;
                        RETURN NULL;
                    END IF;

                    -- Get user
                    SELECT id, is_active
                    INTO v_user_id, v_is_active
                    FROM public.auth_user
                    WHERE (username = p_username OR email = p_username)
                    AND is_active = true
                    LIMIT 1;

                    -- If user exists, return user ID (password verification in Python)
                    IF v_user_id IS NOT NULL THEN
                        -- Reset attempt count on success
                        DELETE FROM public.auth_rate_limit WHERE username = p_username;
                        RETURN v_user_id;
                    ELSE
                        -- Increment attempt count
                        INSERT INTO public.auth_rate_limit (username, attempt_count, last_attempt)
                        VALUES (p_username, 1, CURRENT_TIMESTAMP)
                        ON CONFLICT (username) DO UPDATE
                        SET attempt_count = auth_rate_limit.attempt_count + 1,
                            last_attempt = CURRENT_TIMESTAMP,
                            locked_until = CASE
                                WHEN auth_rate_limit.attempt_count + 1 >= v_max_attempts
                                THEN CURRENT_TIMESTAMP + (v_lockout_minutes || ' minutes')::INTERVAL
                                ELSE NULL
                            END;

                        RETURN NULL;
                    END IF;
                END;
                $$;

                GRANT EXECUTE ON FUNCTION public.authenticate_user_with_rate_limit(TEXT, TEXT) TO app_anonymous;
                REVOKE ALL ON FUNCTION public.authenticate_user_with_rate_limit(TEXT, TEXT) FROM PUBLIC;
            """,
            reverse_sql="""
                DROP FUNCTION IF EXISTS public.authenticate_user_with_rate_limit(TEXT, TEXT);
            """
        ),
    ]


# Settings configuration example
SETTINGS_EXAMPLE = """
# settings.py

# Authentication backends
AUTHENTICATION_BACKENDS = [
    # RLS authentication backend (recommended for RLS setups)
    'django_postgres_rls.RLSAuthenticationBackendWithPythonVerification',

    # Fallback to default Django backend
    'django.contrib.auth.backends.ModelBackend',
]

# RLS authentication settings
POSTGRES_RLS_AUTH_FUNCTION = 'public.get_user_for_auth'  # Name of SECURITY DEFINER function
POSTGRES_RLS_AUTH_USE_EMAIL = False  # Set to True to use email instead of username

# RLS middleware settings
POSTGRES_RLS_DEFAULT_ANONYMOUS_ROLE = 'app_anonymous'
POSTGRES_RLS_WHITELIST = [
    '/api/auth/login/',
    '/api/auth/register/',
    '/api/auth/token/',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',

    # RLS middleware (must be after AuthenticationMiddleware)
    'myapp.middleware.MyRLSMiddleware',  # Your RLS middleware subclass

    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
"""
