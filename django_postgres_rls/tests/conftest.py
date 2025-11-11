"""
Pytest configuration for django-postgres-rls tests.

Configuration is handled via django_postgres_rls.tests.test_settings module.
"""

import os
import pytest
from typing import Generator, Dict, Optional

# pytest-django will automatically configure Django using the
# DJANGO_SETTINGS_MODULE specified in pytest.ini


def _is_testcontainers_available() -> bool:
    """Check if testcontainers is available."""
    try:
        import testcontainers  # noqa: F401
        return True
    except ImportError:
        return False


@pytest.fixture(scope="session")
def postgres_container():
    """
    Provide a PostgreSQL container for integration tests.

    Uses testcontainers if available, otherwise tries to use
    environment-configured PostgreSQL database.

    Environment variables for using existing PostgreSQL:
    - POSTGRES_HOST: PostgreSQL host (default: localhost)
    - POSTGRES_PORT: PostgreSQL port (default: 5432)
    - POSTGRES_USER: PostgreSQL user (default: postgres)
    - POSTGRES_PASSWORD: PostgreSQL password (default: postgres)
    - POSTGRES_DB: PostgreSQL database (default: test_rls)
    - USE_EXISTING_POSTGRES: Set to '1' to skip testcontainers
    """
    use_existing = os.environ.get('USE_EXISTING_POSTGRES', '').lower() in ('1', 'true', 'yes')

    if use_existing or not _is_testcontainers_available():
        # Use existing PostgreSQL from environment
        connection_params = {
            'host': os.environ.get('POSTGRES_HOST', 'localhost'),
            'port': int(os.environ.get('POSTGRES_PORT', '5432')),
            'user': os.environ.get('POSTGRES_USER', 'postgres'),
            'password': os.environ.get('POSTGRES_PASSWORD', 'postgres'),
            'dbname': os.environ.get('POSTGRES_DB', 'test_rls'),
        }

        # Build database URL
        db_url = (
            f"postgresql://{connection_params['user']}:{connection_params['password']}"
            f"@{connection_params['host']}:{connection_params['port']}"
            f"/{connection_params['dbname']}"
        )

        yield {
            'url': db_url,
            'params': connection_params,
            'container': None,
        }
    else:
        # Use testcontainers
        from testcontainers.postgres import PostgresContainer

        # Use PostgreSQL 16 by default, can be overridden with POSTGRES_VERSION
        postgres_version = os.environ.get('POSTGRES_VERSION', '16')

        with PostgresContainer(f"postgres:{postgres_version}") as postgres:
            connection_params = {
                'host': postgres.get_container_host_ip(),
                'port': postgres.get_exposed_port(5432),
                'user': postgres.username,
                'password': postgres.password,
                'dbname': postgres.dbname,
            }

            yield {
                'url': postgres.get_connection_url(),
                'params': connection_params,
                'container': postgres,
            }


@pytest.fixture(scope="session")
def postgres_db_url(postgres_container: Dict) -> str:
    """Get PostgreSQL database URL."""
    return postgres_container['url']


@pytest.fixture(scope="session")
def postgres_connection_params(postgres_container: Dict) -> Dict[str, any]:
    """Get PostgreSQL connection parameters."""
    return postgres_container['params']


@pytest.fixture(scope="session", autouse=True)
def configure_postgres_for_all_tests(postgres_container: Dict):
    """
    Configure Django to use PostgreSQL from testcontainers/environment for ALL tests.

    This is an autouse fixture that ensures unit tests and integration tests
    both use the same PostgreSQL instance.
    """
    from django.conf import settings

    # Update database configuration with postgres_container parameters
    settings.DATABASES['default'].update({
        'NAME': postgres_container['params']['dbname'],
        'USER': postgres_container['params']['user'],
        'PASSWORD': postgres_container['params']['password'],
        'HOST': postgres_container['params']['host'],
        'PORT': postgres_container['params']['port'],
    })

    return postgres_container


@pytest.fixture(scope="function")
def postgres_db(postgres_container: Dict, django_db_setup, django_db_blocker):
    """
    Provide a clean PostgreSQL database for each test.

    This fixture:
    1. Configures Django to use the test PostgreSQL database
    2. Runs migrations
    3. Yields control to the test
    4. Cleans up after the test
    """
    from django.conf import settings
    from django.core.management import call_command
    from django.db import connections, connection

    # Configure Django database settings
    db_config = {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': postgres_container['params']['dbname'],
        'USER': postgres_container['params']['user'],
        'PASSWORD': postgres_container['params']['password'],
        'HOST': postgres_container['params']['host'],
        'PORT': postgres_container['params']['port'],
        'ATOMIC_REQUESTS': True,  # Required for RLS
        'CONN_MAX_AGE': 0,  # Don't persist connections
    }

    # Update settings
    with django_db_blocker.unblock():
        settings.DATABASES['default'] = db_config

        # Force connection reload
        if 'default' in connections:
            connections['default'].close()
            del connections.databases['default']

        # Run migrations
        call_command('migrate', '--run-syncdb', verbosity=0, interactive=False)

        yield connection

        # Cleanup is handled by Django's test framework


@pytest.fixture(scope="function")
def postgres_test_roles(postgres_db):
    """
    Create test PostgreSQL roles for RLS testing.

    Creates the following roles:
    - app_user: Basic user role
    - app_staff: Staff user role
    - app_superuser: Superuser role

    These roles are granted to the current database user so they can be switched to.
    """
    from django.db import connection

    test_roles = ['app_user', 'app_staff', 'app_superuser']
    current_user = connection.settings_dict['USER']

    with connection.cursor() as cursor:
        # Create roles if they don't exist
        for role in test_roles:
            cursor.execute(f"""
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{role}') THEN
                        CREATE ROLE {role};
                    END IF;
                END
                $$;
            """)

            # Grant role to current user
            cursor.execute(f"GRANT {role} TO {current_user}")

        # Grant necessary permissions to roles
        cursor.execute("""
            GRANT USAGE ON SCHEMA public TO app_user, app_staff, app_superuser;
            GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public
                TO app_user, app_staff, app_superuser;
            GRANT SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public
                TO app_user, app_staff, app_superuser;
        """)

    yield test_roles

    # Cleanup: Reset role and optionally drop roles
    with connection.cursor() as cursor:
        cursor.execute("RESET ROLE")

        # In production tests, we might want to keep roles
        # For now, we'll revoke grants but not drop roles
        for role in test_roles:
            try:
                cursor.execute(f"REVOKE {role} FROM {current_user}")
            except Exception:
                pass  # Ignore errors during cleanup


@pytest.fixture
def integration_test_models(postgres_db, postgres_test_roles):
    """
    Create test models for integration testing.

    This fixture creates Django models and applies them to the test database.
    """
    from django.apps import apps
    from django.db import connection, models
    from django_postgres_rls import RLSModel, RlsPolicy, PolicyCommand, CurrentUserId
    from django.db.models import Q, F

    # Create a test model dynamically
    class Document(RLSModel, models.Model):
        title = models.CharField(max_length=200)
        owner_id = models.IntegerField()
        is_public = models.BooleanField(default=False)

        class Meta:
            app_label = 'tests'
            db_table = 'test_document'
            rls_policies = [
                # Users can see public documents or their own
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.SELECT,
                    using=Q(is_public=True) | Q(owner_id=CurrentUserId())
                ),
                # Staff can see all
                RlsPolicy(
                    role_name='app_staff',
                    command=PolicyCommand.ALL,
                    using='true'
                ),
            ]

    # Create table
    with connection.schema_editor() as schema_editor:
        schema_editor.create_model(Document)

    yield {'Document': Document}

    # Cleanup
    with connection.schema_editor() as schema_editor:
        schema_editor.delete_model(Document)
