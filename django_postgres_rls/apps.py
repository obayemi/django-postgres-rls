"""
Django app configuration for django-postgres-rls.
"""

from django.apps import AppConfig


class DjangoPostgresRLSConfig(AppConfig):
    """
    AppConfig for django-postgres-rls package.
    """

    name = 'django_postgres_rls'
    verbose_name = 'Django PostgreSQL RLS'

    def ready(self):
        """
        Called when the app is ready.

        Imports system checks and signal handlers to register them with Django.
        """
        # Import checks to register them
        from . import checks  # noqa: F401
        # Import signals to register pre_migrate/post_migrate handlers
        from . import signals  # noqa: F401
