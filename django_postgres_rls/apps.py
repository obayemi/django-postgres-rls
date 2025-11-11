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
        Also processes any pending RLS model registrations from __init_subclass__.
        """
        # Import checks to register them
        from . import checks  # noqa: F401
        # Import signals to register pre_migrate/post_migrate handlers
        from . import signals  # noqa: F401

        # Process any pending RLS model registrations from __init_subclass__
        from django.apps import apps
        if hasattr(apps, '_pending_rls_registrations'):
            for register_func in apps._pending_rls_registrations:
                try:
                    register_func()
                except Exception:
                    # Ignore errors during auto-registration
                    # This can happen if the model isn't fully initialized yet
                    pass
            # Clear the list after processing
            apps._pending_rls_registrations = []
