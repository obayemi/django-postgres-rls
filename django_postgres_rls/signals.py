"""
Django PostgreSQL RLS Signal Handlers.

This module provides signal handlers for automatically applying RLS policies
after migrations and creating PostgreSQL roles before migrations.
"""

import logging
from typing import List, Type, Optional
from django.apps import apps
from django.conf import settings
from django.db import connection
from django.db.models.signals import pre_migrate, post_migrate
from django.dispatch import receiver
from psycopg2 import sql

from .management import apply_rls_policies

logger = logging.getLogger(__name__)


# Registry for models that should have RLS policies auto-applied
_rls_model_registry: List[Type] = []


def register_rls_model(model: Type) -> Type:
    """
    Register a model to have RLS policies automatically applied on post_migrate.

    This is a decorator that can be used on model classes to register them
    for automatic RLS policy application.

    Args:
        model: Django model class with RLSModel mixin

    Returns:
        The model class (unchanged)

    Example:
        from django_postgres_rls import RLSModel, register_rls_model

        @register_rls_model
        class MyModel(RLSModel, models.Model):
            class Meta:
                rls_policies = [...]
    """
    if model not in _rls_model_registry:
        _rls_model_registry.append(model)
    return model


def unregister_rls_model(model: Type) -> None:
    """
    Unregister a model from automatic RLS policy application.

    Args:
        model: Django model class to unregister
    """
    if model in _rls_model_registry:
        _rls_model_registry.remove(model)


def get_registered_models() -> List[Type]:
    """
    Get list of models registered for automatic RLS policy application.

    Returns:
        List of registered model classes
    """
    return _rls_model_registry.copy()


@receiver(pre_migrate)
def auto_create_rls_roles(sender, app_config, verbosity, **kwargs):
    """
    Signal handler to automatically create PostgreSQL roles before migrations.

    This ensures that roles referenced in RLS policies exist before migrations run.
    Roles are created with NOLOGIN and granted to the current database user so the
    application can SET ROLE to them.

    Controlled by POSTGRES_RLS_AUTO_CREATE_ROLES setting (default: True).
    Set to False if roles are managed externally (e.g., by DBAs or IaC tools).

    Args:
        sender: The sender of the signal
        app_config: The AppConfig of the app being migrated
        verbosity: Verbosity level (0-3)
        **kwargs: Additional keyword arguments
    """
    # Only run once per migrate command (not for every app)
    if hasattr(auto_create_rls_roles, '_processed'):
        return
    auto_create_rls_roles._processed = True

    # Check if disabled (defaults to True for best developer experience)
    auto_create_enabled = getattr(settings, 'POSTGRES_RLS_AUTO_CREATE_ROLES', True)
    if not auto_create_enabled:
        if verbosity >= 2:
            logger.info("PostgreSQL RLS: Automatic role creation disabled")
        return

    # Only run for PostgreSQL databases
    if connection.vendor != 'postgresql':
        if verbosity >= 2:
            logger.debug("PostgreSQL RLS: Skipping role creation (not PostgreSQL)")
        return

    # Get configured roles from settings
    valid_roles = getattr(settings, 'POSTGRES_RLS_VALID_ROLES', None)
    if not valid_roles:
        if verbosity >= 2:
            logger.debug("PostgreSQL RLS: No roles configured in POSTGRES_RLS_VALID_ROLES")
        return

    try:
        with connection.cursor() as cursor:
            # Get existing roles from PostgreSQL
            cursor.execute("SELECT rolname FROM pg_roles")
            existing_roles = {row[0] for row in cursor.fetchall()}

            roles_created = []
            roles_skipped = []
            roles_failed = []

            for role in valid_roles:
                if role in existing_roles:
                    roles_skipped.append(role)
                    if verbosity >= 2:
                        logger.info(f"  PostgreSQL role '{role}' already exists")
                    continue

                try:
                    # Create role with NOLOGIN (cannot connect directly to database)
                    cursor.execute(
                        sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(role))
                    )

                    # Grant role to current user so application can SET ROLE to it
                    cursor.execute(
                        sql.SQL("GRANT {} TO CURRENT_USER").format(sql.Identifier(role))
                    )

                    roles_created.append(role)

                    if verbosity >= 2:
                        logger.info(f"  Created PostgreSQL role: {role}")

                except Exception as e:
                    roles_failed.append((role, str(e)))
                    logger.warning(
                        f"  Could not create role '{role}': {e}\n"
                        f"  You may need to create it manually with:\n"
                        f"    CREATE ROLE {role} NOLOGIN;\n"
                        f"    GRANT {role} TO your_app_user;"
                    )

            # Log summary
            if verbosity >= 1:
                if roles_created:
                    logger.info(
                        f"PostgreSQL RLS: Created {len(roles_created)} role(s): "
                        f"{', '.join(roles_created)}"
                    )
                if roles_skipped and verbosity >= 2:
                    logger.info(
                        f"PostgreSQL RLS: Skipped {len(roles_skipped)} existing role(s)"
                    )
                if roles_failed:
                    logger.warning(
                        f"PostgreSQL RLS: Failed to create {len(roles_failed)} role(s). "
                        f"If your app user lacks CREATEROLE privilege, create them manually."
                    )

    except Exception as e:
        # Don't fail migrations if role creation fails - roles might be managed externally
        logger.error(f"PostgreSQL RLS: Error during automatic role creation: {e}")
        if verbosity >= 2:
            import traceback
            traceback.print_exc()


@receiver(post_migrate)
def cleanup_auto_create_flag(sender, **kwargs):
    """
    Clean up the processed flag after migrations complete.

    This allows role creation to run again on the next migrate command.
    """
    if hasattr(auto_create_rls_roles, '_processed'):
        delattr(auto_create_rls_roles, '_processed')


@receiver(post_migrate)
def auto_apply_rls_policies(sender, app_config, verbosity, **kwargs):
    """
    Signal handler to automatically apply RLS policies after migrations.

    This handler is triggered after Django runs migrations. It will:
    1. Find all registered RLS models
    2. Enable RLS on their tables
    3. Create/update their policies

    To use this handler, you need to:
    1. Register your models using @register_rls_model decorator
    2. Ensure this signal handler is connected (it's auto-connected on import)

    Args:
        sender: The sender of the signal
        app_config: The AppConfig of the app being migrated
        verbosity: Verbosity level (0-3)
        **kwargs: Additional keyword arguments
    """
    if not _rls_model_registry:
        return

    # Filter models for this app
    app_models = [
        model for model in _rls_model_registry
        if model._meta.app_label == app_config.label
    ]

    if not app_models:
        return

    if verbosity >= 1:
        logger.info(f"Applying RLS policies for app '{app_config.label}'...")

    total_created = 0
    total_skipped = 0

    for model in app_models:
        model_name = f"{model._meta.app_label}.{model.__name__}"

        try:
            # Check if model has any policies defined
            policies = model.get_rls_policies()
            if not policies:
                if verbosity >= 2:
                    logger.info(f"  {model_name}: No RLS policies defined, skipping")
                continue

            if verbosity >= 1:
                logger.info(f"  {model_name}: Applying RLS policies...")

            created, skipped = apply_rls_policies(model, verbosity=verbosity)
            total_created += created
            total_skipped += skipped

        except Exception as e:
            logger.error(f"  {model_name}: Error applying RLS policies: {e}")
            if verbosity >= 2:
                import traceback
                traceback.print_exc()

    if verbosity >= 1 and (total_created > 0 or total_skipped > 0):
        logger.info(
            f"RLS policy application complete: "
            f"{total_created} created, {total_skipped} skipped"
        )


def setup_rls_for_app(app_label: str, verbosity: int = 1) -> None:
    """
    Manually apply RLS policies for all models in a Django app.

    This can be used in management commands or for manual policy application.

    Args:
        app_label: Django app label (e.g., 'myapp')
        verbosity: Verbosity level (0=silent, 1=normal, 2=verbose)

    Example:
        from django_postgres_rls import setup_rls_for_app

        # In a management command
        setup_rls_for_app('myapp', verbosity=2)
    """
    try:
        app_config = apps.get_app_config(app_label)
    except LookupError:
        logger.error(f"App '{app_label}' not found")
        return

    # Get all models from the app
    models = app_config.get_models()

    # Filter models that have RLS policies
    rls_models = [
        model for model in models
        if hasattr(model, 'get_rls_policies') and model.get_rls_policies()
    ]

    if not rls_models:
        if verbosity >= 1:
            logger.info(f"No RLS models found in app '{app_label}'")
        return

    if verbosity >= 1:
        logger.info(f"Setting up RLS for {len(rls_models)} models in app '{app_label}'...")

    total_created = 0
    total_skipped = 0

    for model in rls_models:
        model_name = f"{model._meta.app_label}.{model.__name__}"

        try:
            if verbosity >= 1:
                logger.info(f"  {model_name}: Applying RLS policies...")

            created, skipped = apply_rls_policies(model, verbosity=verbosity)
            total_created += created
            total_skipped += skipped

        except Exception as e:
            logger.error(f"  {model_name}: Error applying RLS policies: {e}")
            if verbosity >= 2:
                import traceback
                traceback.print_exc()

    if verbosity >= 1:
        logger.info(
            f"RLS setup complete for '{app_label}': "
            f"{total_created} policies created, {total_skipped} skipped"
        )


def setup_rls_for_model(model: Type, verbosity: int = 1) -> None:
    """
    Manually apply RLS policies for a specific model.

    Args:
        model: Django model class with RLSModel mixin
        verbosity: Verbosity level (0=silent, 1=normal, 2=verbose)

    Example:
        from myapp.models import MyModel
        from django_postgres_rls import setup_rls_for_model

        setup_rls_for_model(MyModel, verbosity=2)
    """
    model_name = f"{model._meta.app_label}.{model.__name__}"

    policies = model.get_rls_policies()
    if not policies:
        if verbosity >= 1:
            logger.info(f"{model_name}: No RLS policies defined")
        return

    try:
        if verbosity >= 1:
            logger.info(f"{model_name}: Applying RLS policies...")

        created, skipped = apply_rls_policies(model, verbosity=verbosity)

        if verbosity >= 1:
            logger.info(
                f"{model_name}: {created} policies created, {skipped} skipped"
            )

    except Exception as e:
        logger.error(f"{model_name}: Error applying RLS policies: {e}")
        if verbosity >= 2:
            import traceback
            traceback.print_exc()
        raise
