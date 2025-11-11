"""
Django PostgreSQL RLS Management Utilities.

This module provides utilities for generating migration code and managing
RLS policies programmatically.
"""

from typing import List, Type, Optional, Tuple
from django.db import models, connection
from django.db.migrations.operations.base import Operation


def generate_rls_migration_operations(
    model: Type[models.Model],
    enable_rls: bool = True,
    force_rls: bool = True,
    create_policies: bool = True,
    reverse: bool = True
) -> List[Operation]:
    """
    Generate Django migration operations for enabling RLS and creating policies.

    This function generates a list of migration operations that can be added
    to a Django migration file to enable RLS on a table and create all policies
    defined in the model's Meta.rls_policies.

    Args:
        model: Django model class with RLSModel mixin
        enable_rls: Whether to enable RLS on the table
        force_rls: Whether to force RLS (applies to table owner too)
        create_policies: Whether to create the RLS policies
        reverse: Whether to include reverse SQL for migration rollback

    Returns:
        List of Django migration operations

    Example:
        # In your migration file
        from django_postgres_rls import generate_rls_migration_operations
        from myapp.models import MyModel

        class Migration(migrations.Migration):
            operations = [
                *generate_rls_migration_operations(MyModel),
            ]
    """
    from django.db import migrations

    operations = []
    table_name = model._meta.db_table

    # Operation 1: Enable RLS on the table
    if enable_rls:
        sql_parts = []
        reverse_sql_parts = []

        if enable_rls:
            sql_parts.append(f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY;")
            reverse_sql_parts.append(f"ALTER TABLE {table_name} DISABLE ROW LEVEL SECURITY;")

        if force_rls:
            sql_parts.append(f"ALTER TABLE {table_name} FORCE ROW LEVEL SECURITY;")
            reverse_sql_parts.append(f"ALTER TABLE {table_name} NO FORCE ROW LEVEL SECURITY;")

        operations.append(
            migrations.RunSQL(
                sql="\n".join(sql_parts),
                reverse_sql="\n".join(reverse_sql_parts) if reverse else None
            )
        )

    # Operation 2: Create policies
    if create_policies:
        policy_sql_statements = model.get_policy_sql()

        if policy_sql_statements:
            # Get policy names for reverse SQL
            policy_names = []
            for idx in range(len(model.get_rls_policies())):
                policy_name = f"{table_name}_policy_{idx}"
                policy_names.append(policy_name)

            # Generate reverse SQL (DROP POLICY)
            reverse_sql_parts = []
            for policy_name in policy_names:
                reverse_sql_parts.append(f"DROP POLICY IF EXISTS {policy_name} ON {table_name};")

            operations.append(
                migrations.RunSQL(
                    sql="\n\n".join(policy_sql_statements),
                    reverse_sql="\n".join(reverse_sql_parts) if reverse else None
                )
            )

    return operations


def generate_rls_migration_code(
    model: Type[models.Model],
    enable_rls: bool = True,
    force_rls: bool = True,
    create_policies: bool = True,
    reverse: bool = True
) -> str:
    """
    Generate migration code as a string for copying into a migration file.

    This is useful for quickly generating migration code that can be
    copy-pasted into a migration file.

    Args:
        model: Django model class with RLSModel mixin
        enable_rls: Whether to enable RLS on the table
        force_rls: Whether to force RLS (applies to table owner too)
        create_policies: Whether to create the RLS policies
        reverse: Whether to include reverse SQL for migration rollback

    Returns:
        String containing the migration code

    Example:
        from myapp.models import MyModel
        from django_postgres_rls import generate_rls_migration_code

        print(generate_rls_migration_code(MyModel))
    """
    from django.db import migrations

    table_name = model._meta.db_table
    app_label = model._meta.app_label
    model_name = model.__name__

    lines = [
        "from django.db import migrations",
        "",
        "",
        "class Migration(migrations.Migration):",
        f"    dependencies = [",
        f"        ('{app_label}', 'XXXX_previous_migration'),",
        f"    ]",
        "",
        "    operations = [",
    ]

    # Add RLS enable operation
    if enable_rls:
        sql_parts = []
        reverse_sql_parts = []

        if enable_rls:
            sql_parts.append(f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY;")
            reverse_sql_parts.append(f"ALTER TABLE {table_name} DISABLE ROW LEVEL SECURITY;")

        if force_rls:
            sql_parts.append(f"ALTER TABLE {table_name} FORCE ROW LEVEL SECURITY;")
            reverse_sql_parts.append(f"ALTER TABLE {table_name} NO FORCE ROW LEVEL SECURITY;")

        lines.append("        migrations.RunSQL(")
        lines.append('            sql="""')
        for sql in sql_parts:
            lines.append(f"            {sql}")
        lines.append('            """,')

        if reverse:
            lines.append('            reverse_sql="""')
            for sql in reverse_sql_parts:
                lines.append(f"            {sql}")
            lines.append('            """')

        lines.append("        ),")

    # Add policy creation operation
    if create_policies:
        policy_sql_statements = model.get_policy_sql()

        if policy_sql_statements:
            lines.append("        migrations.RunSQL(")
            lines.append('            sql="""')
            for stmt in policy_sql_statements:
                lines.append(f"            {stmt}")
                lines.append("")
            lines.append('            """,')

            if reverse:
                # Generate reverse SQL (DROP POLICY)
                lines.append('            reverse_sql="""')
                for idx in range(len(model.get_rls_policies())):
                    policy_name = f"{table_name}_policy_{idx}"
                    lines.append(f"            DROP POLICY IF EXISTS {policy_name} ON {table_name};")
                lines.append('            """')

            lines.append("        ),")

    lines.append("    ]")

    return "\n".join(lines)


class CreateRLSPoliciesOperation(Operation):
    """
    Custom migration operation for creating RLS policies from a model.

    This is a reusable migration operation that can be used in migration files
    to create RLS policies for a model.

    Example:
        from django_postgres_rls import CreateRLSPoliciesOperation

        class Migration(migrations.Migration):
            operations = [
                CreateRLSPoliciesOperation(
                    model_name='MyModel',
                    app_label='myapp',
                ),
            ]
    """

    reversible = True

    def __init__(self, model_name: str, app_label: str):
        """
        Initialize the operation.

        Args:
            model_name: Name of the model class
            app_label: Django app label containing the model
        """
        self.model_name = model_name
        self.app_label = app_label

    def state_forwards(self, app_label, state):
        """No state changes needed."""
        pass

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        """Create RLS policies."""
        # Get the model class
        model = to_state.apps.get_model(self.app_label, self.model_name)

        # Generate and execute policy SQL
        policy_sql_statements = model.get_policy_sql()

        with schema_editor.connection.cursor() as cursor:
            for sql in policy_sql_statements:
                cursor.execute(sql)

    def database_backwards(self, app_label, schema_editor, from_state, to_state):
        """Drop RLS policies."""
        model = from_state.apps.get_model(self.app_label, self.model_name)
        table_name = model._meta.db_table

        # Generate DROP POLICY statements
        with schema_editor.connection.cursor() as cursor:
            for idx in range(len(model.get_rls_policies())):
                policy_name = f"{table_name}_policy_{idx}"
                cursor.execute(f"DROP POLICY IF EXISTS {policy_name} ON {table_name}")

    def describe(self):
        """Return a description of the operation."""
        return f"Create RLS policies for {self.app_label}.{self.model_name}"


class EnableRLSOperation(Operation):
    """
    Custom migration operation for enabling RLS on a model's table.

    Example:
        from django_postgres_rls import EnableRLSOperation

        class Migration(migrations.Migration):
            operations = [
                EnableRLSOperation(
                    model_name='MyModel',
                    app_label='myapp',
                    force=True,
                ),
            ]
    """

    reversible = True

    def __init__(self, model_name: str, app_label: str, force: bool = True):
        """
        Initialize the operation.

        Args:
            model_name: Name of the model class
            app_label: Django app label containing the model
            force: Whether to force RLS (applies to table owner too)
        """
        self.model_name = model_name
        self.app_label = app_label
        self.force = force

    def state_forwards(self, app_label, state):
        """No state changes needed."""
        pass

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        """Enable RLS on the table."""
        model = to_state.apps.get_model(self.app_label, self.model_name)
        table_name = model._meta.db_table

        with schema_editor.connection.cursor() as cursor:
            cursor.execute(f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY")
            if self.force:
                cursor.execute(f"ALTER TABLE {table_name} FORCE ROW LEVEL SECURITY")

    def database_backwards(self, app_label, schema_editor, from_state, to_state):
        """Disable RLS on the table."""
        model = from_state.apps.get_model(self.app_label, self.model_name)
        table_name = model._meta.db_table

        with schema_editor.connection.cursor() as cursor:
            cursor.execute(f"ALTER TABLE {table_name} DISABLE ROW LEVEL SECURITY")
            if self.force:
                cursor.execute(f"ALTER TABLE {table_name} NO FORCE ROW LEVEL SECURITY")

    def describe(self):
        """Return a description of the operation."""
        force_text = " (FORCE)" if self.force else ""
        return f"Enable RLS{force_text} on {self.app_label}.{self.model_name}"


def apply_rls_policies(model: Type[models.Model], verbosity: int = 1) -> Tuple[int, int]:
    """
    Apply RLS policies for a model to the database.

    This function enables RLS on the table and creates all policies defined
    in the model's Meta.rls_policies. This can be used in management commands
    or signal handlers.

    Args:
        model: Django model class with RLSModel mixin
        verbosity: Verbosity level (0=silent, 1=normal, 2=verbose)

    Returns:
        Tuple of (policies_created, policies_skipped)

    Example:
        from myapp.models import MyModel
        from django_postgres_rls import apply_rls_policies

        apply_rls_policies(MyModel, verbosity=2)
    """
    from psycopg2 import sql
    from .models import PolicyCommand

    table_name = model._meta.db_table
    policies_created = 0
    policies_skipped = 0

    with connection.cursor() as cursor:
        # Enable RLS on the table
        if verbosity >= 1:
            print(f"Enabling RLS on {table_name}...")

        cursor.execute(f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY")
        cursor.execute(f"ALTER TABLE {table_name} FORCE ROW LEVEL SECURITY")

        # Create policies
        policy_sql_statements = model.get_policy_sql()

        for idx, sql_stmt in enumerate(policy_sql_statements):
            policy_name = f"{table_name}_policy_{idx}"

            try:
                if verbosity >= 2:
                    print(f"Creating policy {policy_name}...")

                cursor.execute(sql_stmt)
                policies_created += 1

                if verbosity >= 1:
                    print(f"✓ Created policy {policy_name}")

            except Exception as e:
                # Policy might already exist
                if "already exists" in str(e).lower():
                    policies_skipped += 1
                    if verbosity >= 1:
                        print(f"⊘ Policy {policy_name} already exists, skipping")
                else:
                    # Re-raise if it's a different error
                    if verbosity >= 1:
                        print(f"✗ Error creating policy {policy_name}: {e}")
                    raise

        # Grant table-level permissions to roles
        # RLS policies control which ROWS are visible, but roles still need
        # table-level permissions to access the table at all
        if verbosity >= 1:
            print(f"Granting table permissions to roles...")

        # Collect permissions needed for each role
        role_permissions = {}  # role_name -> set of permissions
        for policy in model.get_rls_policies():
            role = policy.role_name
            if not role:
                continue  # Skip PUBLIC policies

            if role not in role_permissions:
                role_permissions[role] = set()

            # Map PolicyCommand to table permissions
            if policy.command == PolicyCommand.ALL:
                role_permissions[role].update(['SELECT', 'INSERT', 'UPDATE', 'DELETE'])
            elif policy.command == PolicyCommand.SELECT:
                role_permissions[role].add('SELECT')
            elif policy.command == PolicyCommand.INSERT:
                role_permissions[role].add('INSERT')
            elif policy.command == PolicyCommand.UPDATE:
                role_permissions[role].add('UPDATE')
            elif policy.command == PolicyCommand.DELETE:
                role_permissions[role].add('DELETE')

        # Grant permissions to each role
        for role, permissions in role_permissions.items():
            if not permissions:
                continue

            try:
                perms_list = ', '.join(sorted(permissions))
                grant_sql = sql.SQL("GRANT {permissions} ON TABLE {table} TO {role}").format(
                    permissions=sql.SQL(perms_list),
                    table=sql.Identifier(table_name),
                    role=sql.Identifier(role)
                )

                if verbosity >= 2:
                    print(f"Granting {perms_list} on {table_name} to {role}...")

                cursor.execute(grant_sql)

                if verbosity >= 1:
                    print(f"✓ Granted {perms_list} on {table_name} to {role}")

            except Exception as e:
                if verbosity >= 1:
                    print(f"✗ Error granting permissions to {role}: {e}")
                # Don't fail if grants fail - might already be granted
                # or role might not exist yet
                pass

    return policies_created, policies_skipped


def drop_rls_policies(model: Type[models.Model], verbosity: int = 1) -> int:
    """
    Drop all RLS policies for a model from the database.

    This function drops all policies defined in the model's Meta.rls_policies
    and optionally disables RLS on the table.

    Args:
        model: Django model class with RLSModel mixin
        verbosity: Verbosity level (0=silent, 1=normal, 2=verbose)

    Returns:
        Number of policies dropped

    Example:
        from myapp.models import MyModel
        from django_postgres_rls import drop_rls_policies

        drop_rls_policies(MyModel, verbosity=2)
    """
    table_name = model._meta.db_table
    policies_dropped = 0

    with connection.cursor() as cursor:
        # Drop policies
        for idx in range(len(model.get_rls_policies())):
            policy_name = f"{table_name}_policy_{idx}"

            try:
                if verbosity >= 2:
                    print(f"Dropping policy {policy_name}...")

                cursor.execute(f"DROP POLICY IF EXISTS {policy_name} ON {table_name}")
                policies_dropped += 1

                if verbosity >= 1:
                    print(f"✓ Dropped policy {policy_name}")

            except Exception as e:
                if verbosity >= 1:
                    print(f"✗ Error dropping policy {policy_name}: {e}")
                raise

    return policies_dropped
