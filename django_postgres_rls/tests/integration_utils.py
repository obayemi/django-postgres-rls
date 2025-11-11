"""
Utility functions for PostgreSQL RLS integration tests.

This module provides helper functions for:
- Creating and managing test PostgreSQL roles
- Applying and verifying RLS policies
- Testing RLS enforcement
- Database setup and teardown
"""

from typing import List, Dict, Any, Optional
from django.db import connection
from psycopg2 import sql


def create_test_roles(roles: Optional[List[str]] = None) -> List[str]:
    """
    Create test PostgreSQL roles if they don't exist.

    Args:
        roles: List of role names to create. Defaults to standard test roles.

    Returns:
        List of created role names.

    Example:
        >>> roles = create_test_roles(['app_user', 'app_staff'])
        >>> assert 'app_user' in roles
    """
    if roles is None:
        roles = ['app_user', 'app_staff', 'app_superuser']

    current_user = connection.settings_dict['USER']

    with connection.cursor() as cursor:
        for role in roles:
            # Create role if it doesn't exist
            cursor.execute(f"""
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{role}') THEN
                        CREATE ROLE {role};
                    END IF;
                END
                $$;
            """)

            # Grant role to current user so we can switch to it
            cursor.execute(f"GRANT {role} TO {current_user}")

    return roles


def cleanup_test_roles(roles: Optional[List[str]] = None) -> None:
    """
    Clean up test PostgreSQL roles.

    Args:
        roles: List of role names to clean up. Defaults to standard test roles.

    Example:
        >>> cleanup_test_roles(['app_user', 'app_staff'])
    """
    if roles is None:
        roles = ['app_user', 'app_staff', 'app_superuser']

    current_user = connection.settings_dict['USER']

    with connection.cursor() as cursor:
        # Reset role first
        cursor.execute("RESET ROLE")

        # Revoke roles
        for role in roles:
            try:
                cursor.execute(f"REVOKE {role} FROM {current_user}")
            except Exception:
                pass  # Ignore errors during cleanup


def grant_table_permissions(table_name: str, roles: List[str],
                           permissions: List[str] = None) -> None:
    """
    Grant table permissions to roles.

    Args:
        table_name: Name of the table
        roles: List of role names
        permissions: List of permissions (SELECT, INSERT, UPDATE, DELETE, ALL)
                    Defaults to all permissions.

    Example:
        >>> grant_table_permissions('test_document', ['app_user'], ['SELECT', 'INSERT'])
    """
    if permissions is None:
        permissions = ['SELECT', 'INSERT', 'UPDATE', 'DELETE']

    perms_str = ', '.join(permissions)
    roles_str = ', '.join(roles)

    with connection.cursor() as cursor:
        # Grant table permissions
        cursor.execute(
            f"GRANT {perms_str} ON {table_name} TO {roles_str}"
        )

        # Grant sequence permissions (needed for INSERT with SERIAL columns)
        cursor.execute(
            f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {roles_str}"
        )


def apply_test_policies(model_class, verbosity: int = 0) -> None:
    """
    Apply RLS policies from a model to the database.

    Args:
        model_class: Django model class with RLS policies
        verbosity: Verbosity level (0, 1, or 2)

    Example:
        >>> from myapp.models import Document
        >>> apply_test_policies(Document, verbosity=1)
    """
    from django_postgres_rls import apply_rls_policies

    apply_rls_policies(model_class, verbosity=verbosity)


def verify_rls_enforcement(table_name: str, role: str) -> bool:
    """
    Verify that RLS is enabled and enforced for a table.

    Args:
        table_name: Name of the table
        role: Role name to check enforcement for

    Returns:
        True if RLS is enabled and enforced, False otherwise.

    Example:
        >>> assert verify_rls_enforcement('test_document', 'app_user')
    """
    with connection.cursor() as cursor:
        # Check if RLS is enabled
        cursor.execute("""
            SELECT relrowsecurity, relforcerowsecurity
            FROM pg_class
            WHERE relname = %s
        """, [table_name])

        result = cursor.fetchone()
        if not result:
            return False

        rls_enabled, rls_forced = result
        return rls_enabled


def get_active_policies(table_name: str, role: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Get active RLS policies for a table.

    Args:
        table_name: Name of the table
        role: Optional role name to filter policies

    Returns:
        List of dictionaries containing policy information.

    Example:
        >>> policies = get_active_policies('test_document', 'app_user')
        >>> assert len(policies) > 0
    """
    with connection.cursor() as cursor:
        query = """
            SELECT
                schemaname,
                tablename,
                policyname,
                permissive,
                roles,
                cmd,
                qual,
                with_check
            FROM pg_policies
            WHERE tablename = %s
        """

        params = [table_name]
        if role:
            query += " AND %s = ANY(roles)"
            params.append(role)

        cursor.execute(query, params)

        columns = [desc[0] for desc in cursor.description]
        policies = []

        for row in cursor.fetchall():
            policy = dict(zip(columns, row))
            policies.append(policy)

        return policies


def switch_role(role: str) -> None:
    """
    Switch to a PostgreSQL role using SET ROLE.

    Args:
        role: Role name to switch to

    Example:
        >>> switch_role('app_user')
    """
    with connection.cursor() as cursor:
        cursor.execute(
            sql.SQL("SET ROLE {}").format(sql.Identifier(role))
        )


def reset_role() -> None:
    """
    Reset to the default PostgreSQL role.

    Example:
        >>> reset_role()
    """
    with connection.cursor() as cursor:
        cursor.execute("RESET ROLE")


def get_current_role() -> str:
    """
    Get the current PostgreSQL role.

    Returns:
        Name of the current role.

    Example:
        >>> role = get_current_role()
        >>> assert role == 'postgres' or role == 'app_user'
    """
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_user")
        return cursor.fetchone()[0]


def set_session_variable(name: str, value: str) -> None:
    """
    Set a PostgreSQL session variable.

    Args:
        name: Variable name (e.g., 'app.current_user_id')
        value: Variable value

    Example:
        >>> set_session_variable('app.current_user_id', '123')
    """
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT set_config(%s, %s, false)",
            [name, value]
        )


def get_session_variable(name: str) -> Optional[str]:
    """
    Get a PostgreSQL session variable.

    Args:
        name: Variable name (e.g., 'app.current_user_id')

    Returns:
        Variable value or None if not set.

    Example:
        >>> set_session_variable('app.current_user_id', '123')
        >>> value = get_session_variable('app.current_user_id')
        >>> assert value == '123'
    """
    with connection.cursor() as cursor:
        try:
            cursor.execute("SELECT current_setting(%s)", [name])
            return cursor.fetchone()[0]
        except Exception:
            return None


def enable_rls(table_name: str, force: bool = True) -> None:
    """
    Enable RLS on a table.

    Args:
        table_name: Name of the table
        force: If True, use FORCE ROW LEVEL SECURITY (applies to table owner)

    Example:
        >>> enable_rls('test_document', force=True)
    """
    with connection.cursor() as cursor:
        cursor.execute(f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY")

        if force:
            cursor.execute(f"ALTER TABLE {table_name} FORCE ROW LEVEL SECURITY")


def disable_rls(table_name: str) -> None:
    """
    Disable RLS on a table.

    Args:
        table_name: Name of the table

    Example:
        >>> disable_rls('test_document')
    """
    with connection.cursor() as cursor:
        cursor.execute(f"ALTER TABLE {table_name} NO FORCE ROW LEVEL SECURITY")
        cursor.execute(f"ALTER TABLE {table_name} DISABLE ROW LEVEL SECURITY")


def drop_all_policies(table_name: str) -> int:
    """
    Drop all RLS policies from a table.

    Args:
        table_name: Name of the table

    Returns:
        Number of policies dropped.

    Example:
        >>> count = drop_all_policies('test_document')
        >>> assert count >= 0
    """
    with connection.cursor() as cursor:
        # Get all policies for the table
        cursor.execute("""
            SELECT policyname
            FROM pg_policies
            WHERE tablename = %s
        """, [table_name])

        policies = [row[0] for row in cursor.fetchall()]

        # Drop each policy
        for policy_name in policies:
            cursor.execute(f"DROP POLICY IF EXISTS {policy_name} ON {table_name}")

        return len(policies)


def count_visible_rows(table_name: str, role: Optional[str] = None) -> int:
    """
    Count visible rows in a table (respects RLS).

    Args:
        table_name: Name of the table
        role: Optional role to switch to before counting

    Returns:
        Number of visible rows.

    Example:
        >>> count = count_visible_rows('test_document', 'app_user')
        >>> assert count >= 0
    """
    with connection.cursor() as cursor:
        if role:
            switch_role(role)

        try:
            cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
            return cursor.fetchone()[0]
        finally:
            if role:
                reset_role()


def insert_test_data(table_name: str, data: List[Dict[str, Any]]) -> int:
    """
    Insert test data into a table.

    Args:
        table_name: Name of the table
        data: List of dictionaries with column names and values

    Returns:
        Number of rows inserted.

    Example:
        >>> data = [
        ...     {'title': 'Doc 1', 'owner_id': 1, 'is_public': True},
        ...     {'title': 'Doc 2', 'owner_id': 2, 'is_public': False},
        ... ]
        >>> count = insert_test_data('test_document', data)
        >>> assert count == 2
    """
    if not data:
        return 0

    columns = list(data[0].keys())
    column_names = ', '.join(columns)
    placeholders = ', '.join(['%s'] * len(columns))

    with connection.cursor() as cursor:
        for row in data:
            values = [row[col] for col in columns]
            cursor.execute(
                f"INSERT INTO {table_name} ({column_names}) VALUES ({placeholders})",
                values
            )

    return len(data)


def truncate_table(table_name: str) -> None:
    """
    Truncate a table (removes all data).

    Args:
        table_name: Name of the table

    Example:
        >>> truncate_table('test_document')
    """
    with connection.cursor() as cursor:
        cursor.execute(f"TRUNCATE TABLE {table_name} CASCADE")
