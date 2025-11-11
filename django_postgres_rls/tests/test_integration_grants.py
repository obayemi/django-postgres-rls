"""
Integration tests for verifying that GRANT statements are properly executed.

These tests verify that when RLS policies are applied, the necessary table-level
permissions are granted to the roles specified in the policies.
"""

import pytest
from django.db import connection, models
from django.apps import AppConfig
from unittest.mock import Mock

from django_postgres_rls import (
    RLSModel,
    RlsPolicy,
    PolicyCommand,
    apply_rls_policies,
    register_rls_model,
    get_registered_models,
)
from django_postgres_rls.signals import auto_apply_rls_policies
from .integration_utils import create_test_roles, cleanup_test_roles


pytestmark = pytest.mark.integration


def get_table_grants(table_name: str, grantee: str = None):
    """
    Query information_schema.role_table_grants to get actual grants.

    Args:
        table_name: Name of the table to check
        grantee: Optional role name to filter by

    Returns:
        List of tuples: (grantee, privilege_type)
    """
    with connection.cursor() as cursor:
        if grantee:
            cursor.execute("""
                SELECT grantee, privilege_type
                FROM information_schema.role_table_grants
                WHERE table_name = %s AND grantee = %s
                ORDER BY grantee, privilege_type
            """, [table_name, grantee])
        else:
            cursor.execute("""
                SELECT grantee, privilege_type
                FROM information_schema.role_table_grants
                WHERE table_name = %s
                ORDER BY grantee, privilege_type
            """, [table_name])
        return cursor.fetchall()


def verify_role_has_privilege(table_name: str, role: str, privilege: str) -> bool:
    """
    Verify that a role has a specific privilege on a table.

    Args:
        table_name: Name of the table
        role: Role name
        privilege: Privilege type (SELECT, INSERT, UPDATE, DELETE)

    Returns:
        True if the role has the privilege, False otherwise
    """
    grants = get_table_grants(table_name, role)
    privilege_types = [grant[1] for grant in grants]
    return privilege.upper() in privilege_types


@pytest.fixture
def test_table():
    """Create a test table for grant testing."""
    table_name = 'test_grants_table'

    with connection.cursor() as cursor:
        # Drop table if exists
        cursor.execute(f"DROP TABLE IF EXISTS {table_name} CASCADE")

        # Create test table
        cursor.execute(f"""
            CREATE TABLE {table_name} (
                id SERIAL PRIMARY KEY,
                owner_id INTEGER,
                data TEXT
            )
        """)

    yield table_name

    # Cleanup
    with connection.cursor() as cursor:
        cursor.execute(f"DROP TABLE IF EXISTS {table_name} CASCADE")


@pytest.fixture
def test_roles():
    """Create test roles for grant testing."""
    roles = create_test_roles(['app_user', 'app_staff', 'app_superuser'])
    yield roles
    cleanup_test_roles(roles)


class TestApplyRLSPoliciesGrants:
    """Test that apply_rls_policies correctly grants table permissions."""

    def test_grants_select_permission_for_select_policy(self, postgres_db, test_table, test_roles):
        """Test that SELECT permission is granted for SELECT policy."""
        # Create a model with SELECT policy
        class TestModel(RLSModel, models.Model):
            rls_policies = [
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.SELECT,
                    using='true'
                ),
            ]

            class Meta:
                app_label = 'test_grants'
                db_table = test_table

        # Apply RLS policies (this should grant SELECT to app_user)
        created, skipped = apply_rls_policies(TestModel, verbosity=2)

        # Verify the grant was created
        grants = get_table_grants(test_table, 'app_user')
        privilege_types = [grant[1] for grant in grants]

        assert 'SELECT' in privilege_types, \
            f"app_user should have SELECT privilege. Got: {privilege_types}"

    def test_grants_insert_permission_for_insert_policy(self, postgres_db, test_table, test_roles):
        """Test that INSERT permission is granted for INSERT policy."""
        class TestModel(RLSModel, models.Model):
            rls_policies = [
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.INSERT,
                    with_check='true'
                ),
            ]

            class Meta:
                app_label = 'test_grants'
                db_table = test_table

        apply_rls_policies(TestModel, verbosity=2)

        assert verify_role_has_privilege(test_table, 'app_user', 'INSERT'), \
            "app_user should have INSERT privilege"

    def test_grants_update_permission_for_update_policy(self, postgres_db, test_table, test_roles):
        """Test that UPDATE permission is granted for UPDATE policy."""
        class TestModel(RLSModel, models.Model):
            rls_policies = [
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.UPDATE,
                    using='true'
                ),
            ]

            class Meta:
                app_label = 'test_grants'
                db_table = test_table

        apply_rls_policies(TestModel, verbosity=2)

        assert verify_role_has_privilege(test_table, 'app_user', 'UPDATE'), \
            "app_user should have UPDATE privilege"

    def test_grants_delete_permission_for_delete_policy(self, postgres_db, test_table, test_roles):
        """Test that DELETE permission is granted for DELETE policy."""
        class TestModel(RLSModel, models.Model):
            rls_policies = [
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.DELETE,
                    using='true'
                ),
            ]

            class Meta:
                app_label = 'test_grants'
                db_table = test_table

        apply_rls_policies(TestModel, verbosity=2)

        assert verify_role_has_privilege(test_table, 'app_user', 'DELETE'), \
            "app_user should have DELETE privilege"

    def test_grants_all_permissions_for_all_policy(self, postgres_db, test_table, test_roles):
        """Test that all permissions are granted for PolicyCommand.ALL."""
        class TestModel(RLSModel, models.Model):
            rls_policies = [
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.ALL,
                    using='true'
                ),
            ]

            class Meta:
                app_label = 'test_grants'
                db_table = test_table

        apply_rls_policies(TestModel, verbosity=2)

        # Verify all permissions
        assert verify_role_has_privilege(test_table, 'app_user', 'SELECT'), \
            "app_user should have SELECT privilege"
        assert verify_role_has_privilege(test_table, 'app_user', 'INSERT'), \
            "app_user should have INSERT privilege"
        assert verify_role_has_privilege(test_table, 'app_user', 'UPDATE'), \
            "app_user should have UPDATE privilege"
        assert verify_role_has_privilege(test_table, 'app_user', 'DELETE'), \
            "app_user should have DELETE privilege"

    def test_grants_to_multiple_roles(self, postgres_db, test_table, test_roles):
        """Test that permissions are granted to multiple roles."""
        class TestModel(RLSModel, models.Model):
            rls_policies = [
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.SELECT,
                    using='true'
                ),
                RlsPolicy(
                    role_name='app_staff',
                    command=PolicyCommand.ALL,
                    using='true'
                ),
            ]

            class Meta:
                app_label = 'test_grants'
                db_table = test_table

        apply_rls_policies(TestModel, verbosity=2)

        # Verify app_user has SELECT
        assert verify_role_has_privilege(test_table, 'app_user', 'SELECT'), \
            "app_user should have SELECT privilege"

        # Verify app_staff has all privileges
        assert verify_role_has_privilege(test_table, 'app_staff', 'SELECT'), \
            "app_staff should have SELECT privilege"
        assert verify_role_has_privilege(test_table, 'app_staff', 'INSERT'), \
            "app_staff should have INSERT privilege"
        assert verify_role_has_privilege(test_table, 'app_staff', 'UPDATE'), \
            "app_staff should have UPDATE privilege"
        assert verify_role_has_privilege(test_table, 'app_staff', 'DELETE'), \
            "app_staff should have DELETE privilege"

    def test_no_grants_for_public_policy(self, postgres_db, test_table, test_roles):
        """Test that PUBLIC policies don't grant to specific roles."""
        class TestModel(RLSModel, models.Model):
            rls_policies = [
                RlsPolicy(
                    role_name=None,  # PUBLIC policy
                    command=PolicyCommand.SELECT,
                    using='true'
                ),
            ]

            class Meta:
                app_label = 'test_grants'
                db_table = test_table

        apply_rls_policies(TestModel, verbosity=2)

        # Verify no specific grants to app_user (PUBLIC doesn't grant to named roles)
        grants = get_table_grants(test_table, 'app_user')
        assert len(grants) == 0, \
            "PUBLIC policy should not create grants to specific roles"

    def test_multiple_policies_same_role_combines_permissions(self, postgres_db, test_table, test_roles):
        """Test that multiple policies for the same role combine permissions."""
        class TestModel(RLSModel, models.Model):
            rls_policies = [
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.SELECT,
                    using='true'
                ),
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.INSERT,
                    with_check='true'
                ),
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.UPDATE,
                    using='true'
                ),
            ]

            class Meta:
                app_label = 'test_grants'
                db_table = test_table

        apply_rls_policies(TestModel, verbosity=2)

        # Verify all three permissions were granted
        assert verify_role_has_privilege(test_table, 'app_user', 'SELECT')
        assert verify_role_has_privilege(test_table, 'app_user', 'INSERT')
        assert verify_role_has_privilege(test_table, 'app_user', 'UPDATE')


class TestAutoApplyWithGrants:
    """Test that auto_apply_rls_policies signal handler grants permissions."""

    def test_auto_apply_creates_grants(self, postgres_db, test_table, test_roles):
        """Test that post_migrate signal handler creates grants."""
        from django_postgres_rls.signals import _rls_model_registry

        # Clear registry
        _rls_model_registry.clear()

        # Create and register a model
        class TestModel(RLSModel, models.Model):
            rls_policies = [
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.ALL,
                    using='true'
                ),
            ]

            class Meta:
                app_label = 'test_grants'
                db_table = test_table

        register_rls_model(TestModel)

        # Simulate post_migrate signal
        mock_app_config = Mock(spec=AppConfig)
        mock_app_config.label = 'test_grants'

        auto_apply_rls_policies(
            sender=None,
            app_config=mock_app_config,
            verbosity=2
        )

        # Verify grants were created
        assert verify_role_has_privilege(test_table, 'app_user', 'SELECT')
        assert verify_role_has_privilege(test_table, 'app_user', 'INSERT')
        assert verify_role_has_privilege(test_table, 'app_user', 'UPDATE')
        assert verify_role_has_privilege(test_table, 'app_user', 'DELETE')

        # Cleanup
        _rls_model_registry.clear()


class TestAutoRegistrationWithGrants:
    """Test that auto-registered models get grants when policies are applied."""

    def test_auto_registered_model_gets_grants(self, postgres_db, test_table, test_roles):
        """Test that automatically registered RLSModel subclasses get table grants."""
        from django_postgres_rls.signals import _rls_model_registry
        from django.apps import apps

        # Clear registry and pending registrations
        _rls_model_registry.clear()
        if hasattr(apps, '_pending_rls_registrations'):
            apps._pending_rls_registrations = []

        # Create a model that should auto-register
        class AutoTestModel(RLSModel, models.Model):
            rls_policies = [
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.SELECT,
                    using='true'
                ),
                RlsPolicy(
                    role_name='app_staff',
                    command=PolicyCommand.ALL,
                    using='true'
                ),
            ]

            class Meta:
                app_label = 'test_grants'
                db_table = test_table

        # Process pending registrations (simulating AppConfig.ready())
        if hasattr(apps, '_pending_rls_registrations'):
            for register_func in apps._pending_rls_registrations:
                try:
                    register_func()
                except Exception:
                    pass
            apps._pending_rls_registrations = []

        # Verify model is registered
        assert AutoTestModel in get_registered_models(), \
            "Model should be auto-registered"

        # Simulate post_migrate signal to apply policies
        mock_app_config = Mock(spec=AppConfig)
        mock_app_config.label = 'test_grants'

        auto_apply_rls_policies(
            sender=None,
            app_config=mock_app_config,
            verbosity=2
        )

        # Verify grants were created for both roles
        assert verify_role_has_privilege(test_table, 'app_user', 'SELECT'), \
            "app_user should have SELECT privilege after auto-registration"

        assert verify_role_has_privilege(test_table, 'app_staff', 'SELECT'), \
            "app_staff should have SELECT privilege"
        assert verify_role_has_privilege(test_table, 'app_staff', 'INSERT'), \
            "app_staff should have INSERT privilege"
        assert verify_role_has_privilege(test_table, 'app_staff', 'UPDATE'), \
            "app_staff should have UPDATE privilege"
        assert verify_role_has_privilege(test_table, 'app_staff', 'DELETE'), \
            "app_staff should have DELETE privilege"

        # Cleanup
        _rls_model_registry.clear()


class TestGrantsWithRealUsage:
    """Test grants in realistic usage scenarios."""

    def test_role_can_query_after_grant(self, postgres_db, test_table, test_roles):
        """Test that a role can actually query a table after grants are applied."""
        class TestModel(RLSModel, models.Model):
            rls_policies = [
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.SELECT,
                    using='true'  # Allow all rows
                ),
            ]

            class Meta:
                app_label = 'test_grants'
                db_table = test_table

        # Apply policies and grants
        apply_rls_policies(TestModel, verbosity=2)

        # Insert test data as superuser
        with connection.cursor() as cursor:
            cursor.execute(f"INSERT INTO {test_table} (owner_id, data) VALUES (1, 'test')")

        # Try to query as app_user
        with connection.cursor() as cursor:
            cursor.execute("SET ROLE app_user")
            try:
                cursor.execute(f"SELECT COUNT(*) FROM {test_table}")
                count = cursor.fetchone()[0]
                assert count == 1, "Should be able to query after GRANT"
            finally:
                cursor.execute("RESET ROLE")

    def test_role_cannot_query_without_grant(self, postgres_db, test_table, test_roles):
        """Test that a role cannot query without table-level grants (even with policy)."""
        # Enable RLS but DON'T grant table permissions
        with connection.cursor() as cursor:
            cursor.execute(f"ALTER TABLE {test_table} ENABLE ROW LEVEL SECURITY")
            cursor.execute(f"ALTER TABLE {test_table} FORCE ROW LEVEL SECURITY")

            # Create a policy but don't grant table permissions
            cursor.execute(f"""
                CREATE POLICY test_policy ON {test_table}
                FOR SELECT
                TO app_user
                USING (true)
            """)

        # Try to query as app_user - should fail with permission denied
        with connection.cursor() as cursor:
            cursor.execute("SET ROLE app_user")
            try:
                cursor.execute(f"SELECT COUNT(*) FROM {test_table}")
                # If we get here, the test failed - should have raised an exception
                assert False, "Should have raised permission denied error"
            except Exception as e:
                # Should get permission denied error
                assert "permission denied" in str(e).lower(), \
                    f"Expected permission denied error, got: {e}"
            finally:
                cursor.execute("RESET ROLE")
