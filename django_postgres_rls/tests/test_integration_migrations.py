"""
Integration tests for RLS migration operations with real PostgreSQL.

Tests migration operations that create and manage RLS policies.
"""

import pytest
from django.db import connection, models
from django.db.models import Q, F

from django_postgres_rls import (
    RLSModel,
    RlsPolicy,
    PolicyCommand,
    PolicyMode,
    CurrentUserId,
    apply_rls_policies,
    drop_rls_policies,
)
from .integration_utils import (
    get_active_policies,
    verify_rls_enforcement,
    enable_rls,
    drop_all_policies,
)


pytestmark = pytest.mark.integration


class TestMigrationOperations:
    """Test RLS migration operations."""

    def test_apply_rls_policies_creates_policies(self, postgres_db, postgres_test_roles):
        """Test that apply_rls_policies creates actual policies in database."""
        # Create test model
        class TestModel(RLSModel, models.Model):
            title = models.CharField(max_length=200)
            owner_id = models.IntegerField()

            rls_policies = [
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.SELECT,
                    using='true'
                ),
            ]

            class Meta:
                app_label = 'tests'
                db_table = 'test_apply_policies'

        # Create table
        with connection.schema_editor() as schema_editor:
            schema_editor.create_model(TestModel)

        # Apply RLS policies
        apply_rls_policies(TestModel, verbosity=0)

        # Verify policies were created
        policies = get_active_policies('test_apply_policies')
        assert len(policies) > 0

        # Verify RLS is enabled
        assert verify_rls_enforcement('test_apply_policies', 'app_user')

        # Cleanup
        with connection.schema_editor() as schema_editor:
            schema_editor.delete_model(TestModel)

    def test_drop_rls_policies_removes_policies(self, postgres_db, postgres_test_roles):
        """Test that drop_rls_policies removes policies from database."""
        # Create test model
        class TestModel(RLSModel, models.Model):
            title = models.CharField(max_length=200)

            rls_policies = [
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.SELECT,
                    using='true'
                ),
            ]

            class Meta:
                app_label = 'tests'
                db_table = 'test_drop_policies'

        # Create table
        with connection.schema_editor() as schema_editor:
            schema_editor.create_model(TestModel)

        # Apply policies
        apply_rls_policies(TestModel, verbosity=0)

        # Verify policies exist
        policies_before = get_active_policies('test_drop_policies')
        assert len(policies_before) > 0

        # Drop policies
        drop_rls_policies(TestModel, verbosity=0)

        # Verify policies were removed
        policies_after = get_active_policies('test_drop_policies')
        assert len(policies_after) == 0

        # Cleanup
        with connection.schema_editor() as schema_editor:
            schema_editor.delete_model(TestModel)

    def test_apply_policies_is_idempotent(self, postgres_db, postgres_test_roles):
        """Test that applying policies multiple times doesn't cause errors."""
        class TestModel(RLSModel, models.Model):
            title = models.CharField(max_length=200)

            rls_policies = [
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.SELECT,
                    using='true'
                ),
            ]

            class Meta:
                app_label = 'tests'
                db_table = 'test_idempotent'

        # Create table
        with connection.schema_editor() as schema_editor:
            schema_editor.create_model(TestModel)

        # Apply policies first time
        apply_rls_policies(TestModel, verbosity=0)
        policies_count_1 = len(get_active_policies('test_idempotent'))

        # Apply policies second time (should not error)
        apply_rls_policies(TestModel, verbosity=0)
        policies_count_2 = len(get_active_policies('test_idempotent'))

        # Should have same number of policies
        assert policies_count_1 == policies_count_2

        # Cleanup
        with connection.schema_editor() as schema_editor:
            schema_editor.delete_model(TestModel)

    def test_complex_policy_with_q_objects(self, postgres_db, postgres_test_roles):
        """Test applying policies with Django Q objects."""
        class TestModel(RLSModel, models.Model):
            owner_id = models.IntegerField()
            is_public = models.BooleanField()

            rls_policies = [
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.SELECT,
                    using=Q(is_public=True) | Q(owner_id=CurrentUserId())
                ),
            ]

            class Meta:
                app_label = 'tests'
                db_table = 'test_q_objects'

        # Create table
        with connection.schema_editor() as schema_editor:
            schema_editor.create_model(TestModel)

        # Apply policies
        apply_rls_policies(TestModel, verbosity=0)

        # Verify policies were created
        policies = get_active_policies('test_q_objects', 'app_user')
        assert len(policies) > 0

        # Verify the policy contains expected SQL
        policy = policies[0]
        qual = policy['qual'].lower()
        assert 'is_public' in qual or 'owner_id' in qual

        # Cleanup
        with connection.schema_editor() as schema_editor:
            schema_editor.delete_model(TestModel)

    def test_multiple_policies_for_different_roles(self, postgres_db, postgres_test_roles):
        """Test applying multiple policies for different roles."""
        class TestModel(RLSModel, models.Model):
            owner_id = models.IntegerField()

            rls_policies = [
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.SELECT,
                    using='owner_id = 1'
                ),
                RlsPolicy(
                    role_name='app_staff',
                    command=PolicyCommand.SELECT,
                    using='true'
                ),
            ]

            class Meta:
                app_label = 'tests'
                db_table = 'test_multi_role'

        # Create table
        with connection.schema_editor() as schema_editor:
            schema_editor.create_model(TestModel)

        # Apply policies
        apply_rls_policies(TestModel, verbosity=0)

        # Verify policies for each role
        user_policies = get_active_policies('test_multi_role', 'app_user')
        staff_policies = get_active_policies('test_multi_role', 'app_staff')

        assert len(user_policies) >= 1
        assert len(staff_policies) >= 1

        # Cleanup
        with connection.schema_editor() as schema_editor:
            schema_editor.delete_model(TestModel)

    def test_policy_with_all_commands(self, postgres_db, postgres_test_roles):
        """Test policy that applies to all commands."""
        class TestModel(RLSModel, models.Model):
            data = models.CharField(max_length=200)

            rls_policies = [
                RlsPolicy(
                    role_name='app_staff',
                    command=PolicyCommand.ALL,
                    using='true'
                ),
            ]

            class Meta:
                app_label = 'tests'
                db_table = 'test_all_commands'

        # Create table
        with connection.schema_editor() as schema_editor:
            schema_editor.create_model(TestModel)

        # Apply policies
        apply_rls_policies(TestModel, verbosity=0)

        # Verify policy was created
        policies = get_active_policies('test_all_commands', 'app_staff')
        assert len(policies) > 0

        # Check that policy applies to ALL commands
        policy = policies[0]
        assert policy['cmd'] == '*' or policy['cmd'] == 'ALL'

        # Cleanup
        with connection.schema_editor() as schema_editor:
            schema_editor.delete_model(TestModel)

    def test_policy_with_with_check_clause(self, postgres_db, postgres_test_roles):
        """Test policy with different USING and WITH CHECK clauses."""
        class TestModel(RLSModel, models.Model):
            owner_id = models.IntegerField()
            status = models.CharField(max_length=50)

            rls_policies = [
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.UPDATE,
                    using="owner_id = 1",
                    with_check="status = 'draft'"
                ),
            ]

            class Meta:
                app_label = 'tests'
                db_table = 'test_with_check'

        # Create table
        with connection.schema_editor() as schema_editor:
            schema_editor.create_model(TestModel)

        # Apply policies
        apply_rls_policies(TestModel, verbosity=0)

        # Verify policy was created with both clauses
        policies = get_active_policies('test_with_check', 'app_user')
        assert len(policies) > 0

        policy = policies[0]
        assert policy['qual'] is not None  # USING clause
        assert policy['with_check'] is not None  # WITH CHECK clause

        # Cleanup
        with connection.schema_editor() as schema_editor:
            schema_editor.delete_model(TestModel)

    def test_restrictive_policy_mode(self, postgres_db, postgres_test_roles):
        """Test creating RESTRICTIVE policy."""
        class TestModel(RLSModel, models.Model):
            is_active = models.BooleanField()

            rls_policies = [
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.SELECT,
                    using='is_active = true',
                    mode=PolicyMode.RESTRICTIVE
                ),
            ]

            class Meta:
                app_label = 'tests'
                db_table = 'test_restrictive_mode'

        # Create table
        with connection.schema_editor() as schema_editor:
            schema_editor.create_model(TestModel)

        # Apply policies
        apply_rls_policies(TestModel, verbosity=0)

        # Verify policy was created as restrictive
        policies = get_active_policies('test_restrictive_mode', 'app_user')
        assert len(policies) > 0

        policy = policies[0]
        # permissive field: RESTRICTIVE = 'r', PERMISSIVE = 'p'
        assert policy['permissive'] == 'RESTRICTIVE' or policy['permissive'] == 'r'

        # Cleanup
        with connection.schema_editor() as schema_editor:
            schema_editor.delete_model(TestModel)

    def test_force_rls_enabled_by_default(self, postgres_db, postgres_test_roles):
        """Test that FORCE ROW LEVEL SECURITY is enabled by default."""
        class TestModel(RLSModel, models.Model):
            data = models.CharField(max_length=200)

            rls_policies = [
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.SELECT,
                    using='true'
                ),
            ]

            class Meta:
                app_label = 'tests'
                db_table = 'test_force_rls'

        # Create table
        with connection.schema_editor() as schema_editor:
            schema_editor.create_model(TestModel)

        # Apply policies
        apply_rls_policies(TestModel, verbosity=0)

        # Check that FORCE RLS is enabled
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT relforcerowsecurity
                FROM pg_class
                WHERE relname = 'test_force_rls'
            """)
            result = cursor.fetchone()
            assert result is not None
            force_rls = result[0]
            assert force_rls is True

        # Cleanup
        with connection.schema_editor() as schema_editor:
            schema_editor.delete_model(TestModel)

    def test_policy_names_are_unique_per_table(self, postgres_db, postgres_test_roles):
        """Test that policy names don't conflict across tables."""
        class TestModel1(RLSModel, models.Model):
            data = models.CharField(max_length=200)

            rls_policies = [
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.SELECT,
                    using='true'
                ),
            ]

            class Meta:
                app_label = 'tests'
                db_table = 'test_policy_names_1'

        class TestModel2(RLSModel, models.Model):
            data = models.CharField(max_length=200)

            rls_policies = [
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.SELECT,
                    using='true'
                ),
            ]

            class Meta:
                app_label = 'tests'
                db_table = 'test_policy_names_2'

        # Create tables
        with connection.schema_editor() as schema_editor:
            schema_editor.create_model(TestModel1)
            schema_editor.create_model(TestModel2)

        # Apply policies
        apply_rls_policies(TestModel1, verbosity=0)
        apply_rls_policies(TestModel2, verbosity=0)

        # Verify both have policies
        policies1 = get_active_policies('test_policy_names_1')
        policies2 = get_active_policies('test_policy_names_2')

        assert len(policies1) > 0
        assert len(policies2) > 0

        # Cleanup
        with connection.schema_editor() as schema_editor:
            schema_editor.delete_model(TestModel1)
            schema_editor.delete_model(TestModel2)
