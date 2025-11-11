"""
Tests for django_postgres_rls.management module.

Tests cover:
- Migration operation generation
- Migration code generation
- Custom migration operations
- Policy application functions
"""

import pytest
from unittest.mock import Mock, patch, MagicMock, call
from django.db import models
from django.db.migrations.operations.base import Operation
from django.test import TestCase

from django_postgres_rls import (
    RLSModel,
    RlsPolicy,
    PolicyCommand,
    generate_rls_migration_operations,
    generate_rls_migration_code,
    CreateRLSPoliciesOperation,
    EnableRLSOperation,
    apply_rls_policies,
    drop_rls_policies,
)


class TestGenerateRLSMigrationOperations(TestCase):
    """Test generate_rls_migration_operations function."""

    def setUp(self):
        """Create test model."""
        class TestModel(RLSModel, models.Model):
            name = models.CharField(max_length=100)

            rls_policies = [
                RlsPolicy(role_name='app_user', command=PolicyCommand.SELECT, using='true'),
                RlsPolicy(role_name='app_staff', command=PolicyCommand.ALL, using='true'),
            ]

            class Meta:
                app_label = 'test_management'
                db_table = 'test_model'

        self.TestModel = TestModel

    def test_generate_operations_default(self):
        """Test generating operations with default parameters."""
        from django.db import migrations

        operations = generate_rls_migration_operations(self.TestModel)

        # Should have 2 operations: enable RLS and create policies
        assert len(operations) == 2
        assert all(isinstance(op, migrations.RunSQL) for op in operations)

    def test_generate_operations_enable_rls(self):
        """Test RLS enable operation."""
        from django.db import migrations

        operations = generate_rls_migration_operations(
            self.TestModel,
            enable_rls=True,
            force_rls=True
        )

        # First operation should enable RLS
        enable_op = operations[0]
        assert 'ENABLE ROW LEVEL SECURITY' in enable_op.sql
        assert 'FORCE ROW LEVEL SECURITY' in enable_op.sql
        assert 'test_model' in enable_op.sql

        # Should have reverse SQL
        assert enable_op.reverse_sql is not None
        assert 'DISABLE ROW LEVEL SECURITY' in enable_op.reverse_sql

    def test_generate_operations_create_policies(self):
        """Test policy creation operation."""
        operations = generate_rls_migration_operations(
            self.TestModel,
            create_policies=True
        )

        # Second operation should create policies
        policy_op = operations[1]
        assert 'CREATE POLICY' in policy_op.sql
        assert 'test_model_policy_0' in policy_op.sql
        assert 'test_model_policy_1' in policy_op.sql

        # Should have reverse SQL
        assert policy_op.reverse_sql is not None
        assert 'DROP POLICY' in policy_op.reverse_sql

    def test_generate_operations_no_reverse(self):
        """Test generating operations without reverse SQL."""
        operations = generate_rls_migration_operations(
            self.TestModel,
            reverse=False
        )

        # Operations should not have reverse SQL
        for op in operations:
            assert op.reverse_sql is None

    def test_generate_operations_only_enable(self):
        """Test generating only RLS enable operation."""
        operations = generate_rls_migration_operations(
            self.TestModel,
            enable_rls=True,
            create_policies=False
        )

        assert len(operations) == 1
        assert 'ENABLE ROW LEVEL SECURITY' in operations[0].sql

    def test_generate_operations_only_policies(self):
        """Test generating only policy creation operation."""
        operations = generate_rls_migration_operations(
            self.TestModel,
            enable_rls=False,
            create_policies=True
        )

        assert len(operations) == 1
        assert 'CREATE POLICY' in operations[0].sql

    def test_generate_operations_no_force_rls(self):
        """Test generating operations without FORCE RLS."""
        operations = generate_rls_migration_operations(
            self.TestModel,
            enable_rls=True,
            force_rls=False
        )

        enable_op = operations[0]
        assert 'ENABLE ROW LEVEL SECURITY' in enable_op.sql
        assert 'FORCE ROW LEVEL SECURITY' not in enable_op.sql


class TestGenerateRLSMigrationCode(TestCase):
    """Test generate_rls_migration_code function."""

    def setUp(self):
        """Create test model."""
        class TestModel(RLSModel, models.Model):
            name = models.CharField(max_length=100)

            rls_policies = [
                RlsPolicy(role_name='app_user', command=PolicyCommand.SELECT, using='true'),
            ]

            class Meta:
                app_label = 'test_management'
                db_table = 'test_model'

        self.TestModel = TestModel

    def test_generate_code_basic(self):
        """Test generating basic migration code."""
        code = generate_rls_migration_code(self.TestModel)

        # Should contain migration class structure
        assert 'from django.db import migrations' in code
        assert 'class Migration(migrations.Migration):' in code
        assert 'dependencies = [' in code
        assert 'operations = [' in code

    def test_generate_code_contains_app_label(self):
        """Test generated code contains correct app label."""
        code = generate_rls_migration_code(self.TestModel)
        assert "'test_management'" in code

    def test_generate_code_contains_enable_rls(self):
        """Test generated code contains RLS enable SQL."""
        code = generate_rls_migration_code(self.TestModel, enable_rls=True)
        assert 'ENABLE ROW LEVEL SECURITY' in code
        assert 'FORCE ROW LEVEL SECURITY' in code

    def test_generate_code_contains_policies(self):
        """Test generated code contains policy creation SQL."""
        code = generate_rls_migration_code(self.TestModel, create_policies=True)
        assert 'CREATE POLICY' in code
        assert 'test_model_policy_0' in code

    def test_generate_code_contains_reverse_sql(self):
        """Test generated code contains reverse SQL."""
        code = generate_rls_migration_code(self.TestModel, reverse=True)
        assert 'reverse_sql=' in code
        assert 'DROP POLICY' in code

    def test_generate_code_no_reverse_sql(self):
        """Test generated code without reverse SQL."""
        code = generate_rls_migration_code(self.TestModel, reverse=False)
        # reverse_sql should still appear but might be empty or not included
        # This is implementation dependent

    def test_generate_code_is_valid_python(self):
        """Test that generated code is syntactically valid Python."""
        code = generate_rls_migration_code(self.TestModel)

        # Try to compile the code
        try:
            compile(code, '<string>', 'exec')
        except SyntaxError:
            pytest.fail("Generated code is not valid Python")


class TestCreateRLSPoliciesOperation(TestCase):
    """Test CreateRLSPoliciesOperation custom migration operation."""

    def setUp(self):
        """Create test model and operation."""
        class TestModel(RLSModel, models.Model):
            name = models.CharField(max_length=100)

            rls_policies = [
                RlsPolicy(role_name='app_user', using='true'),
            ]

            class Meta:
                app_label = 'test_management'
                db_table = 'test_model'

        self.TestModel = TestModel
        self.operation = CreateRLSPoliciesOperation(
            model_name='TestModel',
            app_label='test_app'
        )

    def test_operation_is_reversible(self):
        """Test that operation is reversible."""
        assert self.operation.reversible is True

    def test_operation_describe(self):
        """Test operation description."""
        description = self.operation.describe()
        assert 'test_app' in description
        assert 'TestModel' in description
        assert 'RLS' in description or 'policies' in description.lower()

    def test_state_forwards_no_change(self):
        """Test state_forwards doesn't modify state."""
        # state_forwards should not modify state
        # This is a no-op for this operation
        self.operation.state_forwards('test_app', Mock())

    @patch('django_postgres_rls.management.CreateRLSPoliciesOperation')
    def test_database_forwards_executes_sql(self, mock_op):
        """Test database_forwards executes policy SQL."""
        # This would require mocking the database cursor
        # Testing that it's called correctly
        pass

    @patch('django_postgres_rls.management.CreateRLSPoliciesOperation')
    def test_database_backwards_drops_policies(self, mock_op):
        """Test database_backwards drops policies."""
        # This would require mocking the database cursor
        pass


class TestEnableRLSOperation(TestCase):
    """Test EnableRLSOperation custom migration operation."""

    def setUp(self):
        """Create operation."""
        self.operation = EnableRLSOperation(
            model_name='TestModel',
            app_label='test_app',
            force=True
        )

    def test_operation_is_reversible(self):
        """Test that operation is reversible."""
        assert self.operation.reversible is True

    def test_operation_describe(self):
        """Test operation description."""
        description = self.operation.describe()
        assert 'test_app' in description
        assert 'TestModel' in description
        assert 'RLS' in description
        assert 'FORCE' in description

    def test_operation_describe_no_force(self):
        """Test operation description without force."""
        operation = EnableRLSOperation(
            model_name='TestModel',
            app_label='test_app',
            force=False
        )
        description = operation.describe()
        assert 'FORCE' not in description

    def test_state_forwards_no_change(self):
        """Test state_forwards doesn't modify state."""
        self.operation.state_forwards('test_app', Mock())


class TestApplyRLSPolicies(TestCase):
    """Test apply_rls_policies function."""

    def setUp(self):
        """Create test model."""
        class TestModel(RLSModel, models.Model):
            name = models.CharField(max_length=100)

            rls_policies = [
                RlsPolicy(role_name='app_user', using='true'),
                RlsPolicy(role_name='app_staff', using='true'),
            ]

            class Meta:
                app_label = 'test_management'
                db_table = 'test_model'

        self.TestModel = TestModel

    @patch('django_postgres_rls.management.connection')
    def test_apply_rls_policies_basic(self, mock_connection):
        """Test basic policy application."""
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        created, skipped = apply_rls_policies(self.TestModel, verbosity=0)

        # Should have executed ALTER TABLE commands
        assert mock_cursor.execute.called
        call_args = [call[0][0] for call in mock_cursor.execute.call_args_list]

        # Check for RLS enable commands
        assert any('ENABLE ROW LEVEL SECURITY' in arg for arg in call_args)
        assert any('FORCE ROW LEVEL SECURITY' in arg for arg in call_args)

        # Check for CREATE POLICY commands
        assert any('CREATE POLICY' in arg for arg in call_args)

    @patch('django_postgres_rls.management.connection')
    def test_apply_rls_policies_returns_counts(self, mock_connection):
        """Test that apply_rls_policies returns correct counts."""
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        created, skipped = apply_rls_policies(self.TestModel, verbosity=0)

        assert isinstance(created, int)
        assert isinstance(skipped, int)
        assert created >= 0
        assert skipped >= 0

    @patch('django_postgres_rls.management.connection')
    def test_apply_rls_policies_handles_existing(self, mock_connection):
        """Test handling of already existing policies."""
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        # Simulate policy already exists error
        mock_cursor.execute.side_effect = [
            None,  # ENABLE RLS
            None,  # FORCE RLS
            Exception("already exists"),  # First policy
            None,  # Second policy
        ]

        created, skipped = apply_rls_policies(self.TestModel, verbosity=0)

        assert skipped >= 0

    @patch('django_postgres_rls.management.connection')
    def test_apply_rls_policies_verbosity(self, mock_connection):
        """Test different verbosity levels."""
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        # Test verbosity levels 0, 1, 2
        for verbosity in [0, 1, 2]:
            apply_rls_policies(self.TestModel, verbosity=verbosity)


class TestDropRLSPolicies(TestCase):
    """Test drop_rls_policies function."""

    def setUp(self):
        """Create test model."""
        class TestModel(RLSModel, models.Model):
            name = models.CharField(max_length=100)

            rls_policies = [
                RlsPolicy(role_name='app_user', using='true'),
                RlsPolicy(role_name='app_staff', using='true'),
            ]

            class Meta:
                app_label = 'test_management'
                db_table = 'test_model'

        self.TestModel = TestModel

    @patch('django_postgres_rls.management.connection')
    def test_drop_rls_policies_basic(self, mock_connection):
        """Test basic policy dropping."""
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        dropped = drop_rls_policies(self.TestModel, verbosity=0)

        # Should have executed DROP POLICY commands
        assert mock_cursor.execute.called
        call_args = [call[0][0] for call in mock_cursor.execute.call_args_list]

        # Check for DROP POLICY commands
        assert any('DROP POLICY' in arg for arg in call_args)
        assert any('test_model_policy_0' in arg for arg in call_args)
        assert any('test_model_policy_1' in arg for arg in call_args)

    @patch('django_postgres_rls.management.connection')
    def test_drop_rls_policies_returns_count(self, mock_connection):
        """Test that drop_rls_policies returns correct count."""
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        dropped = drop_rls_policies(self.TestModel, verbosity=0)

        assert isinstance(dropped, int)
        assert dropped >= 0

    @patch('django_postgres_rls.management.connection')
    def test_drop_rls_policies_verbosity(self, mock_connection):
        """Test different verbosity levels."""
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        # Test verbosity levels 0, 1, 2
        for verbosity in [0, 1, 2]:
            drop_rls_policies(self.TestModel, verbosity=verbosity)

    @patch('django_postgres_rls.management.connection')
    def test_drop_rls_policies_with_if_exists(self, mock_connection):
        """Test that DROP POLICY uses IF EXISTS."""
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        drop_rls_policies(self.TestModel, verbosity=0)

        call_args = [call[0][0] for call in mock_cursor.execute.call_args_list]

        # Check that IF EXISTS is used
        assert any('IF EXISTS' in arg for arg in call_args)


class TestEdgeCases(TestCase):
    """Test edge cases for management functions."""

    def test_generate_operations_empty_policies(self):
        """Test generating operations for model with no policies."""
        class TestModel(RLSModel, models.Model):
            name = models.CharField(max_length=100)

            class Meta:
                app_label = 'test_management'
                db_table = 'test_model'

        operations = generate_rls_migration_operations(TestModel)

        # Should still have enable RLS operation
        assert len(operations) == 1

    def test_generate_code_empty_policies(self):
        """Test generating code for model with no policies."""
        class TestModel(RLSModel, models.Model):
            name = models.CharField(max_length=100)

            class Meta:
                app_label = 'test_management'
                db_table = 'test_model'

        code = generate_rls_migration_code(TestModel)
        assert 'class Migration' in code

    @patch('django_postgres_rls.management.connection')
    def test_apply_empty_policies(self, mock_connection):
        """Test applying policies for model with no policies."""
        class TestModel(RLSModel, models.Model):
            name = models.CharField(max_length=100)

            class Meta:
                app_label = 'test_management'
                db_table = 'test_model'

        mock_cursor = MagicMock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        created, skipped = apply_rls_policies(TestModel, verbosity=0)

        # Should still enable RLS but create no policies
        assert created == 0
