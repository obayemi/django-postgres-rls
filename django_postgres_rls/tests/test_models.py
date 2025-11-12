"""
Tests for django_postgres_rls.models module.

Tests cover:
- RlsPolicy dataclass validation
- PolicyCommand and PolicyMode constants
- RLSModel mixin functionality
- Q object to SQL conversion
- Policy SQL generation
"""

import pytest
from django.db import models
from django.db.models import Q, F, Exists, Value
from django.test import TestCase

from django_postgres_rls import (
    RLSModel,
    RlsPolicy,
    PolicyCommand,
    PolicyMode,
)


class TestPolicyConstants(TestCase):
    """Test PolicyCommand and PolicyMode constants."""

    def test_policy_command_values(self):
        """Test PolicyCommand has all required values."""
        assert PolicyCommand.ALL == 'ALL'
        assert PolicyCommand.SELECT == 'SELECT'
        assert PolicyCommand.INSERT == 'INSERT'
        assert PolicyCommand.UPDATE == 'UPDATE'
        assert PolicyCommand.DELETE == 'DELETE'

    def test_policy_mode_values(self):
        """Test PolicyMode has all required values."""
        assert PolicyMode.RESTRICTIVE == 'RESTRICTIVE'
        assert PolicyMode.PERMISSIVE == 'PERMISSIVE'


class TestRlsPolicy(TestCase):
    """Test RlsPolicy dataclass."""

    def test_create_policy_with_defaults(self):
        """Test creating policy with default values."""
        policy = RlsPolicy(using='true')

        assert policy.using == 'true'
        assert policy.role_name is None
        assert policy.command == PolicyCommand.ALL
        assert policy.mode is None
        assert policy.with_check is None

    def test_create_policy_with_all_fields(self):
        """Test creating policy with all fields specified."""
        policy = RlsPolicy(
            role_name='app_user',
            command=PolicyCommand.SELECT,
            using='owner_id = 1',
            mode=PolicyMode.PERMISSIVE,
            with_check='status = \'draft\''
        )

        assert policy.role_name == 'app_user'
        assert policy.command == PolicyCommand.SELECT
        assert policy.using == 'owner_id = 1'
        assert policy.mode == PolicyMode.PERMISSIVE
        assert policy.with_check == 'status = \'draft\''

    def test_create_policy_with_q_object(self):
        """Test creating policy with Django Q object."""
        q_obj = Q(is_public=True)
        policy = RlsPolicy(
            role_name='app_user',
            command=PolicyCommand.SELECT,
            using=q_obj
        )

        assert isinstance(policy.using, Q)
        assert policy.using == q_obj

    def test_create_policy_with_q_object_complex(self):
        """Test creating policy with complex Django Q object."""
        q_obj = Q(is_public=True) | Q(owner_id=F('current_user_id'))
        policy = RlsPolicy(
            role_name='app_user',
            command=PolicyCommand.SELECT,
            using=q_obj
        )

        assert isinstance(policy.using, Q)

    def test_invalid_policy_command(self):
        """Test validation fails for invalid command."""
        with pytest.raises(ValueError, match="Invalid policy command"):
            RlsPolicy(
                using='true',
                command='INVALID_COMMAND'
            )

    def test_invalid_policy_mode(self):
        """Test validation fails for invalid mode."""
        with pytest.raises(ValueError, match="Invalid policy mode"):
            RlsPolicy(
                using='true',
                mode='INVALID_MODE'
            )

    def test_valid_commands(self):
        """Test all valid commands are accepted."""
        for cmd in [PolicyCommand.ALL, PolicyCommand.SELECT, PolicyCommand.INSERT,
                    PolicyCommand.UPDATE, PolicyCommand.DELETE]:
            policy = RlsPolicy(using='true', command=cmd)
            assert policy.command == cmd

    def test_valid_modes(self):
        """Test all valid modes are accepted."""
        for mode in [PolicyMode.RESTRICTIVE, PolicyMode.PERMISSIVE]:
            policy = RlsPolicy(using='true', mode=mode)
            assert policy.mode == mode


class TestRLSModel(TestCase):
    """Test RLSModel mixin."""

    def setUp(self):
        """Create test model classes."""
        # Model with policies
        class TestDocument(RLSModel, models.Model):
            title = models.CharField(max_length=200)
            owner_id = models.IntegerField()
            is_public = models.BooleanField(default=False)

            # Use class attribute instead of Meta (Django 5.2+ compatible)
            rls_policies = [
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.SELECT,
                    using="owner_id = current_setting('app.current_user_id')::int"
                ),
                RlsPolicy(
                    role_name='app_staff',
                    command=PolicyCommand.ALL,
                    using='true'
                ),
            ]

            class Meta:
                app_label = 'test_models'
                db_table = 'test_document'

        # Model without policies
        class TestArticle(RLSModel, models.Model):
            title = models.CharField(max_length=200)

            class Meta:
                app_label = 'test_models'
                db_table = 'test_article'

        self.TestDocument = TestDocument
        self.TestArticle = TestArticle

    def test_get_rls_policies(self):
        """Test get_rls_policies returns defined policies."""
        policies = self.TestDocument.get_rls_policies()

        assert len(policies) == 2
        assert all(isinstance(p, RlsPolicy) for p in policies)
        assert policies[0].role_name == 'app_user'
        assert policies[1].role_name == 'app_staff'

    def test_get_rls_policies_empty(self):
        """Test get_rls_policies returns empty list when no policies."""
        policies = self.TestArticle.get_rls_policies()

        assert policies == []

    def test_get_table_name(self):
        """Test get_table_name returns correct table name."""
        assert self.TestDocument.get_table_name() == 'test_document'
        assert self.TestArticle.get_table_name() == 'test_article'

    def test_get_policy_sql_basic(self):
        """Test get_policy_sql generates correct SQL."""
        sql_statements = self.TestDocument.get_policy_sql()

        assert len(sql_statements) == 2

        # Check first policy
        sql1 = sql_statements[0]
        assert 'CREATE POLICY test_document_policy_0' in sql1
        assert 'ON test_document' in sql1
        assert 'FOR SELECT' in sql1
        assert 'TO app_user' in sql1
        assert "owner_id = current_setting('app.current_user_id')::int" in sql1

        # Check second policy
        sql2 = sql_statements[1]
        assert 'CREATE POLICY test_document_policy_1' in sql2
        assert 'ON test_document' in sql2
        assert 'FOR ALL' in sql2
        assert 'TO app_staff' in sql2
        assert 'USING (true)' in sql2

    def test_get_policy_sql_with_mode(self):
        """Test get_policy_sql includes mode when specified."""
        class TestModel(RLSModel, models.Model):
            name = models.CharField(max_length=100)

            # Use class attribute instead of Meta (Django 5.2+ compatible)
            rls_policies = [
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.SELECT,
                    using='true',
                    mode=PolicyMode.RESTRICTIVE
                ),
            ]

            class Meta:
                app_label = 'test_models'
                db_table = 'test_model'

        sql_statements = TestModel.get_policy_sql()
        assert len(sql_statements) == 1
        assert 'AS RESTRICTIVE' in sql_statements[0]

    def test_get_policy_sql_with_check(self):
        """Test get_policy_sql includes WITH CHECK when specified."""
        class TestModel(RLSModel, models.Model):
            name = models.CharField(max_length=100)

            # Use class attribute instead of Meta (Django 5.2+ compatible)
            rls_policies = [
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.INSERT,
                    using='true',
                    with_check="owner_id = current_setting('app.current_user_id')::int"
                ),
            ]

            class Meta:
                app_label = 'test_models'
                db_table = 'test_model'

        sql_statements = TestModel.get_policy_sql()
        assert len(sql_statements) == 1
        assert 'WITH CHECK' in sql_statements[0]
        assert "owner_id = current_setting('app.current_user_id')::int" in sql_statements[0]

    def test_get_policy_sql_public_role(self):
        """Test get_policy_sql uses PUBLIC when no role specified."""
        class TestModel(RLSModel, models.Model):
            name = models.CharField(max_length=100)

            # Use class attribute instead of Meta (Django 5.2+ compatible)
            rls_policies = [
                RlsPolicy(
                    command=PolicyCommand.SELECT,
                    using='true'
                ),
            ]

            class Meta:
                app_label = 'test_models'
                db_table = 'test_model'

        sql_statements = TestModel.get_policy_sql()
        assert len(sql_statements) == 1
        assert 'TO PUBLIC' in sql_statements[0]

    def test_get_policy_sql_custom_prefix(self):
        """Test get_policy_sql with custom policy name prefix."""
        sql_statements = self.TestDocument.get_policy_sql(policy_name_prefix='custom')

        assert len(sql_statements) == 2
        assert 'CREATE POLICY custom_policy_0' in sql_statements[0]
        assert 'CREATE POLICY custom_policy_1' in sql_statements[1]

    def test_get_policy_sql_empty(self):
        """Test get_policy_sql returns empty list when no policies."""
        sql_statements = self.TestArticle.get_policy_sql()
        assert sql_statements == []

    def test_model_is_abstract(self):
        """Test RLSModel is abstract."""
        assert RLSModel._meta.abstract is True

    def test_multiple_policies_different_commands(self):
        """Test model with policies for different commands."""
        class TestModel(RLSModel, models.Model):
            name = models.CharField(max_length=100)

            # Use class attribute instead of Meta (Django 5.2+ compatible)
            rls_policies = [
                RlsPolicy(role_name='app_user', command=PolicyCommand.SELECT, using='true'),
                RlsPolicy(role_name='app_user', command=PolicyCommand.INSERT, using='true'),
                RlsPolicy(role_name='app_user', command=PolicyCommand.UPDATE, using='true'),
                RlsPolicy(role_name='app_user', command=PolicyCommand.DELETE, using='false'),
            ]

            class Meta:
                app_label = 'test_models'
                db_table = 'test_model'

        policies = TestModel.get_rls_policies()
        assert len(policies) == 4

        sql_statements = TestModel.get_policy_sql()
        assert len(sql_statements) == 4
        assert 'FOR SELECT' in sql_statements[0]
        assert 'FOR INSERT' in sql_statements[1]
        assert 'FOR UPDATE' in sql_statements[2]
        assert 'FOR DELETE' in sql_statements[3]


class TestQObjectToSQL(TestCase):
    """Test Q object to SQL conversion."""

    def setUp(self):
        """Create test model class."""
        class TestModel(RLSModel, models.Model):
            title = models.CharField(max_length=200)
            owner_id = models.IntegerField()
            is_public = models.BooleanField(default=False)
            status = models.CharField(max_length=50)

            class Meta:
                app_label = 'test_models'
                db_table = 'test_model'

        self.TestModel = TestModel

    def test_q_object_simple(self):
        """Test simple Q object conversion."""
        q_obj = Q(is_public=True)
        sql = self.TestModel._q_to_sql(q_obj)

        # Check that SQL contains the field name
        # The actual SQL generated depends on the database backend
        assert 'is_public' in sql.lower()

    def test_q_object_or(self):
        """Test Q object with OR logic."""
        q_obj = Q(is_public=True) | Q(owner_id=1)
        sql = self.TestModel._q_to_sql(q_obj)

        assert 'is_public' in sql.lower()
        assert 'owner_id' in sql.lower()
        # Should contain OR operator
        assert 'or' in sql.lower()

    def test_q_object_and(self):
        """Test Q object with AND logic."""
        q_obj = Q(is_public=True) & Q(status='active')
        sql = self.TestModel._q_to_sql(q_obj)

        assert 'is_public' in sql.lower()
        assert 'status' in sql.lower()
        # Should contain AND operator (or implicit AND)
        assert 'and' in sql.lower()

    def test_q_object_complex(self):
        """Test complex Q object with nested logic."""
        q_obj = (Q(is_public=True) | Q(owner_id=1)) & Q(status='active')
        sql = self.TestModel._q_to_sql(q_obj)

        assert 'is_public' in sql.lower()
        assert 'owner_id' in sql.lower()
        assert 'status' in sql.lower()

    def test_policy_with_q_object_generates_sql(self):
        """Test that policies with Q objects generate valid SQL."""
        class TestModel(RLSModel, models.Model):
            title = models.CharField(max_length=200)
            is_public = models.BooleanField()

            # Use class attribute instead of Meta (Django 5.2+ compatible)
            rls_policies = [
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.SELECT,
                    using=Q(is_public=True)
                ),
            ]

            class Meta:
                app_label = 'test_models'
                db_table = 'test_model_q'

        sql_statements = TestModel.get_policy_sql()
        assert len(sql_statements) == 1

        sql = sql_statements[0]
        assert 'CREATE POLICY' in sql
        assert 'USING' in sql
        # Should have converted Q object to SQL
        assert 'is_public' in sql.lower()


class TestPolicyEdgeCases(TestCase):
    """Test edge cases and error conditions."""

    def test_policy_with_none_using(self):
        """Test policy with None as using clause."""
        policy = RlsPolicy(using=None)
        assert policy.using is None

    def test_model_with_single_policy(self):
        """Test model with exactly one policy."""
        class TestModel(RLSModel, models.Model):
            name = models.CharField(max_length=100)

            # Use class attribute instead of Meta (Django 5.2+ compatible)
            rls_policies = [
                RlsPolicy(role_name='app_user', using='true'),
            ]

            class Meta:
                app_label = 'test_models'
                db_table = 'test_single'

        policies = TestModel.get_rls_policies()
        assert len(policies) == 1

        sql_statements = TestModel.get_policy_sql()
        assert len(sql_statements) == 1

    def test_model_with_many_policies(self):
        """Test model with many policies."""
        policies_list = [
            RlsPolicy(role_name=f'role_{i}', using='true')
            for i in range(10)
        ]

        class TestModel(RLSModel, models.Model):
            name = models.CharField(max_length=100)

            # Use class attribute instead of Meta (Django 5.2+ compatible)
            rls_policies = policies_list

            class Meta:
                app_label = 'test_models'
                db_table = 'test_many'

        policies = TestModel.get_rls_policies()
        assert len(policies) == 10

        sql_statements = TestModel.get_policy_sql()
        assert len(sql_statements) == 10

    def test_policy_sql_format(self):
        """Test that generated SQL is properly formatted."""
        class TestModel(RLSModel, models.Model):
            name = models.CharField(max_length=100)

            # Use class attribute instead of Meta (Django 5.2+ compatible)
            rls_policies = [
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.SELECT,
                    using='true',
                    mode=PolicyMode.PERMISSIVE
                ),
            ]

            class Meta:
                app_label = 'test_models'
                db_table = 'test_format'

        sql_statements = TestModel.get_policy_sql()
        sql = sql_statements[0]

        # Check SQL is well-formed
        assert sql.startswith('CREATE POLICY')
        assert sql.endswith(';')
        assert 'ON test_format' in sql
        assert 'AS PERMISSIVE' in sql
        assert 'FOR SELECT' in sql
        assert 'TO app_user' in sql
        assert 'USING (true)' in sql


class TestExpressionObjects(TestCase):
    """Test RlsPolicy with Django Expression objects (Exists, Value, etc.)."""

    def setUp(self):
        """Create test model classes."""
        class RelatedModel(RLSModel, models.Model):
            owner_id = models.IntegerField()

            class Meta:
                app_label = 'test_models'
                db_table = 'test_related'

        class TestModel(RLSModel, models.Model):
            name = models.CharField(max_length=100)
            owner_id = models.IntegerField()
            is_active = models.BooleanField(default=True)

            class Meta:
                app_label = 'test_models'
                db_table = 'test_expressions'

        self.TestModel = TestModel
        self.RelatedModel = RelatedModel

    def test_policy_with_exists(self):
        """Test creating policy with Exists subquery."""
        exists_subquery = Exists(
            self.RelatedModel.objects.filter(owner_id=F('owner_id'))
        )

        policy = RlsPolicy(
            role_name='app_user',
            command=PolicyCommand.SELECT,
            using=exists_subquery
        )

        assert policy.using == exists_subquery
        assert isinstance(policy.using, Exists)

    def test_policy_with_value(self):
        """Test creating policy with Value expression."""
        value_expr = Value(True)

        policy = RlsPolicy(
            role_name='app_user',
            command=PolicyCommand.SELECT,
            using=value_expr
        )

        assert policy.using == value_expr
        assert isinstance(policy.using, Value)

    def test_get_policy_sql_with_exists(self):
        """Test get_policy_sql generates correct SQL for Exists."""
        class TestModelWithExists(RLSModel, models.Model):
            name = models.CharField(max_length=100)
            owner_id = models.IntegerField()

            rls_policies = [
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.SELECT,
                    using=Exists(
                        self.RelatedModel.objects.filter(owner_id=F('owner_id'))
                    )
                ),
            ]

            class Meta:
                app_label = 'test_models'
                db_table = 'test_exists_policy'

        sql_statements = TestModelWithExists.get_policy_sql()
        assert len(sql_statements) == 1

        sql = sql_statements[0]
        assert 'CREATE POLICY' in sql
        assert 'ON test_exists_policy' in sql
        assert 'FOR SELECT' in sql
        assert 'TO app_user' in sql
        assert 'USING' in sql
        assert 'EXISTS' in sql.upper()

    def test_get_policy_sql_with_value(self):
        """Test get_policy_sql generates correct SQL for Value."""
        class TestModelWithValue(RLSModel, models.Model):
            name = models.CharField(max_length=100)

            rls_policies = [
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.SELECT,
                    using=Value(True)
                ),
            ]

            class Meta:
                app_label = 'test_models'
                db_table = 'test_value_policy'

        sql_statements = TestModelWithValue.get_policy_sql()
        assert len(sql_statements) == 1

        sql = sql_statements[0]
        assert 'CREATE POLICY' in sql
        assert 'ON test_value_policy' in sql
        assert 'FOR SELECT' in sql
        assert 'TO app_user' in sql
        assert 'USING' in sql
        # Value(True) should generate something like 'true' or '1'
        assert 'true' in sql.lower() or '1' in sql

    def test_policy_with_exists_and_with_check(self):
        """Test policy with Exists in both using and with_check."""
        exists_subquery = Exists(
            self.RelatedModel.objects.filter(owner_id=F('owner_id'))
        )

        policy = RlsPolicy(
            role_name='app_user',
            command=PolicyCommand.INSERT,
            using=Value(True),
            with_check=exists_subquery
        )

        assert isinstance(policy.using, Value)
        assert isinstance(policy.with_check, Exists)

    def test_expression_to_sql_exists(self):
        """Test _expression_to_sql method with Exists."""
        exists_expr = Exists(
            self.RelatedModel.objects.filter(owner_id=1)
        )

        sql = self.TestModel._expression_to_sql(exists_expr)

        # Should contain EXISTS and reference to the related table
        assert 'EXISTS' in sql.upper()
        assert 'test_related' in sql.lower()

    def test_expression_to_sql_value(self):
        """Test _expression_to_sql method with Value."""
        value_expr = Value(True)

        sql = self.TestModel._expression_to_sql(value_expr)

        # Should contain the boolean value
        assert 'true' in sql.lower() or '1' in sql

    def test_combined_q_and_exists(self):
        """Test policy can accept different expression types for using vs with_check."""
        q_obj = Q(is_active=True)
        exists_subquery = Exists(
            self.RelatedModel.objects.filter(owner_id=F('owner_id'))
        )

        policy = RlsPolicy(
            role_name='app_user',
            command=PolicyCommand.UPDATE,
            using=q_obj,
            with_check=exists_subquery
        )

        assert isinstance(policy.using, Q)
        assert isinstance(policy.with_check, Exists)
