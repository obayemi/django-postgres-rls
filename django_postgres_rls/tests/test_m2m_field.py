"""
Tests for RlsManyToManyField.
"""

from django.test import TestCase
from django.db import models
from django.db.models import Q, F

from django_postgres_rls import RlsManyToManyField, RlsPolicy, PolicyCommand, CurrentUserId


class TestRlsManyToManyField(TestCase):
    """Test RlsManyToManyField functionality."""

    def test_field_initialization(self):
        """Test that field can be initialized with rls_policies."""
        policies = [
            RlsPolicy(
                role_name='app_user',
                command=PolicyCommand.ALL,
                using=Q(owner_id=CurrentUserId())
            )
        ]

        field = RlsManyToManyField(
            'auth.User',
            rls_policies=policies
        )

        assert field.rls_policies == policies

    def test_field_initialization_without_policies(self):
        """Test that field works without rls_policies."""
        field = RlsManyToManyField('auth.User')

        assert field.rls_policies == []

    def test_field_with_auto_through_model(self):
        """Test that policies are attached to auto-generated through model."""
        # Create a simple model with M2M field
        policies = [
            RlsPolicy(
                role_name='app_user',
                command=PolicyCommand.SELECT,
                using=Q(owner_id=CurrentUserId())
            )
        ]

        class M2MTestDocument(models.Model):
            title = models.CharField(max_length=100)
            tags = RlsManyToManyField(
                'auth.User',
                rls_policies=policies,
                related_name='tagged_m2m_documents'
            )

            class Meta:
                app_label = 'test_m2m_field'

        # The through model should be created and have the policies
        # Note: In a real Django app, this happens during app ready
        # For testing, we manually call the callback
        if hasattr(M2MTestDocument, '_rls_m2m_callbacks'):
            for field_name, callback in M2MTestDocument._rls_m2m_callbacks:
                callback()

        # Get the through model from the field
        field = M2MTestDocument._meta.get_field('tags')
        through_model = field.remote_field.through

        # Check if get_rls_policies method exists
        assert hasattr(through_model, 'get_rls_policies')

        # Get policies from through model
        through_policies = through_model.get_rls_policies()
        assert len(through_policies) == 1
        assert through_policies[0].role_name == 'app_user'
        assert through_policies[0].command == PolicyCommand.SELECT

    def test_field_with_explicit_through_model(self):
        """Test that policies work with explicit through models."""
        # Create explicit through model
        class M2MDocumentTag(models.Model):
            document = models.ForeignKey('M2MTestDocument2', on_delete=models.CASCADE)
            user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
            added_at = models.DateTimeField(auto_now_add=True)

            class Meta:
                app_label = 'test_m2m_field'

        policies = [
            RlsPolicy(
                role_name='app_user',
                command=PolicyCommand.ALL,
                using=Q(document__owner_id=CurrentUserId())
            )
        ]

        class M2MTestDocument2(models.Model):
            title = models.CharField(max_length=100)
            owner_id = models.IntegerField()
            tags = RlsManyToManyField(
                'auth.User',
                through=M2MDocumentTag,
                rls_policies=policies,
                related_name='tagged_m2m_documents2'
            )

            class Meta:
                app_label = 'test_m2m_field'

        # Manually trigger callbacks
        if hasattr(M2MTestDocument2, '_rls_m2m_callbacks'):
            for field_name, callback in M2MTestDocument2._rls_m2m_callbacks:
                callback()

        # The explicit through model should have policies
        assert hasattr(M2MDocumentTag, 'get_rls_policies')
        through_policies = M2MDocumentTag.get_rls_policies()
        assert len(through_policies) == 1

    def test_field_deconstruction(self):
        """Test that field can be deconstructed for migrations."""
        policies = [
            RlsPolicy(
                role_name='app_user',
                command=PolicyCommand.SELECT,
                using="true"
            )
        ]

        field = RlsManyToManyField(
            'auth.User',
            rls_policies=policies,
            related_name='test_related'
        )

        name, path, args, kwargs = field.deconstruct()

        # Check that rls_policies is in kwargs
        assert 'rls_policies' in kwargs
        assert kwargs['rls_policies'] == policies
        assert kwargs['related_name'] == 'test_related'

    def test_field_deconstruction_without_policies(self):
        """Test deconstruction when no policies are provided."""
        field = RlsManyToManyField(
            'auth.User',
            related_name='test_related'
        )

        name, path, args, kwargs = field.deconstruct()

        # rls_policies should not be in kwargs if empty
        assert 'rls_policies' not in kwargs
        assert kwargs['related_name'] == 'test_related'

    def test_multiple_policies_on_through_model(self):
        """Test that multiple policies can be attached to through model."""
        policies = [
            RlsPolicy(
                role_name='app_user',
                command=PolicyCommand.SELECT,
                using=Q(owner_id=F('current_user_id'))
            ),
            RlsPolicy(
                role_name='app_staff',
                command=PolicyCommand.ALL,
                using="true"
            ),
            RlsPolicy(
                role_name='app_user',
                command=PolicyCommand.INSERT,
                with_check=Q(owner_id=F('current_user_id'))
            ),
        ]

        class M2MTestDocument3(models.Model):
            title = models.CharField(max_length=100)
            collaborators = RlsManyToManyField(
                'auth.User',
                rls_policies=policies,
                related_name='collaborated_m2m_docs'
            )

            class Meta:
                app_label = 'test_m2m_field'

        # Trigger callbacks
        if hasattr(M2MTestDocument3, '_rls_m2m_callbacks'):
            for field_name, callback in M2MTestDocument3._rls_m2m_callbacks:
                callback()

        field = M2MTestDocument3._meta.get_field('collaborators')
        through_model = field.remote_field.through
        through_policies = through_model.get_rls_policies()

        assert len(through_policies) == 3
        assert through_policies[0].role_name == 'app_user'
        assert through_policies[1].role_name == 'app_staff'
        assert through_policies[2].command == PolicyCommand.INSERT

    def test_through_model_has_get_table_name(self):
        """Test that through model gets get_table_name method."""
        policies = [
            RlsPolicy(
                role_name='app_user',
                command=PolicyCommand.ALL,
                using="true"
            )
        ]

        class M2MTestDocument4(models.Model):
            title = models.CharField(max_length=100)
            members = RlsManyToManyField(
                'auth.User',
                rls_policies=policies,
                related_name='member_m2m_docs'
            )

            class Meta:
                app_label = 'test_m2m_field'

        # Trigger callbacks
        if hasattr(M2MTestDocument4, '_rls_m2m_callbacks'):
            for field_name, callback in M2MTestDocument4._rls_m2m_callbacks:
                callback()

        field = M2MTestDocument4._meta.get_field('members')
        through_model = field.remote_field.through

        # Should have get_table_name method
        assert hasattr(through_model, 'get_table_name')

        # Should return the table name
        table_name = through_model.get_table_name()
        assert table_name is not None
        assert isinstance(table_name, str)

    def test_field_inheritance(self):
        """Test that RlsManyToManyField is properly a subclass of ManyToManyField."""
        field = RlsManyToManyField('auth.User')

        # Should be instance of both
        assert isinstance(field, models.ManyToManyField)
        assert isinstance(field, RlsManyToManyField)

    def test_field_with_all_m2m_kwargs(self):
        """Test that field works with all standard ManyToManyField kwargs."""
        policies = [
            RlsPolicy(
                role_name='app_user',
                command=PolicyCommand.ALL,
                using="true"
            )
        ]

        field = RlsManyToManyField(
            'auth.User',
            rls_policies=policies,
            related_name='test_related',
            related_query_name='test_query',
            symmetrical=False,
            blank=True,
            db_table='custom_through_table',
        )

        # Should preserve all kwargs
        assert field.rls_policies == policies
        assert field.remote_field.related_name == 'test_related'
        assert field.blank is True
