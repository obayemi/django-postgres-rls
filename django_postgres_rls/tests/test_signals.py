"""
Tests for django_postgres_rls.signals module.

Tests cover:
- Model registration
- post_migrate signal handler
- Manual policy application functions
"""

import pytest
from unittest.mock import Mock, patch, MagicMock, call
from django.apps import AppConfig
from django.db import models
from django.test import TestCase

from django_postgres_rls import (
    RLSModel,
    RlsPolicy,
    PolicyCommand,
    register_rls_model,
    unregister_rls_model,
    get_registered_models,
    setup_rls_for_app,
    setup_rls_for_model,
)
from django_postgres_rls.signals import auto_apply_rls_policies


class TestModelRegistration(TestCase):
    """Test model registration for auto-apply."""

    def setUp(self):
        """Clear registry before each test."""
        # Clear the registry
        from django_postgres_rls.signals import _rls_model_registry
        _rls_model_registry.clear()

    def tearDown(self):
        """Clean up registry after each test."""
        from django_postgres_rls.signals import _rls_model_registry
        _rls_model_registry.clear()

    def test_register_rls_model(self):
        """Test registering a model."""
        class TestModel(RLSModel, models.Model):
            class Meta:
                app_label = 'test_signals'

        # Register model
        register_rls_model(TestModel)

        # Check it's in the registry
        registered = get_registered_models()
        assert TestModel in registered

    def test_register_rls_model_as_decorator(self):
        """Test using register_rls_model as a decorator."""
        @register_rls_model
        class TestModel(RLSModel, models.Model):
            class Meta:
                app_label = 'test_signals'

        # Check it's registered
        registered = get_registered_models()
        assert TestModel in registered

    def test_register_returns_model(self):
        """Test that register_rls_model returns the model unchanged."""
        class TestModel(RLSModel, models.Model):
            class Meta:
                app_label = 'test_signals'

        result = register_rls_model(TestModel)
        assert result is TestModel

    def test_register_multiple_models(self):
        """Test registering multiple models."""
        class TestModel1(RLSModel, models.Model):
            class Meta:
                app_label = 'test_signals'

        class TestModel2(RLSModel, models.Model):
            class Meta:
                app_label = 'test_signals'

        register_rls_model(TestModel1)
        register_rls_model(TestModel2)

        registered = get_registered_models()
        assert TestModel1 in registered
        assert TestModel2 in registered
        assert len(registered) == 2

    def test_register_same_model_twice(self):
        """Test registering the same model twice doesn't duplicate."""
        class TestModel(RLSModel, models.Model):
            class Meta:
                app_label = 'test_signals'

        register_rls_model(TestModel)
        register_rls_model(TestModel)

        registered = get_registered_models()
        assert registered.count(TestModel) == 1

    def test_unregister_rls_model(self):
        """Test unregistering a model."""
        class TestModel(RLSModel, models.Model):
            class Meta:
                app_label = 'test_signals'

        register_rls_model(TestModel)
        assert TestModel in get_registered_models()

        unregister_rls_model(TestModel)
        assert TestModel not in get_registered_models()

    def test_unregister_not_registered_model(self):
        """Test unregistering a model that wasn't registered."""
        class TestModel(RLSModel, models.Model):
            class Meta:
                app_label = 'test_signals'

        # Should not raise error
        unregister_rls_model(TestModel)

    def test_get_registered_models_returns_copy(self):
        """Test that get_registered_models returns a copy."""
        class TestModel(RLSModel, models.Model):
            class Meta:
                app_label = 'test_signals'

        register_rls_model(TestModel)

        registered1 = get_registered_models()
        registered2 = get_registered_models()

        # Should be equal but not the same object
        assert registered1 == registered2
        assert registered1 is not registered2

    def test_get_registered_models_empty(self):
        """Test get_registered_models when no models registered."""
        registered = get_registered_models()
        assert registered == []

    def test_auto_registration_of_rls_model_subclasses(self):
        """Test that RLSModel subclasses are automatically registered without @decorator."""
        # Clear any pending registrations first
        from django.apps import apps
        if hasattr(apps, '_pending_rls_registrations'):
            apps._pending_rls_registrations = []

        # Create a model that inherits from RLSModel
        # This should trigger __init_subclass__ and queue the model for registration
        class TestAutoModel(RLSModel, models.Model):
            rls_policies = [
                RlsPolicy(role_name='app_user', using='true'),
            ]

            class Meta:
                app_label = 'test_signals'
                db_table = 'test_auto_model'

        # Process pending registrations (simulating what happens in AppConfig.ready())
        if hasattr(apps, '_pending_rls_registrations'):
            for register_func in apps._pending_rls_registrations:
                try:
                    register_func()
                except Exception:
                    pass
            apps._pending_rls_registrations = []

        # Model should now be registered automatically
        registered = get_registered_models()
        assert TestAutoModel in registered

    def test_auto_registration_ignores_abstract_models(self):
        """Test that abstract RLSModel subclasses are not auto-registered."""
        # Clear any pending registrations first
        from django.apps import apps
        if hasattr(apps, '_pending_rls_registrations'):
            apps._pending_rls_registrations = []

        # Create an abstract model
        class AbstractTestModel(RLSModel, models.Model):
            class Meta:
                abstract = True
                app_label = 'test_signals'

        # Process pending registrations
        if hasattr(apps, '_pending_rls_registrations'):
            for register_func in apps._pending_rls_registrations:
                try:
                    register_func()
                except Exception:
                    pass
            apps._pending_rls_registrations = []

        # Abstract model should NOT be registered
        registered = get_registered_models()
        assert AbstractTestModel not in registered


class TestAutoApplyRLSPolicies(TestCase):
    """Test auto_apply_rls_policies signal handler."""

    def setUp(self):
        """Clear registry before each test."""
        from django_postgres_rls.signals import _rls_model_registry
        _rls_model_registry.clear()

    def tearDown(self):
        """Clean up registry after each test."""
        from django_postgres_rls.signals import _rls_model_registry
        _rls_model_registry.clear()

    @patch('django_postgres_rls.signals.apply_rls_policies')
    def test_auto_apply_no_registered_models(self, mock_apply):
        """Test signal handler with no registered models."""
        mock_app_config = Mock(spec=AppConfig)
        mock_app_config.label = 'test_signals'

        auto_apply_rls_policies(
            sender=None,
            app_config=mock_app_config,
            verbosity=1
        )

        # Should not call apply_rls_policies
        mock_apply.assert_not_called()

    @patch('django_postgres_rls.signals.apply_rls_policies')
    def test_auto_apply_with_registered_model(self, mock_apply):
        """Test signal handler with registered model."""
        class TestModel(RLSModel, models.Model):
            rls_policies = [
                RlsPolicy(role_name='app_user', using='true'),
            ]

            class Meta:
                app_label = 'test_signals'
                db_table = 'test_model'

        register_rls_model(TestModel)

        mock_app_config = Mock(spec=AppConfig)
        mock_app_config.label = 'test_signals'

        mock_apply.return_value = (1, 0)  # 1 created, 0 skipped

        auto_apply_rls_policies(
            sender=None,
            app_config=mock_app_config,
            verbosity=1
        )

        # Should call apply_rls_policies for the model
        mock_apply.assert_called_once_with(TestModel, verbosity=1)

    @patch('django_postgres_rls.signals.apply_rls_policies')
    def test_auto_apply_different_app(self, mock_apply):
        """Test signal handler with model from different app."""
        class TestModel(RLSModel, models.Model):
            rls_policies = [
                RlsPolicy(role_name='app_user', using='true'),
            ]

            class Meta:
                app_label = 'other_app'

        register_rls_model(TestModel)

        mock_app_config = Mock(spec=AppConfig)
        mock_app_config.label = 'test_signals'  # Different app

        auto_apply_rls_policies(
            sender=None,
            app_config=mock_app_config,
            verbosity=1
        )

        # Should not call apply_rls_policies (different app)
        mock_apply.assert_not_called()

    @patch('django_postgres_rls.signals.apply_rls_policies')
    def test_auto_apply_model_without_policies(self, mock_apply):
        """Test signal handler with model that has no policies."""
        class TestModel(RLSModel, models.Model):
            class Meta:
                app_label = 'test_signals'

        register_rls_model(TestModel)

        mock_app_config = Mock(spec=AppConfig)
        mock_app_config.label = 'test_signals'

        auto_apply_rls_policies(
            sender=None,
            app_config=mock_app_config,
            verbosity=1
        )

        # Should not call apply_rls_policies (no policies)
        mock_apply.assert_not_called()

    @patch('django_postgres_rls.signals.apply_rls_policies')
    def test_auto_apply_multiple_models(self, mock_apply):
        """Test signal handler with multiple registered models."""
        class TestModel1(RLSModel, models.Model):
            rls_policies = [RlsPolicy(role_name='app_user', using='true')]

            class Meta:
                app_label = 'test_signals'

        class TestModel2(RLSModel, models.Model):
            rls_policies = [RlsPolicy(role_name='app_staff', using='true')]

            class Meta:
                app_label = 'test_signals'

        register_rls_model(TestModel1)
        register_rls_model(TestModel2)

        mock_app_config = Mock(spec=AppConfig)
        mock_app_config.label = 'test_signals'

        mock_apply.return_value = (1, 0)

        auto_apply_rls_policies(
            sender=None,
            app_config=mock_app_config,
            verbosity=1
        )

        # Should call apply_rls_policies for both models
        assert mock_apply.call_count == 2

    @patch('django_postgres_rls.signals.apply_rls_policies')
    @patch('django_postgres_rls.signals.logger')
    def test_auto_apply_handles_errors(self, mock_logger, mock_apply):
        """Test signal handler handles errors gracefully."""
        class TestModel(RLSModel, models.Model):
            rls_policies = [RlsPolicy(role_name='app_user', using='true')]

            class Meta:
                app_label = 'test_signals'

        register_rls_model(TestModel)

        mock_app_config = Mock(spec=AppConfig)
        mock_app_config.label = 'test_signals'

        mock_apply.side_effect = Exception("Database error")

        # Should not raise exception
        auto_apply_rls_policies(
            sender=None,
            app_config=mock_app_config,
            verbosity=1
        )

        # Should log error
        mock_logger.error.assert_called()

    @patch('django_postgres_rls.signals.apply_rls_policies')
    def test_auto_apply_verbosity_levels(self, mock_apply):
        """Test signal handler with different verbosity levels."""
        class TestModel(RLSModel, models.Model):
            rls_policies = [RlsPolicy(role_name='app_user', using='true')]

            class Meta:
                app_label = 'test_signals'

        register_rls_model(TestModel)

        mock_app_config = Mock(spec=AppConfig)
        mock_app_config.label = 'test_signals'

        mock_apply.return_value = (1, 0)

        # Test different verbosity levels
        for verbosity in [0, 1, 2, 3]:
            auto_apply_rls_policies(
                sender=None,
                app_config=mock_app_config,
                verbosity=verbosity
            )

            # Should pass verbosity to apply_rls_policies
            mock_apply.assert_called_with(TestModel, verbosity=verbosity)


class TestSetupRLSForApp(TestCase):
    """Test setup_rls_for_app function."""

    @patch('django_postgres_rls.signals.apps.get_app_config')
    @patch('django_postgres_rls.signals.apply_rls_policies')
    def test_setup_rls_for_app_basic(self, mock_apply, mock_get_app):
        """Test basic app setup."""
        # Create mock models
        class TestModel1(RLSModel, models.Model):
            rls_policies = [RlsPolicy(role_name='app_user', using='true')]

            class Meta:
                app_label = 'test_signals'

        class TestModel2(RLSModel, models.Model):
            class Meta:
                app_label = 'test_signals'

        mock_app_config = Mock(spec=AppConfig)
        mock_app_config.get_models.return_value = [TestModel1, TestModel2]
        mock_get_app.return_value = mock_app_config

        mock_apply.return_value = (1, 0)

        setup_rls_for_app('test_app', verbosity=1)

        # Should call apply_rls_policies for TestModel1 only (has policies)
        mock_apply.assert_called_once_with(TestModel1, verbosity=1)

    @patch('django_postgres_rls.signals.apps.get_app_config')
    @patch('django_postgres_rls.signals.logger')
    def test_setup_rls_for_app_not_found(self, mock_logger, mock_get_app):
        """Test setup with non-existent app."""
        mock_get_app.side_effect = LookupError("App not found")

        setup_rls_for_app('nonexistent_app', verbosity=1)

        # Should log error
        mock_logger.error.assert_called()

    @patch('django_postgres_rls.signals.apps.get_app_config')
    def test_setup_rls_for_app_no_models(self, mock_get_app):
        """Test setup with app that has no RLS models."""
        mock_app_config = Mock(spec=AppConfig)
        mock_app_config.get_models.return_value = []
        mock_get_app.return_value = mock_app_config

        # Should not raise error
        setup_rls_for_app('test_app', verbosity=1)

    @patch('django_postgres_rls.signals.apps.get_app_config')
    @patch('django_postgres_rls.signals.apply_rls_policies')
    @patch('django_postgres_rls.signals.logger')
    def test_setup_rls_for_app_handles_errors(self, mock_logger, mock_apply, mock_get_app):
        """Test setup handles errors gracefully."""
        class TestModel(RLSModel, models.Model):
            rls_policies = [RlsPolicy(role_name='app_user', using='true')]

            class Meta:
                app_label = 'test_signals'

        mock_app_config = Mock(spec=AppConfig)
        mock_app_config.get_models.return_value = [TestModel]
        mock_get_app.return_value = mock_app_config

        mock_apply.side_effect = Exception("Database error")

        # Should not raise exception
        setup_rls_for_app('test_app', verbosity=1)

        # Should log error
        mock_logger.error.assert_called()


class TestSetupRLSForModel(TestCase):
    """Test setup_rls_for_model function."""

    @patch('django_postgres_rls.signals.apply_rls_policies')
    def test_setup_rls_for_model_basic(self, mock_apply):
        """Test basic model setup."""
        class TestModel(RLSModel, models.Model):
            rls_policies = [RlsPolicy(role_name='app_user', using='true')]

            class Meta:
                app_label = 'test_signals'

        mock_apply.return_value = (1, 0)

        setup_rls_for_model(TestModel, verbosity=1)

        # Should call apply_rls_policies
        mock_apply.assert_called_once_with(TestModel, verbosity=1)

    @patch('django_postgres_rls.signals.apply_rls_policies')
    @patch('django_postgres_rls.signals.logger')
    def test_setup_rls_for_model_no_policies(self, mock_logger, mock_apply):
        """Test setup for model without policies."""
        class TestModel(RLSModel, models.Model):
            class Meta:
                app_label = 'test_signals'

        setup_rls_for_model(TestModel, verbosity=1)

        # Should not call apply_rls_policies
        mock_apply.assert_not_called()

    @patch('django_postgres_rls.signals.apply_rls_policies')
    @patch('django_postgres_rls.signals.logger')
    def test_setup_rls_for_model_handles_errors(self, mock_logger, mock_apply):
        """Test setup handles errors."""
        class TestModel(RLSModel, models.Model):
            rls_policies = [RlsPolicy(role_name='app_user', using='true')]

            class Meta:
                app_label = 'test_signals'

        mock_apply.side_effect = Exception("Database error")

        # Should raise the exception
        with pytest.raises(Exception):
            setup_rls_for_model(TestModel, verbosity=1)

        # Should log error
        mock_logger.error.assert_called()

    @patch('django_postgres_rls.signals.apply_rls_policies')
    def test_setup_rls_for_model_verbosity_levels(self, mock_apply):
        """Test setup with different verbosity levels."""
        class TestModel(RLSModel, models.Model):
            rls_policies = [RlsPolicy(role_name='app_user', using='true')]

            class Meta:
                app_label = 'test_signals'

        mock_apply.return_value = (1, 0)

        # Test different verbosity levels
        for verbosity in [0, 1, 2]:
            setup_rls_for_model(TestModel, verbosity=verbosity)
            mock_apply.assert_called_with(TestModel, verbosity=verbosity)


class TestIntegration(TestCase):
    """Integration tests combining multiple components."""

    def setUp(self):
        """Clear registry before each test."""
        from django_postgres_rls.signals import _rls_model_registry
        _rls_model_registry.clear()

    def tearDown(self):
        """Clean up registry after each test."""
        from django_postgres_rls.signals import _rls_model_registry
        _rls_model_registry.clear()

    @patch('django_postgres_rls.signals.apply_rls_policies')
    def test_register_and_auto_apply(self, mock_apply):
        """Test full workflow: register model and auto-apply on migrate."""
        @register_rls_model
        class TestModel(RLSModel, models.Model):
            rls_policies = [RlsPolicy(role_name='app_user', using='true')]

            class Meta:
                app_label = 'test_signals'

        # Verify registration
        assert TestModel in get_registered_models()

        # Simulate post_migrate signal
        mock_app_config = Mock(spec=AppConfig)
        mock_app_config.label = 'test_signals'

        mock_apply.return_value = (1, 0)

        auto_apply_rls_policies(
            sender=None,
            app_config=mock_app_config,
            verbosity=1
        )

        # Verify apply was called
        mock_apply.assert_called_once()

    @patch('django_postgres_rls.signals.apps.get_app_config')
    @patch('django_postgres_rls.signals.apply_rls_policies')
    def test_setup_multiple_models_in_app(self, mock_apply, mock_get_app):
        """Test setting up multiple models in the same app."""
        class TestModel1(RLSModel, models.Model):
            rls_policies = [RlsPolicy(role_name='app_user', using='true')]

            class Meta:
                app_label = 'test_signals'

        class TestModel2(RLSModel, models.Model):
            rls_policies = [RlsPolicy(role_name='app_staff', using='true')]

            class Meta:
                app_label = 'test_signals'

        mock_app_config = Mock(spec=AppConfig)
        mock_app_config.get_models.return_value = [TestModel1, TestModel2]
        mock_get_app.return_value = mock_app_config

        mock_apply.return_value = (1, 0)

        setup_rls_for_app('test_app', verbosity=1)

        # Should call apply for both models
        assert mock_apply.call_count == 2


class TestAutoCreateRLSRoles(TestCase):
    """Test auto_create_rls_roles signal handler for automatic role creation."""

    def tearDown(self):
        """Clean up the processed flag after each test."""
        from django_postgres_rls.signals import auto_create_rls_roles
        if hasattr(auto_create_rls_roles, '_processed'):
            delattr(auto_create_rls_roles, '_processed')

    @patch('django_postgres_rls.signals.connection')
    @patch('django_postgres_rls.signals.settings')
    def test_auto_create_roles_enabled_by_default(self, mock_settings, mock_connection):
        """Test that role auto-creation is enabled by default."""
        from django_postgres_rls.signals import auto_create_rls_roles

        # Setup mocks
        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user', 'app_staff']
        mock_connection.vendor = 'postgresql'

        mock_cursor = MagicMock()
        mock_cursor.__enter__ = Mock(return_value=mock_cursor)
        mock_cursor.__exit__ = Mock(return_value=False)
        mock_cursor.fetchall.return_value = []  # No existing roles
        mock_connection.cursor.return_value = mock_cursor

        mock_app_config = Mock(spec=AppConfig)
        mock_app_config.label = 'test_signals'

        # Call handler - should use default True for POSTGRES_RLS_AUTO_CREATE_ROLES
        auto_create_rls_roles(
            sender=None,
            app_config=mock_app_config,
            verbosity=1
        )

        # Should have queried for existing roles
        assert mock_cursor.execute.called
        # Should have attempted to create roles
        assert mock_cursor.execute.call_count >= 3  # Query + 2 roles created

    @patch('django_postgres_rls.signals.connection')
    @patch('django_postgres_rls.signals.settings')
    def test_auto_create_roles_can_be_disabled(self, mock_settings, mock_connection):
        """Test that role auto-creation can be explicitly disabled."""
        from django_postgres_rls.signals import auto_create_rls_roles

        # Setup mocks - explicitly disable
        mock_settings.POSTGRES_RLS_AUTO_CREATE_ROLES = False
        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user']
        mock_connection.vendor = 'postgresql'

        mock_app_config = Mock(spec=AppConfig)
        mock_app_config.label = 'test_signals'

        # Call handler
        auto_create_rls_roles(
            sender=None,
            app_config=mock_app_config,
            verbosity=1
        )

        # Should not attempt to create roles
        mock_connection.cursor.assert_not_called()

    @patch('django_postgres_rls.signals.connection')
    @patch('django_postgres_rls.signals.settings')
    def test_auto_create_roles_creates_missing_roles(self, mock_settings, mock_connection):
        """Test that missing roles are created."""
        from django_postgres_rls.signals import auto_create_rls_roles

        # Setup mocks
        mock_settings.POSTGRES_RLS_AUTO_CREATE_ROLES = True
        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user', 'app_staff']
        mock_connection.vendor = 'postgresql'

        mock_cursor = MagicMock()
        mock_cursor.__enter__ = Mock(return_value=mock_cursor)
        mock_cursor.__exit__ = Mock(return_value=False)
        mock_cursor.fetchall.return_value = []  # No existing roles
        mock_connection.cursor.return_value = mock_cursor

        mock_app_config = Mock(spec=AppConfig)
        mock_app_config.label = 'test_signals'

        # Call handler
        auto_create_rls_roles(
            sender=None,
            app_config=mock_app_config,
            verbosity=2
        )

        # Verify SQL commands executed
        execute_calls = [str(call) for call in mock_cursor.execute.call_args_list]

        # Should query existing roles
        assert any('pg_roles' in str(call) for call in execute_calls)

        # Should create both roles
        assert any('app_user' in str(call) for call in execute_calls)
        assert any('app_staff' in str(call) for call in execute_calls)

    @patch('django_postgres_rls.signals.connection')
    @patch('django_postgres_rls.signals.settings')
    def test_auto_create_roles_skips_existing_roles(self, mock_settings, mock_connection):
        """Test that existing roles are not recreated."""
        from django_postgres_rls.signals import auto_create_rls_roles

        # Setup mocks
        mock_settings.POSTGRES_RLS_AUTO_CREATE_ROLES = True
        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user', 'app_staff']
        mock_connection.vendor = 'postgresql'

        mock_cursor = MagicMock()
        mock_cursor.__enter__ = Mock(return_value=mock_cursor)
        mock_cursor.__exit__ = Mock(return_value=False)
        # app_user already exists
        mock_cursor.fetchall.return_value = [('app_user',)]
        mock_connection.cursor.return_value = mock_cursor

        mock_app_config = Mock(spec=AppConfig)
        mock_app_config.label = 'test_signals'

        # Call handler
        auto_create_rls_roles(
            sender=None,
            app_config=mock_app_config,
            verbosity=2
        )

        # Verify SQL commands
        execute_calls = [str(call) for call in mock_cursor.execute.call_args_list]

        # Should create app_staff but not app_user
        assert any('app_staff' in str(call) for call in execute_calls)
        # app_user should only appear in the query, not in CREATE statements
        create_calls = [call for call in execute_calls if 'CREATE ROLE' in str(call)]
        assert not any('app_user' in str(call) for call in create_calls)

    @patch('django_postgres_rls.signals.connection')
    @patch('django_postgres_rls.signals.settings')
    def test_auto_create_roles_skips_non_postgresql(self, mock_settings, mock_connection):
        """Test that role creation is skipped for non-PostgreSQL databases."""
        from django_postgres_rls.signals import auto_create_rls_roles

        # Setup mocks - not PostgreSQL
        mock_settings.POSTGRES_RLS_AUTO_CREATE_ROLES = True
        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user']
        mock_connection.vendor = 'sqlite'  # Not PostgreSQL

        mock_app_config = Mock(spec=AppConfig)
        mock_app_config.label = 'test_signals'

        # Call handler
        auto_create_rls_roles(
            sender=None,
            app_config=mock_app_config,
            verbosity=1
        )

        # Should not attempt to create roles
        mock_connection.cursor.assert_not_called()

    @patch('django_postgres_rls.signals.connection')
    @patch('django_postgres_rls.signals.settings')
    def test_auto_create_roles_handles_no_config(self, mock_settings, mock_connection):
        """Test behavior when POSTGRES_RLS_VALID_ROLES is not configured."""
        from django_postgres_rls.signals import auto_create_rls_roles

        # Setup mocks - no valid roles configured
        mock_settings.POSTGRES_RLS_AUTO_CREATE_ROLES = True
        mock_settings.POSTGRES_RLS_VALID_ROLES = None
        mock_connection.vendor = 'postgresql'

        mock_app_config = Mock(spec=AppConfig)
        mock_app_config.label = 'test_signals'

        # Call handler
        auto_create_rls_roles(
            sender=None,
            app_config=mock_app_config,
            verbosity=1
        )

        # Should not attempt to create roles
        mock_connection.cursor.assert_not_called()

    @patch('django_postgres_rls.signals.connection')
    @patch('django_postgres_rls.signals.settings')
    @patch('django_postgres_rls.signals.logger')
    def test_auto_create_roles_handles_creation_errors(self, mock_logger, mock_settings, mock_connection):
        """Test that role creation errors are handled gracefully."""
        from django_postgres_rls.signals import auto_create_rls_roles

        # Setup mocks
        mock_settings.POSTGRES_RLS_AUTO_CREATE_ROLES = True
        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user']
        mock_connection.vendor = 'postgresql'

        mock_cursor = MagicMock()
        mock_cursor.__enter__ = Mock(return_value=mock_cursor)
        mock_cursor.__exit__ = Mock(return_value=False)
        mock_cursor.fetchall.return_value = []
        # Simulate permission error when creating role
        mock_cursor.execute.side_effect = [
            None,  # First call (SELECT from pg_roles) succeeds
            Exception("permission denied to create role")  # Second call fails
        ]
        mock_connection.cursor.return_value = mock_cursor

        mock_app_config = Mock(spec=AppConfig)
        mock_app_config.label = 'test_signals'

        # Call handler - should not raise exception
        auto_create_rls_roles(
            sender=None,
            app_config=mock_app_config,
            verbosity=1
        )

        # Should log warning about failed creation
        assert mock_logger.warning.called

    @patch('django_postgres_rls.signals.connection')
    @patch('django_postgres_rls.signals.settings')
    def test_auto_create_roles_only_runs_once(self, mock_settings, mock_connection):
        """Test that role creation only runs once per migrate command."""
        from django_postgres_rls.signals import auto_create_rls_roles

        # Setup mocks
        mock_settings.POSTGRES_RLS_AUTO_CREATE_ROLES = True
        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user']
        mock_connection.vendor = 'postgresql'

        mock_cursor = MagicMock()
        mock_cursor.__enter__ = Mock(return_value=mock_cursor)
        mock_cursor.__exit__ = Mock(return_value=False)
        mock_cursor.fetchall.return_value = []
        mock_connection.cursor.return_value = mock_cursor

        mock_app_config = Mock(spec=AppConfig)
        mock_app_config.label = 'test_signals'

        # Call handler twice (simulating multiple apps)
        auto_create_rls_roles(
            sender=None,
            app_config=mock_app_config,
            verbosity=1
        )

        call_count_first = mock_cursor.execute.call_count

        auto_create_rls_roles(
            sender=None,
            app_config=mock_app_config,
            verbosity=1
        )

        # Should not execute again
        assert mock_cursor.execute.call_count == call_count_first

    @patch('django_postgres_rls.signals.connection')
    @patch('django_postgres_rls.signals.settings')
    def test_auto_create_roles_grants_to_current_user(self, mock_settings, mock_connection):
        """Test that created roles are granted to the current database user."""
        from django_postgres_rls.signals import auto_create_rls_roles

        # Setup mocks
        mock_settings.POSTGRES_RLS_AUTO_CREATE_ROLES = True
        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user']
        mock_connection.vendor = 'postgresql'

        mock_cursor = MagicMock()
        mock_cursor.__enter__ = Mock(return_value=mock_cursor)
        mock_cursor.__exit__ = Mock(return_value=False)
        mock_cursor.fetchall.return_value = []  # No existing roles
        mock_connection.cursor.return_value = mock_cursor

        mock_app_config = Mock(spec=AppConfig)
        mock_app_config.label = 'test_signals'

        # Call handler
        auto_create_rls_roles(
            sender=None,
            app_config=mock_app_config,
            verbosity=1
        )

        # Verify GRANT command was executed
        execute_calls = [str(call) for call in mock_cursor.execute.call_args_list]
        assert any('GRANT' in str(call) and 'CURRENT_USER' in str(call) for call in execute_calls)

    def test_cleanup_flag_after_post_migrate(self):
        """Test that the processed flag is cleaned up after migrations."""
        from django_postgres_rls.signals import auto_create_rls_roles, cleanup_auto_create_flag

        # Set the flag
        auto_create_rls_roles._processed = True
        assert hasattr(auto_create_rls_roles, '_processed')

        # Call cleanup
        cleanup_auto_create_flag(sender=None)

        # Flag should be removed
        assert not hasattr(auto_create_rls_roles, '_processed')

    @patch('django_postgres_rls.signals.connection')
    @patch('django_postgres_rls.signals.settings')
    def test_auto_create_roles_verbosity_output(self, mock_settings, mock_connection):
        """Test logging output at different verbosity levels."""
        from django_postgres_rls.signals import auto_create_rls_roles

        # Setup mocks
        mock_settings.POSTGRES_RLS_AUTO_CREATE_ROLES = True
        mock_settings.POSTGRES_RLS_VALID_ROLES = ['app_user', 'app_staff']
        mock_connection.vendor = 'postgresql'

        mock_cursor = MagicMock()
        mock_cursor.__enter__ = Mock(return_value=mock_cursor)
        mock_cursor.__exit__ = Mock(return_value=False)
        mock_cursor.fetchall.return_value = [('app_user',)]  # One existing role
        mock_connection.cursor.return_value = mock_cursor

        mock_app_config = Mock(spec=AppConfig)
        mock_app_config.label = 'test_signals'

        # Test with high verbosity
        with patch('django_postgres_rls.signals.logger') as mock_logger:
            auto_create_rls_roles(
                sender=None,
                app_config=mock_app_config,
                verbosity=2
            )

            # Should log detailed information at verbosity >= 2
            assert mock_logger.info.called
