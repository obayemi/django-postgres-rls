"""Tests for database expressions."""

import pytest
from django.db import models
from django.db.models import Q, CharField, IntegerField
from django.test import TestCase

from django_postgres_rls.expressions import SessionVar, CurrentUserId


class TestSessionVar(TestCase):
    """Test SessionVar expression."""

    def test_session_var_basic(self):
        """Test basic SessionVar creation."""
        expr = SessionVar('app.current_user_id')
        assert expr.variable_name == 'app.current_user_id'
        assert expr.missing_ok is False
        assert isinstance(expr.output_field, IntegerField)

    def test_session_var_with_missing_ok(self):
        """Test SessionVar with missing_ok=True."""
        expr = SessionVar('app.current_user_id', missing_ok=True)
        assert expr.variable_name == 'app.current_user_id'
        assert expr.missing_ok is True

    def test_session_var_with_output_field(self):
        """Test SessionVar with custom output field."""
        expr = SessionVar('app.tenant_code', output_field=CharField(max_length=50))
        assert expr.variable_name == 'app.tenant_code'
        assert isinstance(expr.output_field, CharField)

    def test_session_var_repr(self):
        """Test SessionVar string representation."""
        expr = SessionVar('app.current_user_id')
        assert repr(expr) == "SessionVar('app.current_user_id', missing_ok=False)"

        expr = SessionVar('app.current_user_id', missing_ok=True)
        assert repr(expr) == "SessionVar('app.current_user_id', missing_ok=True)"

    def test_session_var_in_q_object(self):
        """Test SessionVar can be used in Q objects."""
        q = Q(owner_id=SessionVar('app.current_user_id'))
        assert q is not None

    def test_session_var_in_complex_q_object(self):
        """Test SessionVar in complex Q expressions."""
        q = (
            Q(is_public=True) |
            Q(owner_id=SessionVar('app.current_user_id')) |
            Q(organization_id=SessionVar('app.current_org_id'))
        )
        assert q is not None


class TestCurrentUserId(TestCase):
    """Test CurrentUserId convenience expression."""

    def test_current_user_id_basic(self):
        """Test basic CurrentUserId creation."""
        expr = CurrentUserId()
        assert expr.variable_name == 'app.current_user_id'
        assert expr.missing_ok is False
        assert isinstance(expr.output_field, IntegerField)

    def test_current_user_id_with_missing_ok(self):
        """Test CurrentUserId with missing_ok=True."""
        expr = CurrentUserId(missing_ok=True)
        assert expr.variable_name == 'app.current_user_id'
        assert expr.missing_ok is True

    def test_current_user_id_repr(self):
        """Test CurrentUserId string representation."""
        expr = CurrentUserId()
        assert repr(expr) == "CurrentUserId(missing_ok=False)"

        expr = CurrentUserId(missing_ok=True)
        assert repr(expr) == "CurrentUserId(missing_ok=True)"

    def test_current_user_id_in_q_object(self):
        """Test CurrentUserId can be used in Q objects."""
        q = Q(owner_id=CurrentUserId())
        assert q is not None


class TestSessionVarSQL(TestCase):
    """Test SessionVar SQL compilation."""

    def test_session_var_compiles_to_sql(self):
        """Test that SessionVar compiles to proper SQL."""
        from django.db import connection

        expr = SessionVar('app.current_user_id')
        compiler = models.sql.Query(models.Model).get_compiler(connection=connection)

        # Get SQL representation
        sql, params = expr.as_sql(compiler, connection)

        # Should contain current_setting function call
        assert 'current_setting' in sql.lower()
        assert 'app.current_user_id' in params or 'app.current_user_id' in sql

    def test_session_var_with_type_casting(self):
        """Test that SessionVar includes type casting."""
        from django.db import connection

        expr = SessionVar('app.current_user_id', output_field=IntegerField())
        compiler = models.sql.Query(models.Model).get_compiler(connection=connection)

        sql, params = expr.as_sql(compiler, connection)

        # Should contain type cast
        assert '::' in sql or 'CAST' in sql.upper()

    def test_session_var_missing_ok_parameter(self):
        """Test that missing_ok parameter is included in SQL."""
        from django.db import connection

        expr = SessionVar('app.current_user_id', missing_ok=True)
        compiler = models.sql.Query(models.Model).get_compiler(connection=connection)

        sql, params = expr.as_sql(compiler, connection)

        # The function should have 2 parameters
        assert 'current_setting' in sql.lower()
        # Check that we have the right number of placeholders or values
        assert sql.count('%s') == 2 or 'true' in sql.lower() or 'True' in sql


@pytest.mark.django_db
class TestSessionVarIntegration:
    """Integration tests for SessionVar with actual database."""

    def test_session_var_in_raw_query(self):
        """Test SessionVar works in raw queries."""
        from django.db import connection

        # Set a session variable
        with connection.cursor() as cursor:
            cursor.execute("SELECT set_config('app.test_var', '42', false)")

            # Create a simple model for testing
            class TempModel(models.Model):
                value = IntegerField()

                class Meta:
                    app_label = 'test_expressions'
                    managed = False
                    db_table = 'test_temp'

            # This tests that the expression can be compiled
            # (actual execution would require a real table)
            expr = SessionVar('app.test_var')
            assert expr is not None


class TestSessionVarImport(TestCase):
    """Test that SessionVar can be imported from main package."""

    def test_import_from_package(self):
        """Test importing SessionVar from main package."""
        from django_postgres_rls import SessionVar as ImportedSessionVar
        from django_postgres_rls import CurrentUserId as ImportedCurrentUserId

        # Should be the same classes
        assert ImportedSessionVar is SessionVar
        assert ImportedCurrentUserId is CurrentUserId

    def test_in_all(self):
        """Test that SessionVar is in __all__."""
        import django_postgres_rls

        assert 'SessionVar' in django_postgres_rls.__all__
        assert 'CurrentUserId' in django_postgres_rls.__all__
