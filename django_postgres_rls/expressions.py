"""
Database expressions for PostgreSQL RLS.

This module provides Django ORM-compatible expressions for accessing
PostgreSQL-specific features in RLS policies.
"""

from django.db.models import Func, IntegerField, Value, BooleanField, CharField


class SessionVar(Func):
    """
    Database expression for accessing PostgreSQL session variables (configuration parameters).

    This allows you to reference PostgreSQL session variables set via `set_config()`
    in RLS policies, similar to how Django's F() objects reference model fields.

    The expression compiles to `current_setting('variable_name', missing_ok)::cast_type`
    which can be used in WHERE clauses, including RLS policy USING expressions.

    Args:
        variable_name: The PostgreSQL configuration parameter name (e.g., 'app.current_user_id')
        output_field: Django field instance for type casting (default: IntegerField)
        missing_ok: If True, returns NULL when variable doesn't exist instead of raising error

    Examples:
        # Basic usage in RLS policy
        from django_postgres_rls.expressions import SessionVar

        RlsPolicy(
            role_name='app_user',
            command=PolicyCommand.SELECT,
            using=Q(owner_id=SessionVar('app.current_user_id'))
        )

        # With explicit type casting
        RlsPolicy(
            role_name='app_user',
            command=PolicyCommand.SELECT,
            using=Q(owner_id=SessionVar('app.current_user_id', output_field=IntegerField()))
        )

        # Handle missing variables gracefully
        RlsPolicy(
            role_name='app_user',
            command=PolicyCommand.SELECT,
            using=Q(owner_id=SessionVar('app.current_user_id', missing_ok=True))
        )

        # Complex policies
        RlsPolicy(
            role_name='app_user',
            command=PolicyCommand.SELECT,
            using=(
                Q(is_public=True) |
                Q(owner_id=SessionVar('app.current_user_id')) |
                Q(organization_id=SessionVar('app.current_org_id'))
            )
        )

        # Use in queries (though typically used in RLS policies)
        MyModel.objects.filter(
            owner_id=SessionVar('app.current_user_id')
        )
    """

    function = 'current_setting'
    arity = 2  # Two arguments: variable_name and missing_ok

    def __init__(self, variable_name, output_field=None, missing_ok=False, **extra):
        """
        Initialize SessionVar expression.

        Args:
            variable_name: PostgreSQL configuration parameter name
            output_field: Django field for type casting (default: IntegerField)
            missing_ok: If True, returns NULL when variable doesn't exist
            **extra: Additional arguments passed to Func
        """
        if output_field is None:
            output_field = IntegerField()

        # Wrap arguments in Value() expressions so they compile correctly
        variable_name_expr = Value(variable_name, output_field=CharField())
        missing_ok_expr = Value(missing_ok, output_field=BooleanField())

        # Pass the wrapped expressions as arguments to Func
        super().__init__(
            variable_name_expr,
            missing_ok_expr,
            output_field=output_field,
            **extra
        )
        self.variable_name = variable_name
        self.missing_ok = missing_ok

    def as_sql(self, compiler, connection, **extra_context):
        """
        Compile the expression to SQL.

        Returns SQL like: current_setting('app.current_user_id', false)::integer
        """
        # Get the base SQL from Func (current_setting('...', ...))
        sql, params = super().as_sql(compiler, connection, **extra_context)

        # Add type casting based on output_field
        if self.output_field:
            # Get the PostgreSQL type for the output field
            db_type = self.output_field.db_type(connection)
            if db_type:
                sql = f"({sql})::{db_type}"

        return sql, params

    def as_postgresql(self, compiler, connection, **extra_context):
        """PostgreSQL-specific compilation."""
        return self.as_sql(compiler, connection, **extra_context)

    def __repr__(self):
        return f"SessionVar('{self.variable_name}', missing_ok={self.missing_ok})"


class CurrentUserId(SessionVar):
    """
    Convenience expression for accessing the current user ID.

    This is a shortcut for SessionVar('app.current_user_id'), which is
    the most common session variable used in RLS policies.

    Example:
        from django_postgres_rls.expressions import CurrentUserId

        RlsPolicy(
            role_name='app_user',
            command=PolicyCommand.SELECT,
            using=Q(owner_id=CurrentUserId())
        )
    """

    def __init__(self, output_field=None, missing_ok=False, **extra):
        super().__init__(
            'app.current_user_id',
            output_field=output_field,
            missing_ok=missing_ok,
            **extra
        )

    def __repr__(self):
        return f"CurrentUserId(missing_ok={self.missing_ok})"
