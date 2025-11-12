"""
Django PostgreSQL Row-Level Security (RLS) Models and Policy Configuration.

This module provides model mixins and dataclasses for defining RLS policies
declaratively in Django model Meta classes.
"""

from dataclasses import dataclass
from typing import Optional, Union, List
from django.db import models
from django.db.models import Q, Exists, Value
from django.db.models.expressions import Expression


class RlsUser:
    """
    Mixin for User models to define their PostgreSQL role.

    When this mixin is added to a User model and the `get_postgres_role()` method
    is implemented, the PostgresRLSMiddleware will automatically call this method
    to determine the user's PostgreSQL role, eliminating the need to override
    `extract_role()` in the middleware.

    Example:
        from django.contrib.auth.models import AbstractUser
        from django_postgres_rls import RlsUser

        class User(RlsUser, AbstractUser):
            organization = models.ForeignKey(Organization, on_delete=models.CASCADE)

            def get_postgres_role(self):
                '''Return the PostgreSQL role for this user.'''
                if self.is_superuser:
                    return 'app_superuser'
                elif self.is_staff:
                    return 'app_staff'
                elif self.organization.is_premium:
                    return 'app_premium_user'
                return 'app_user'
    """

    def get_postgres_role(self) -> Optional[str]:
        """
        Return the PostgreSQL role for this user.

        This method should be overridden in your User model to return the
        appropriate PostgreSQL role name based on user attributes.

        Returns:
            PostgreSQL role name (e.g., 'app_user', 'app_staff', 'app_superuser'),
            or None if no role should be set.

        Example:
            def get_postgres_role(self):
                if self.is_superuser:
                    return 'app_superuser'
                elif self.is_staff:
                    return 'app_staff'
                return 'app_user'
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement get_postgres_role() method "
            "to return the PostgreSQL role for this user."
        )


# Constants for policy commands
class PolicyCommand:
    """Constants for PostgreSQL RLS policy commands."""
    ALL = 'ALL'
    SELECT = 'SELECT'
    INSERT = 'INSERT'
    UPDATE = 'UPDATE'
    DELETE = 'DELETE'


# Constants for policy mode
class PolicyMode:
    """Constants for PostgreSQL RLS policy modes."""
    RESTRICTIVE = 'RESTRICTIVE'
    PERMISSIVE = 'PERMISSIVE'


@dataclass
class RlsPolicy:
    """
    Configuration for a PostgreSQL Row-Level Security policy.

    This dataclass defines the structure of an RLS policy that can be
    attached to a Django model via the Meta.rls_policies attribute.

    Args:
        role_name: PostgreSQL role name (optional). If not specified, the policy
            applies to PUBLIC (all roles).
        command: Policy command (ALL, SELECT, INSERT, UPDATE, DELETE).
            Defaults to PolicyCommand.ALL.
        using: USING clause expression. Can be either:
            - A Django Q object (will be converted to SQL WHERE clause)
            - A Django Expression (Exists, Value, F, etc.)
            - A raw SQL string expression
            This defines which rows are visible/accessible.
        name: Custom policy name (optional). If not specified, a name will be
            auto-generated based on the table name and policy index.
        mode: Policy mode (RESTRICTIVE or PERMISSIVE). Optional.
            - RESTRICTIVE: Row must pass all RESTRICTIVE policies
            - PERMISSIVE: Row must pass at least one PERMISSIVE policy
        with_check: WITH CHECK clause expression (optional). Can be either:
            - A Django Q object (will be converted to SQL WHERE clause)
            - A Django Expression (Exists, Value, F, etc.)
            - A raw SQL string expression
            This defines which rows can be inserted/updated.
            If not specified, the USING expression is used.

    Example:
        RlsPolicy(
            role_name='app_user',
            command=PolicyCommand.SELECT,
            using=Q(owner_id=F('current_user_id'))
        )

        RlsPolicy(
            role_name='app_user',
            command=PolicyCommand.INSERT,
            name='user_insert_own_documents',
            using='true',
            with_check="owner_id = current_setting('app.current_user_id')::int"
        )
    """
    using: Optional[Union[Q, Expression, str]] = None
    role_name: Optional[str] = None
    command: str = PolicyCommand.ALL
    name: Optional[str] = None
    mode: Optional[str] = None
    with_check: Optional[Union[Q, Expression, str]] = None

    def __post_init__(self):
        """Validate policy configuration."""
        # Validate command is valid
        valid_commands = {
            PolicyCommand.ALL,
            PolicyCommand.SELECT,
            PolicyCommand.INSERT,
            PolicyCommand.UPDATE,
            PolicyCommand.DELETE
        }
        if self.command not in valid_commands:
            raise ValueError(
                f"Invalid policy command '{self.command}'. "
                f"Must be one of: {', '.join(valid_commands)}"
            )

        # Validate mode if specified
        if self.mode is not None:
            valid_modes = {PolicyMode.RESTRICTIVE, PolicyMode.PERMISSIVE}
            if self.mode not in valid_modes:
                raise ValueError(
                    f"Invalid policy mode '{self.mode}'. "
                    f"Must be one of: {', '.join(valid_modes)}"
                )


class RLSModel(models.Model):
    """
    Abstract model mixin for defining Row-Level Security policies.

    This mixin enables declarative RLS policy definition through a class
    attribute named 'rls_policies'. Policies are defined as a list of
    RlsPolicy dataclass instances.

    Models inheriting from RLSModel are automatically registered for RLS
    policy application during migrations (no @register_rls_model decorator needed).

    Example usage:
        class Document(RLSModel, models.Model):
            title = models.CharField(max_length=200)
            owner_id = models.IntegerField()
            is_public = models.BooleanField(default=False)

            # Define RLS policies as a class attribute
            rls_policies = [
                # Users can only see their own documents or public ones
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.SELECT,
                    using=Q(owner_id=F('current_user_id')) | Q(is_public=True)
                ),
                # Users can only insert documents with themselves as owner
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.INSERT,
                    using='true',
                    with_check="owner_id = current_setting('app.current_user_id')::int"
                ),
                # Users can only update their own documents
                RlsPolicy(
                    role_name='app_user',
                    command=PolicyCommand.UPDATE,
                    using="owner_id = current_setting('app.current_user_id')::int"
                ),
                # Superusers can see all documents
                RlsPolicy(
                    role_name='app_superuser',
                    command=PolicyCommand.ALL,
                    using='true',
                    mode=PolicyMode.PERMISSIVE
                )
            ]

            class Meta:
                db_table = 'documents'

    Methods:
        get_rls_policies(): Class method to retrieve the list of RLS policies
            defined as a class attribute.
        get_policy_sql(policy_name_prefix): Class method to generate SQL
            statements for creating the RLS policies.
    """

    class Meta:
        abstract = True

    def __init_subclass__(cls, **kwargs):
        """
        Automatically register concrete RLSModel subclasses for RLS policy application.

        This hook is called whenever a class inherits from RLSModel. It automatically
        registers the model so that RLS policies are applied during migrations without
        needing the @register_rls_model decorator.
        """
        super().__init_subclass__(**kwargs)

        # Defer registration until Django's ModelBase metaclass has fully processed the model
        # We need to wait until _meta is properly initialized
        def register():
            """Register the model when it's fully initialized."""
            # Only register concrete models (not abstract models)
            # Check Meta.abstract to determine if this is an abstract model
            is_abstract = False
            if hasattr(cls, '_meta'):
                is_abstract = getattr(cls._meta, 'abstract', False)
            elif hasattr(cls, 'Meta'):
                is_abstract = getattr(cls.Meta, 'abstract', False)

            if not is_abstract:
                # Import register_rls_model here to avoid circular imports at module load
                try:
                    from .signals import register_rls_model
                    register_rls_model(cls)
                except ImportError:
                    # signals module not available yet, skip registration
                    pass

        # Store the registration callback to be processed later
        # We can't execute it immediately because Django's metaclass hasn't finished yet
        try:
            from django.apps import apps as apps_module
            if not hasattr(apps_module, '_pending_rls_registrations'):
                apps_module._pending_rls_registrations = []
            apps_module._pending_rls_registrations.append(register)
        except ImportError:
            # Django not imported yet, skip
            pass

    @classmethod
    def get_rls_policies(cls) -> List[RlsPolicy]:
        """
        Retrieve the RLS policies defined in the model.

        RLS policies should be defined as a class attribute named 'rls_policies'.

        Returns:
            List[RlsPolicy]: List of RLS policy configurations, or empty list
                if no policies are defined.
        """
        # Check for class attribute
        if hasattr(cls, 'rls_policies') and cls.rls_policies is not None:
            policies = cls.rls_policies
            if not isinstance(policies, list):
                return []
            return policies

        return []

    @classmethod
    def get_table_name(cls) -> str:
        """
        Get the database table name for this model.

        Returns:
            str: The database table name (including app label if db_table not set).
        """
        return cls._meta.db_table

    @classmethod
    def _q_to_sql(cls, q_object: Q) -> str:
        """
        Convert a Django Q object to a SQL WHERE clause expression.

        This uses Django's query compiler to generate the SQL.

        Args:
            q_object: Django Q object to convert

        Returns:
            str: SQL WHERE clause expression
        """
        from django.db.models.sql import Query
        from django.db.models.sql.where import WhereNode

        # Create a query for this model
        query = Query(cls)
        where = query.build_where(q_object)

        # Get the SQL compiler
        compiler = query.get_compiler(using='default')

        # Generate SQL from the where clause
        sql, params = compiler.compile(where)

        # Replace %s placeholders with actual values
        # Note: This is a simplified approach; in production you may want
        # to handle this differently for safety
        if params:
            sql = sql % tuple(
                f"'{p}'" if isinstance(p, str) else str(p)
                for p in params
            )

        return sql

    @classmethod
    def _expression_to_sql(cls, expression: Expression) -> str:
        """
        Convert a Django Expression object to SQL.

        This handles Exists, Value, F, and other Expression subclasses.

        Args:
            expression: Django Expression object to convert

        Returns:
            str: SQL expression
        """
        from django.db.models.sql import Query

        # Create a query for this model
        query = Query(cls)

        # Get the SQL compiler
        compiler = query.get_compiler(using='default')

        # Compile the expression to SQL
        sql, params = expression.as_sql(compiler, compiler.connection)

        # Replace %s placeholders with actual values
        if params:
            sql = sql % tuple(
                f"'{p}'" if isinstance(p, str) else str(p)
                for p in params
            )

        return sql

    @classmethod
    def get_policy_sql(cls, policy_name_prefix: Optional[str] = None) -> List[str]:
        """
        Generate SQL statements for creating RLS policies defined on this model.

        Args:
            policy_name_prefix: Optional prefix for policy names. If not provided,
                uses the model's table name.

        Returns:
            List[str]: List of SQL CREATE POLICY statements

        Example:
            statements = MyModel.get_policy_sql()
            for stmt in statements:
                cursor.execute(stmt)
        """
        policies = cls.get_rls_policies()
        table_name = cls.get_table_name()

        if policy_name_prefix is None:
            policy_name_prefix = table_name

        sql_statements = []

        for idx, policy in enumerate(policies):
            # Use custom policy name if provided, otherwise generate one
            if policy.name:
                policy_name = policy.name
            else:
                policy_name = f"{policy_name_prefix}_policy_{idx}"

            # Start building the CREATE POLICY statement
            sql_parts = [f"CREATE POLICY {policy_name}"]
            sql_parts.append(f"ON {table_name}")

            # Add mode if specified
            if policy.mode:
                sql_parts.append(f"AS {policy.mode}")

            # Add command
            sql_parts.append(f"FOR {policy.command}")

            # Add role if specified
            if policy.role_name:
                sql_parts.append(f"TO {policy.role_name}")
            else:
                sql_parts.append("TO PUBLIC")

            # Add USING clause
            if policy.using:
                if isinstance(policy.using, Q):
                    using_sql = cls._q_to_sql(policy.using)
                elif isinstance(policy.using, Expression):
                    using_sql = cls._expression_to_sql(policy.using)
                else:
                    using_sql = policy.using
                sql_parts.append(f"USING ({using_sql})")

            # Add WITH CHECK clause if specified
            if policy.with_check:
                if isinstance(policy.with_check, Q):
                    with_check_sql = cls._q_to_sql(policy.with_check)
                elif isinstance(policy.with_check, Expression):
                    with_check_sql = cls._expression_to_sql(policy.with_check)
                else:
                    with_check_sql = policy.with_check
                sql_parts.append(f"WITH CHECK ({with_check_sql})")

            # Join all parts with newlines for readability
            sql_statement = "\n  ".join(sql_parts) + ";"
            sql_statements.append(sql_statement)

        return sql_statements


class RlsManyToManyField(models.ManyToManyField):
    """
    A ManyToManyField that accepts RLS policies for the through table.

    This field extends Django's ManyToManyField to automatically apply RLS policies
    to the intermediate (through) table created for many-to-many relationships.

    Args:
        to: The model this field relates to (same as ManyToManyField)
        rls_policies: List of RlsPolicy objects to apply to the through table
        **kwargs: All other ManyToManyField arguments (through, related_name, etc.)

    Example:
        from django.db import models
        from django.db.models import Q, F
        from django_postgres_rls import RlsPolicy, RlsManyToManyField, PolicyCommand

        class Document(models.Model):
            title = models.CharField(max_length=200)
            owner_id = models.IntegerField()

            # Many-to-many with RLS on the through table
            collaborators = RlsManyToManyField(
                'User',
                rls_policies=[
                    RlsPolicy(
                        role_name='app_user',
                        command=PolicyCommand.ALL,
                        # User can only see collaborations for documents they own
                        using=Q(document__owner_id=F('current_user_id'))
                    ),
                    RlsPolicy(
                        role_name='app_staff',
                        command=PolicyCommand.ALL,
                        using="true"  # Staff can see all collaborations
                    ),
                ],
                related_name='collaborated_documents'
            )

    The policies will be automatically applied to the auto-generated through table
    (Document_collaborators in this example).

    For explicit through models, you can still use this field and the policies
    will be applied:

        class DocumentCollaborator(models.Model):
            document = models.ForeignKey(Document, on_delete=models.CASCADE)
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            role = models.CharField(max_length=50)

            class Meta:
                db_table = 'document_collaborators'

        class Document(models.Model):
            collaborators = RlsManyToManyField(
                'User',
                through='DocumentCollaborator',
                rls_policies=[...],
            )
    """

    def __init__(self, to, rls_policies=None, **kwargs):
        """
        Initialize the RlsManyToManyField.

        Args:
            to: The model this field relates to
            rls_policies: Optional list of RlsPolicy objects for the through table
            **kwargs: All other ManyToManyField arguments
        """
        self.rls_policies = rls_policies or []
        super().__init__(to, **kwargs)

    def contribute_to_class(self, cls, name, **kwargs):
        """
        Hook into Django's model creation to attach policies to through model.

        This method is called when the field is added to a model class. We use it
        to attach the RLS policies to the through model after it's created.
        """
        super().contribute_to_class(cls, name, **kwargs)

        # If no policies defined, nothing to do
        if not self.rls_policies:
            return

        # Get the through model (may be auto-generated or explicit)
        # We need to do this in a lazy way since the through model might not exist yet
        def attach_policies_to_through():
            """Attach RLS policies to the through model."""
            # Get the remote field's through model
            through_model = self.remote_field.through

            # Add get_rls_policies method if not already present
            if not hasattr(through_model, 'get_rls_policies'):
                # Store policies on the model class
                through_model._rls_policies = self.rls_policies

                # Add the get_rls_policies method
                @classmethod
                def get_rls_policies(cls):
                    """Return RLS policies for this through model."""
                    return getattr(cls, '_rls_policies', [])

                through_model.get_rls_policies = get_rls_policies

                # Also add get_table_name if not present (from RLSModel)
                if not hasattr(through_model, 'get_table_name'):
                    @classmethod
                    def get_table_name(cls):
                        """Return the database table name for this model."""
                        return cls._meta.db_table

                    through_model.get_table_name = get_table_name

        # Register a callback to run after models are ready
        # We can't apply policies immediately because the through model might not be created yet
        from django.apps import apps
        from django.core.exceptions import AppRegistryNotReady

        try:
            # Try to attach immediately if app registry is ready
            if apps.ready:
                attach_policies_to_through()
            else:
                # Otherwise, register a callback
                # Store the callback as an attribute so we can call it later
                if not hasattr(cls, '_rls_m2m_callbacks'):
                    cls._rls_m2m_callbacks = []
                cls._rls_m2m_callbacks.append((name, attach_policies_to_through))
        except AppRegistryNotReady:
            # App registry not ready, store callback for later
            if not hasattr(cls, '_rls_m2m_callbacks'):
                cls._rls_m2m_callbacks = []
            cls._rls_m2m_callbacks.append((name, attach_policies_to_through))

    def deconstruct(self):
        """
        Deconstruct the field for migrations.

        This method is called by Django's migration framework to serialize the field.
        We need to include the rls_policies parameter.
        """
        name, path, args, kwargs = super().deconstruct()

        # Add rls_policies to kwargs if present
        if self.rls_policies:
            kwargs['rls_policies'] = self.rls_policies

        return name, path, args, kwargs
