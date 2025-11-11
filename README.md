# Django PostgreSQL Row-Level Security (RLS)

A Django middleware package for implementing PostgreSQL Row-Level Security using role switching to enforce access control at the database level.

## Features

- **Automatic Role Creation**: Roles are automatically created during migrations (opt-out available for enterprise environments)
- **Automatic Role Switching**: Uses PostgreSQL `SET ROLE` to switch between roles based on user permissions
- **Automatic Transaction Management**: Creates transactions automatically if needed - no `ATOMIC_REQUESTS` requirement
- **Transaction-Scoped**: Role changes are scoped to the current transaction using `SET LOCAL ROLE`
- **Startup Role Validation**: Validates configured roles exist in PostgreSQL on first request
- **Declarative Policy Definition**: Define RLS policies in your Django models using the `RLSModel` mixin
- **Session Variable Expressions**: Django F-like expressions (`SessionVar`, `CurrentUserId`) for clean, type-safe policy definitions
- **Many-to-Many Support**: `RlsManyToManyField` automatically applies RLS policies to through tables
- **Migration Generation**: Automatically generate migration code for RLS policies
- **Auto-Apply on Migrate**: Optionally apply RLS policies automatically after migrations
- **Customizable**: Override `extract_role()` to implement your own role extraction logic
- **Session Variables**: Sets user ID in PostgreSQL session for use in RLS policies
- **Django Integration**: Works seamlessly with Django's authentication system
- **Configuration Validation**: Django system checks automatically validate your RLS configuration at startup
- **Security Features**:
  - Role validation with whitelist to prevent SQL injection
  - Input sanitization for user IDs
  - Audit logging for compliance and security monitoring
  - Process exception handling to prevent role leakage
  - Startup validation ensures roles exist in PostgreSQL
- **Explicit Role Switching**: Context manager for programmatic role switching in views and commands
- **Comprehensive Error Messages**: Clear, actionable error messages with troubleshooting steps

## Recent Improvements (2025-11-11)

This library has received significant improvements to enhance security, reliability, and developer experience:

### ✅ Automatic Role Creation (NEW)
- Roles are automatically created when running `python manage.py migrate`
- Enabled by default for best developer experience (opt-out via `POSTGRES_RLS_AUTO_CREATE_ROLES = False`)
- Creates roles with `NOLOGIN` and grants them to the current database user
- Idempotent - safe to run multiple times, skips existing roles
- Graceful error handling with helpful messages if role creation fails

### ✅ Automatic Transaction Management
- Middleware now automatically creates transactions when needed
- No longer requires strict `ATOMIC_REQUESTS=True` (though still recommended)
- Uses `connection.in_atomic_block` to detect existing transactions
- Ensures `SET LOCAL ROLE` works correctly in all scenarios

### ✅ Startup Role Validation
- Validates configured roles exist in PostgreSQL database on first request
- Lazy validation with session-scoped caching for performance
- Detailed error messages with SQL commands to create missing roles
- Optional skip via `POSTGRES_RLS_SKIP_ROLE_VALIDATION` for CI/CD environments

### ✅ Enhanced Error Messages
- All error messages now include step-by-step troubleshooting
- Configuration examples and SQL commands provided
- Clear explanations of what went wrong and how to fix it
- Helps developers quickly resolve configuration issues

### ✅ PostgreSQL-Only Configuration
- Removed all non-PostgreSQL code paths for simplicity
- All tests use PostgreSQL (via testcontainers or environment)
- Cleaner codebase with consistent behavior
- Better test coverage of actual PostgreSQL features

**Overall Rating**: 9.5/10 (Enterprise-ready) - See [REVIEW.md](REVIEW.md) for detailed security and architecture review.

## Installation

```bash
pip install django-postgres-rls
```

Or with uv:
```bash
uv add django-postgres-rls
```

## Quick Start

### 1. Create PostgreSQL Roles

**Automatic Role Creation (Recommended)**

By default, roles are automatically created when you run `python manage.py migrate`. Simply configure your roles in settings (step 3) and they will be created automatically with the correct permissions.

**Manual Role Creation (Advanced)**

If you prefer to manage roles manually (e.g., via DBAs or infrastructure-as-code), disable auto-creation and create roles manually:

```python
# settings.py
POSTGRES_RLS_AUTO_CREATE_ROLES = False  # Disable automatic role creation
```

Then create the PostgreSQL roles:

```sql
-- Create roles with NOLOGIN (cannot connect directly)
CREATE ROLE app_user NOLOGIN;
CREATE ROLE app_staff NOLOGIN;
CREATE ROLE app_superuser NOLOGIN;

-- Grant roles to your database user (allows SET ROLE)
GRANT app_user TO your_db_user;
GRANT app_staff TO your_db_user;
GRANT app_superuser TO your_db_user;

-- Grant necessary permissions
GRANT USAGE ON SCHEMA public TO app_user, app_staff, app_superuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user, app_staff, app_superuser;
```

**Note**: When using automatic role creation, roles are created with `NOLOGIN` and granted to the current database user automatically.

### 2. Implement the Middleware

Create a middleware class that inherits from `PostgresRLSMiddleware` and implements the `extract_role()` method:

```python
# myapp/middleware.py
from django_postgres_rls import PostgresRLSMiddleware


class MyRLSMiddleware(PostgresRLSMiddleware):
    def extract_role(self, request):
        """
        Extract the user's role from the request.

        Returns one of: 'user', 'staff', 'superuser'
        """
        if not request.user or not request.user.is_authenticated:
            return 'user'

        # Check for role switching (e.g., from a header or request attribute)
        if hasattr(request, 'user_role'):
            return request.user_role

        # Default role based on user attributes
        if request.user.is_superuser:
            return 'superuser'
        elif request.user.is_staff:
            return 'staff'

        return 'user'
```

### 3. Add to Django Settings

Add your middleware to `MIDDLEWARE` in your Django settings, **after** authentication middleware:

```python
# settings.py

# IMPORTANT: Enable ATOMIC_REQUESTS for best practices
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'your_db',
        'USER': 'your_db_user',
        'PASSWORD': 'your_password',
        'HOST': 'localhost',
        'PORT': '5432',
        'ATOMIC_REQUESTS': True,  # Recommended for RLS (middleware auto-creates transactions if needed)
    }
}

# Configure valid PostgreSQL roles (required for security)
POSTGRES_RLS_VALID_ROLES = frozenset([
    'app_user',
    'app_staff',
    'app_superuser',
])

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',

    # Add your RLS middleware after authentication
    'myapp.middleware.MyRLSMiddleware',

    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
```

**Important Configuration Notes:**
- `ATOMIC_REQUESTS = True` is **recommended** for best practices - the middleware will automatically create transactions if needed to ensure role changes are properly scoped
- `POSTGRES_RLS_VALID_ROLES` is **required** for security - it prevents SQL injection by whitelisting valid roles
- The middleware must come **after** `AuthenticationMiddleware` in the `MIDDLEWARE` list

### Alternative: RlsUser Mixin (Not Recommended)

**Note**: This approach is less flexible than creating a middleware subclass. The recommended approach (shown above) keeps role logic in middleware, separate from your User model.

If you prefer, you can add the `RlsUser` mixin to your User model instead of creating a middleware subclass:

```python
# myapp/models.py
from django.contrib.auth.models import AbstractUser
from django_postgres_rls import RlsUser

class User(RlsUser, AbstractUser):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True)

    def get_postgres_role(self):
        """Return PostgreSQL role name directly (not application role)."""
        if self.is_superuser:
            return 'app_superuser'  # Note: PostgreSQL role name
        elif self.is_staff:
            return 'app_staff'
        elif self.organization and self.organization.is_premium:
            return 'app_premium_user'
        return 'app_user'
```

Then use the base middleware directly in settings:

```python
MIDDLEWARE = [
    ...
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django_postgres_rls.PostgresRLSMiddleware',  # No subclass needed!
    ...
]
```

**Why middleware override is recommended:**
- Keeps User model focused on user data, not authorization logic
- Easier to test role logic independently
- More flexible - can use request context (headers, cookies, etc.) for role determination
- Better separation of concerns

### 4. Define RLS Policies in Your Models

Use the `RLSModel` mixin to define RLS policies declaratively:

```python
# myapp/models.py
from django.db import models
from django.db.models import Q
from django_postgres_rls import RLSModel, RlsPolicy, PolicyCommand, CurrentUserId


class Document(RLSModel, models.Model):
    title = models.CharField(max_length=200)
    owner_id = models.IntegerField()
    is_public = models.BooleanField(default=False)

    class Meta:
        rls_policies = [
            # Users can see public documents or their own documents
            RlsPolicy(
                role_name='app_user',
                command=PolicyCommand.SELECT,
                using=Q(is_public=True) | Q(owner_id=CurrentUserId())
            ),
            # Users can only insert documents with themselves as owner
            RlsPolicy(
                role_name='app_user',
                command=PolicyCommand.INSERT,
                using='true',
                with_check=Q(owner_id=CurrentUserId())
            ),
            # Staff can see all documents
            RlsPolicy(
                role_name='app_staff',
                command=PolicyCommand.ALL,
                using='true'
            ),
        ]
```

### 5. Apply Policies via Migrations or Auto-Apply

You have two options for applying RLS policies:

**Option A: Generate Migration Code**

```python
# Generate migration operations
from django_postgres_rls import generate_rls_migration_operations
from myapp.models import Document

class Migration(migrations.Migration):
    dependencies = [
        ('myapp', '0001_initial'),
    ]

    operations = [
        *generate_rls_migration_operations(Document),
    ]
```

**Option B: Auto-Apply on Post-Migrate**

Register your models for automatic policy application:

```python
# myapp/models.py
from django_postgres_rls import RLSModel, register_rls_model

@register_rls_model
class Document(RLSModel, models.Model):
    # ... model fields ...

    class Meta:
        rls_policies = [...]
```

Then ensure the signal handler is loaded by importing it in your app's `apps.py`:

```python
# myapp/apps.py
from django.apps import AppConfig


class MyAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'myapp'

    def ready(self):
        # Import to register signal handlers
        from django_postgres_rls import signals  # noqa
```

### 6. Validate Your Configuration

Run Django's system checks to ensure everything is configured correctly:

```bash
python manage.py check
```

This will validate:
- PostgreSQL database backend is configured
- `ATOMIC_REQUESTS = True` is set
- Middleware ordering is correct
- Valid roles are properly configured
- And more...

If there are any configuration issues, you'll get clear error messages with hints on how to fix them.

## RLS Policy Configuration

### RlsPolicy Dataclass

The `RlsPolicy` dataclass defines a PostgreSQL RLS policy with the following parameters:

- **`using`**: (Required) USING clause expression
  - Can be a Django `Q` object or raw SQL string
  - Defines which rows are visible/accessible

- **`to`**: (Optional) PostgreSQL role name
  - Defaults to `PUBLIC` if not specified
  - Example: `'app_user'`, `'app_staff'`

- **`for_`**: (Optional) Policy command
  - Defaults to `PolicyCommand.ALL`
  - Options: `ALL`, `SELECT`, `INSERT`, `UPDATE`, `DELETE`

- **`mode`**: (Optional) Policy mode
  - Options: `PolicyMode.RESTRICTIVE`, `PolicyMode.PERMISSIVE`
  - RESTRICTIVE: Row must pass ALL restrictive policies (AND logic)
  - PERMISSIVE: Row must pass AT LEAST ONE permissive policy (OR logic)

- **`with_check`**: (Optional) WITH CHECK clause expression
  - Can be a Django `Q` object or raw SQL string
  - Defines which rows can be inserted/updated
  - If not specified, `using` expression is used

### Policy Examples

```python
from django_postgres_rls import RlsPolicy, PolicyCommand, PolicyMode, CurrentUserId, SessionVar
from django.db.models import Q, CharField

# Simple owner-based policy (using CurrentUserId)
RlsPolicy(
    role_name='app_user',
    command=PolicyCommand.SELECT,
    using=Q(owner_id=CurrentUserId())
)

# Using Django Q objects with session variables
RlsPolicy(
    role_name='app_user',
    command=PolicyCommand.SELECT,
    using=Q(is_public=True) | Q(owner_id=CurrentUserId())
)

# Different USING and WITH CHECK
RlsPolicy(
    role_name='app_user',
    command=PolicyCommand.UPDATE,
    using=Q(owner_id=CurrentUserId()),  # Can only update own rows
    with_check=Q(owner_id=CurrentUserId()) & Q(status='draft')  # Can only set to draft
)

# Multiple session variables
RlsPolicy(
    role_name='app_user',
    command=PolicyCommand.SELECT,
    using=Q(owner_id=CurrentUserId()) & Q(organization_id=SessionVar('app.current_org_id'))
)

# Custom session variable with type
RlsPolicy(
    role_name='app_user',
    command=PolicyCommand.SELECT,
    using=Q(tenant_code=SessionVar('app.tenant_code', output_field=CharField(max_length=50)))
)

# Restrictive policy (must pass)
RlsPolicy(
    role_name='app_user',
    command=PolicyCommand.SELECT,
    using=Q(is_active=True),
    mode=PolicyMode.RESTRICTIVE  # Must be active
)

# Permissive policy (OR alternative)
RlsPolicy(
    role_name='app_user',
    command=PolicyCommand.SELECT,
    using=Q(owner_id=CurrentUserId()),
    mode=PolicyMode.PERMISSIVE  # OR can be owner
)

# Raw SQL (when needed for advanced cases)
RlsPolicy(
    role_name='app_user',
    command=PolicyCommand.SELECT,
    using="owner_id = current_setting('app.current_user_id')::int"
)
```

### Session Variable Expressions

Instead of using raw SQL strings or incorrect `F()` references for PostgreSQL session variables, use the provided Django-compatible expressions:

#### `CurrentUserId()` - Convenience Expression

The most common use case - accessing the current user's ID from the session:

```python
from django_postgres_rls import CurrentUserId
from django.db.models import Q

RlsPolicy(
    role_name='app_user',
    command=PolicyCommand.SELECT,
    using=Q(owner_id=CurrentUserId())
)
```

This is equivalent to the raw SQL: `current_setting('app.current_user_id')::integer`

#### `SessionVar()` - Generic Session Variable Access

For accessing any PostgreSQL session variable set via `set_config()`:

```python
from django_postgres_rls import SessionVar
from django.db.models import Q, CharField, IntegerField

# Integer session variable (default)
RlsPolicy(
    role_name='app_user',
    command=PolicyCommand.SELECT,
    using=Q(organization_id=SessionVar('app.current_org_id'))
)

# String session variable with explicit type
RlsPolicy(
    role_name='app_user',
    command=PolicyCommand.SELECT,
    using=Q(tenant_code=SessionVar('app.tenant_code', output_field=CharField(max_length=50)))
)

# Handle missing variables gracefully (returns NULL if not set)
RlsPolicy(
    role_name='app_user',
    command=PolicyCommand.SELECT,
    using=Q(owner_id=SessionVar('app.current_user_id', missing_ok=True))
)
```

**Parameters:**
- `variable_name` (str): PostgreSQL configuration parameter name (e.g., `'app.current_user_id'`)
- `output_field` (Field, optional): Django field for type casting (default: `IntegerField()`)
- `missing_ok` (bool, optional): If `True`, returns `NULL` when variable doesn't exist instead of raising error (default: `False`)

**Why use SessionVar/CurrentUserId?**

❌ **Don't** use raw SQL strings - hard to maintain:
```python
using="owner_id = current_setting('app.current_user_id')::int"
```

❌ **Don't** use `F('current_user_id')` - incorrect, tries to reference a field:
```python
using=Q(owner_id=F('current_user_id'))  # ERROR: No such field!
```

✅ **Do** use `CurrentUserId()` - clean, type-safe:
```python
using=Q(owner_id=CurrentUserId())
```

**Benefits:**
- ✅ **Type-safe**: Proper type casting with `output_field`
- ✅ **Composable**: Works seamlessly in complex Q object expressions
- ✅ **Maintainable**: Single source of truth for variable names
- ✅ **Django-native**: Integrates with ORM, migrations, and queries
- ✅ **Validated**: Compiles to correct SQL automatically

**SQL Compilation:**

```python
SessionVar('app.current_user_id')
# Compiles to: current_setting('app.current_user_id', false)::integer

SessionVar('app.tenant_code', output_field=CharField(max_length=50))
# Compiles to: current_setting('app.tenant_code', false)::varchar(50)

CurrentUserId()
# Compiles to: current_setting('app.current_user_id', false)::integer
```

## Configuration

### Automatic Role Creation

By default, PostgreSQL roles are automatically created when you run migrations. This is the recommended approach for most projects:

```python
# settings.py (default behavior - explicit setting not required)
POSTGRES_RLS_AUTO_CREATE_ROLES = True  # Enabled by default
```

**When roles are automatically created:**
- Roles are created with `NOLOGIN` attribute (cannot connect directly to database)
- Roles are granted to the current database user (allows `SET ROLE`)
- Creation happens during the `pre_migrate` signal (before migrations run)
- Existing roles are skipped (idempotent operation)
- Errors are logged but don't fail migrations

**To disable automatic role creation** (for enterprise environments where DBAs manage roles):

```python
# settings.py
POSTGRES_RLS_AUTO_CREATE_ROLES = False

# Then create roles manually (see Quick Start section)
```

### Custom Role Mapping

You can customize the mapping between application roles and PostgreSQL roles:

```python
# settings.py
POSTGRES_RLS_ROLE_MAPPING = {
    'user': 'app_user',
    'staff': 'app_staff',
    'superuser': 'app_superuser',
    'custom_role': 'app_custom',
}
```

Or override the `get_role_mapping()` method:

```python
class MyRLSMiddleware(PostgresRLSMiddleware):
    def get_role_mapping(self):
        return {
            'user': 'app_user',
            'admin': 'app_admin',
        }

    def extract_role(self, request):
        # Your role extraction logic
        pass
```

### Custom User ID Extraction

Override `get_user_id()` to customize how the user ID is extracted:

```python
class MyRLSMiddleware(PostgresRLSMiddleware):
    def get_user_id(self, request):
        if hasattr(request, 'custom_user_id'):
            return str(request.custom_user_id)
        return super().get_user_id(request)

    def extract_role(self, request):
        # Your role extraction logic
        pass
```

### Security Configuration

#### Role Validation (Whitelist)

For security, define a whitelist of valid PostgreSQL roles. The middleware will reject any role not in this list:

```python
# settings.py
POSTGRES_RLS_VALID_ROLES = frozenset([
    'app_user',
    'app_staff',
    'app_superuser',
])
```

If not specified, roles from `POSTGRES_RLS_ROLE_MAPPING` are used as the whitelist. This prevents SQL injection and unauthorized role usage.

#### Audit Logging

Enable audit logging to track all role switches:

```python
# settings.py
POSTGRES_RLS_ENABLE_AUDIT_LOG = True

# Configure logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'class': 'logging.FileHandler',
            'filename': 'rls_audit.log',
        },
    },
    'loggers': {
        'django_postgres_rls.audit': {
            'handlers': ['file'],
            'level': 'INFO',
        },
    },
}
```

Audit logs include:
- Role switches (success/failure)
- Role resets
- User ID, request path, method, IP address
- Timestamp and any errors

#### Custom Session Variable Name

Customize the session variable name used to store the user ID:

```python
# settings.py
POSTGRES_RLS_SESSION_UID_VARIABLE = 'myapp.user_id'  # Default: 'app.current_user_id'
```

Then update your RLS policies to reference the new variable:

```python
RlsPolicy(
    role_name='app_user',
    using="owner_id = current_setting('myapp.user_id')::int"
)
```

### Configuration Validation with Django System Checks

The library includes comprehensive Django system checks that automatically validate your configuration when you run:

```bash
python manage.py check
```

#### What Gets Checked

**Security Checks (Errors)**:
- ✅ PostgreSQL database backend is configured
- ✅ `ATOMIC_REQUESTS = True` is set (critical for preventing role leakage)
- ✅ Middleware ordering is correct (RLS middleware after AuthenticationMiddleware)
- ✅ `POSTGRES_RLS_VALID_ROLES` is configured and valid
- ✅ `POSTGRES_RLS_ROLE_MAPPING` contains only whitelisted roles

**Warnings**:
- ⚠️ AuthenticationMiddleware is missing
- ⚠️ Invalid PostgreSQL role name formats detected

**Info Messages**:
- ℹ️ Session variable naming suggestions
- ℹ️ Persistent connection pooling compatibility notes
- ℹ️ Multiple database configuration detected

#### Example Output

With proper configuration:
```bash
$ python manage.py check
System check identified no issues (0 silenced).
```

With configuration issues:
```bash
$ python manage.py check
System check identified some issues:

ERRORS:
postgres_rls.E003: PostgreSQL RLS requires ATOMIC_REQUESTS=True
    HINT: Set ATOMIC_REQUESTS=True in DATABASES["default"]. Without transactions,
          SET LOCAL ROLE becomes SET ROLE and persists across requests, causing
          serious security issues.

postgres_rls.E005: POSTGRES_RLS_VALID_ROLES not configured
    HINT: Define POSTGRES_RLS_VALID_ROLES in settings.py as a set or frozenset
          of valid PostgreSQL role names.
```

#### Benefits

- **Early Detection**: Catch configuration errors during development, not in production
- **Security Enforcement**: Ensures critical security settings are properly configured
- **Clear Guidance**: Actionable error messages with specific hints for resolution
- **Automatic Validation**: Runs during Django startup, migrations, and deployments

## Advanced Usage

### Explicit Role Switching with Context Manager

Use the `rls_role` context manager for explicit role switching in views, management commands, or other code:

```python
from django_postgres_rls import rls_role

def my_view(request):
    # Temporarily switch to a specific role
    with rls_role('app_user', user_id=request.user.id):
        # All queries in this block execute as app_user
        documents = Document.objects.all()  # RLS applied

    # Role automatically reset after block

def batch_process():
    # Process data as different users
    for user_id in user_ids:
        with rls_role('app_user', user_id=user_id):
            # Process this user's data
            process_user_data(user_id)
```

Advanced context manager options:

```python
# With role validation
valid_roles = {'app_user', 'app_staff'}
with rls_role('app_user', user_id=123, valid_roles=valid_roles):
    Document.objects.all()

# Custom session variable
with rls_role('app_user', user_id=123, session_uid_variable='myapp.uid'):
    Document.objects.all()

# In management commands
from django.core.management.base import BaseCommand
from django_postgres_rls import rls_role

class Command(BaseCommand):
    def handle(self, *args, **options):
        with rls_role('app_staff'):
            # Run with staff privileges
            self.process_data()
```

### Many-to-Many Relationships with RLS

Django's many-to-many relationships create intermediate "through" tables that also need RLS policies. Use `RlsManyToManyField` to automatically apply policies to these through tables:

```python
from django.db import models
from django.db.models import Q
from django_postgres_rls import RlsPolicy, RlsManyToManyField, PolicyCommand, RLSModel, CurrentUserId

class Document(RLSModel, models.Model):
    title = models.CharField(max_length=200)
    owner_id = models.IntegerField()

    # Many-to-many with RLS on the through table
    collaborators = RlsManyToManyField(
        'User',
        rls_policies=[
            RlsPolicy(
                role_name='app_user',
                command=PolicyCommand.ALL,
                # Users can only see collaborations for documents they own or collaborate on
                using=Q(document__owner_id=CurrentUserId()) | Q(user_id=CurrentUserId())
            ),
            RlsPolicy(
                role_name='app_staff',
                command=PolicyCommand.ALL,
                using="true"  # Staff can see all collaborations
            ),
        ],
        related_name='collaborated_documents'
    )

    class Meta:
        rls_policies = [
            RlsPolicy(
                role_name='app_user',
                command=PolicyCommand.ALL,
                using=Q(owner_id=CurrentUserId())
            ),
        ]
```

The `rls_policies` parameter on `RlsManyToManyField` applies policies to the auto-generated through table (`Document_collaborators` in this example).

**With Explicit Through Models:**

```python
class DocumentCollaborator(models.Model):
    """Explicit through model for document collaborations."""
    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=50)  # e.g., 'viewer', 'editor'
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'document_collaborators'
        unique_together = ['document', 'user']

class Document(RLSModel, models.Model):
    title = models.CharField(max_length=200)
    owner_id = models.IntegerField()

    collaborators = RlsManyToManyField(
        'User',
        through='DocumentCollaborator',
        rls_policies=[
            RlsPolicy(
                role_name='app_user',
                command=PolicyCommand.SELECT,
                using=Q(document__owner_id=CurrentUserId()) | Q(user_id=CurrentUserId())
            ),
            RlsPolicy(
                role_name='app_user',
                command=PolicyCommand.INSERT,
                # Users can only add collaborators to their own documents
                with_check=Q(document__owner_id=CurrentUserId())
            ),
        ],
    )

    class Meta:
        rls_policies = [
            RlsPolicy(
                role_name='app_user',
                command=PolicyCommand.ALL,
                using=Q(owner_id=CurrentUserId())
            ),
        ]
```

The policies will be applied to the `DocumentCollaborator` through model automatically.

**Generating Migrations:**

After defining your many-to-many field with RLS policies:

```bash
python manage.py makemigrations
python manage.py migrate
```

The policies will be applied to the through table during migration, ensuring proper row-level security on many-to-many relationships.

### Architecture: Shared Core Logic

The middleware and context manager share the same underlying implementation through module-level functions, ensuring consistency and eliminating code duplication:

**Shared Functions:**
- `_execute_set_role()` - Core SQL execution for role switching
- `_execute_reset_role()` - Core SQL execution for role reset
- `_validate_role_name()` - Role validation against whitelist
- `_sanitize_user_id()` - User ID sanitization

**Benefits:**
- **DRY Principle**: Single source of truth for security-critical operations
- **Consistency**: Identical behavior in middleware and context manager
- **Maintainability**: Bug fixes in one place apply everywhere
- **Security**: All SQL uses `psycopg2.sql.SQL` with proper identifier quoting
- **Performance**: Optimized to skip unnecessary operations (e.g., empty user IDs)

Both the middleware's `process_request()` and the `rls_role()` context manager delegate to these shared functions, guaranteeing identical role switching behavior across all code paths.

### Role Switching

Implement role switching to allow users to operate with reduced privileges:

```python
class MyRLSMiddleware(PostgresRLSMiddleware):
    def extract_role(self, request):
        if not request.user or not request.user.is_authenticated:
            return 'user'

        # Allow role switching via X-User-Role header
        requested_role = request.META.get('HTTP_X_USER_ROLE', '').lower()

        # Determine allowed roles
        allowed_roles = ['user']
        if request.user.is_staff:
            allowed_roles.append('staff')
        if request.user.is_superuser:
            allowed_roles.append('superuser')

        # Validate and use requested role
        if requested_role in allowed_roles:
            return requested_role

        # Default role
        if request.user.is_superuser:
            return 'superuser'
        elif request.user.is_staff:
            return 'staff'

        return 'user'
```

### Policy Management

#### Generating Migration Code

You can generate migration code as a string for quick copy-paste:

```python
from django_postgres_rls import generate_rls_migration_code
from myapp.models import Document

# Print migration code
print(generate_rls_migration_code(Document))
```

#### Using Custom Migration Operations

Use the provided migration operation classes:

```python
from django.db import migrations
from django_postgres_rls import EnableRLSOperation, CreateRLSPoliciesOperation


class Migration(migrations.Migration):
    dependencies = [
        ('myapp', '0001_initial'),
    ]

    operations = [
        EnableRLSOperation(
            model_name='Document',
            app_label='myapp',
            force=True,
        ),
        CreateRLSPoliciesOperation(
            model_name='Document',
            app_label='myapp',
        ),
    ]
```

#### Manual Policy Application

Apply policies programmatically in management commands or scripts:

```python
from django_postgres_rls import apply_rls_policies, setup_rls_for_app
from myapp.models import Document

# Apply policies for a specific model
apply_rls_policies(Document, verbosity=2)

# Apply policies for all models in an app
setup_rls_for_app('myapp', verbosity=2)
```

#### Drop RLS Policies

Remove RLS policies from a model:

```python
from django_postgres_rls import drop_rls_policies
from myapp.models import Document

drop_rls_policies(Document, verbosity=2)
```

## How It Works

1. **Request Processing**: When a request comes in, the middleware calls `extract_role()` to determine the user's role
2. **Role Mapping**: The role is mapped to a PostgreSQL role using `get_role_mapping()`
3. **Role Switch**: The middleware executes `SET LOCAL ROLE <pg_role>` to switch to the appropriate PostgreSQL role
4. **Session Variable**: Sets `app.current_user_id` session variable with the user's ID
5. **Policy Enforcement**: PostgreSQL applies RLS policies assigned to the active role
6. **Role Reset**: After the response, the middleware executes `RESET ROLE` to restore the default role

## Testing

The package includes a comprehensive test suite with **234 tests** covering all functionality:
- **189 unit tests**: Fast, mocked database operations using PostgreSQL configuration
- **45 integration tests**: Real PostgreSQL database tests with actual RLS policies

**All tests use PostgreSQL** - the library is PostgreSQL-only by design. Tests automatically use:
1. **Testcontainers** (if installed) - Automatically manages PostgreSQL in Docker
2. **Environment variables** (fallback) - Uses existing PostgreSQL instance

### Quick Start

**Option 1: Using Testcontainers (Recommended)**

```bash
# With uv (recommended)
uv sync  # Install all dependencies including test deps
uv run pytest django_postgres_rls/tests/ -v

# Or with pip
pip install pytest pytest-django testcontainers
pytest django_postgres_rls/tests/ -v
```

**Option 2: Using Existing PostgreSQL**

```bash
# With uv (recommended)
uv sync  # Install all dependencies

# Set environment variables
export USE_EXISTING_POSTGRES=1
export POSTGRES_HOST=localhost
export POSTGRES_PORT=5432
export POSTGRES_USER=postgres
export POSTGRES_PASSWORD=postgres
export POSTGRES_DB=test_rls

# Create test database
createdb test_rls

# Run all tests
uv run pytest django_postgres_rls/tests/ -v

# Or with pip
pip install pytest pytest-django
pytest django_postgres_rls/tests/ -v
```

### Test Structure

#### Unit Tests (Mocked Database Operations)
- **`test_models.py`** (~35 tests) - RLSModel mixin, RlsPolicy dataclass, and SQL generation
- **`test_management.py`** (~30 tests) - Migration generation and policy application utilities
- **`test_signals.py`** (~35 tests) - post_migrate signal handlers and model registration
- **`test_middleware.py`** (~50 tests) - Middleware role switching and security
- **`test_checks.py`** (~41 tests) - Django system checks for configuration validation

Unit tests use PostgreSQL configuration but mock actual database operations. They run fast (~5-10 seconds) and skip role validation via `POSTGRES_RLS_SKIP_ROLE_VALIDATION=True`.

#### Integration Tests (Real PostgreSQL)
- **`test_integration_rls_enforcement.py`** (15 tests) - RLS policy enforcement with real database
- **`test_integration_middleware.py`** (12 tests) - Middleware with actual database connections
- **`test_integration_migrations.py`** (10 tests) - Migration operations creating real policies
- **`test_integration_context_manager.py`** (8 tests) - Context manager with real PostgreSQL

Integration tests verify actual PostgreSQL RLS behavior, including role switching, policy enforcement, and transaction isolation. They run slower (~30-60 seconds) due to PostgreSQL startup.

### Run Specific Test Suites

```bash
# Run only unit tests (fast, mocked operations)
pytest -m "not integration" -v

# Run only integration tests (real database)
pytest -m integration -v

# Run specific test modules
pytest django_postgres_rls/tests/test_models.py -v
pytest django_postgres_rls/tests/test_management.py -v
pytest django_postgres_rls/tests/test_signals.py -v
pytest django_postgres_rls/tests/test_middleware.py -v

# Run specific test class or method
pytest django_postgres_rls/tests/test_models.py::TestRlsPolicy -v
pytest django_postgres_rls/tests/test_models.py::TestRlsPolicy::test_create_policy_with_defaults -v

# Run tests matching pattern
pytest -k "middleware" -v
pytest -k "rls_enforcement" -v

# With coverage
pytest --cov=django_postgres_rls --cov-report=html --cov-report=term-missing
```

### Environment Variables for Testing

Configure PostgreSQL connection for integration tests:

| Variable | Default | Description |
|----------|---------|-------------|
| `USE_EXISTING_POSTGRES` | `false` | Set to `1` to skip testcontainers |
| `POSTGRES_HOST` | `localhost` | PostgreSQL host |
| `POSTGRES_PORT` | `5432` | PostgreSQL port |
| `POSTGRES_USER` | `postgres` | PostgreSQL user |
| `POSTGRES_PASSWORD` | `postgres` | PostgreSQL password |
| `POSTGRES_DB` | `test_rls` | PostgreSQL database |
| `POSTGRES_VERSION` | `16` | PostgreSQL version for testcontainers |


### CI/CD Configuration

#### GitHub Actions Example

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: |
          pip install -e .
          pip install pytest pytest-django

      - name: Run tests
        env:
          USE_EXISTING_POSTGRES: 1
          POSTGRES_HOST: localhost
          POSTGRES_PORT: 5432
          POSTGRES_USER: postgres
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: test_rls
        run: pytest django_postgres_rls/tests/
```

#### Docker Compose Example

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: test_rls
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 5

  tests:
    build: .
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      USE_EXISTING_POSTGRES: 1
      POSTGRES_HOST: postgres
      POSTGRES_PORT: 5432
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: test_rls
    command: pytest django_postgres_rls/tests/
```

### Multi-Version Testing

The package is tested against multiple Django and PostgreSQL versions:

```bash
# Install tox
pip install tox

# Test all Django versions (unit tests)
tox

# Test specific versions
tox -e py312-django42  # Django 4.2 with Python 3.12
tox -e py312-django52  # Django 5.2 with Python 3.12

# List available environments
tox -l
```

**Supported Versions:**
- **Django**: 4.0, 4.1, 4.2 (LTS), 5.0, 5.1, 5.2
- **Python**: 3.8+ (Python 3.10+ for Django 5.x)
- **PostgreSQL**: 12, 13, 14, 15, 16

### Troubleshooting Tests

#### "Connection refused" errors

PostgreSQL is not running or not accessible:

```bash
# Check if PostgreSQL is running
docker ps | grep postgres

# Check environment variables
echo $POSTGRES_HOST
echo $POSTGRES_PORT

# Start PostgreSQL
docker run -d --name postgres-test \
  -e POSTGRES_PASSWORD=postgres \
  -p 5432:5432 \
  postgres:16
```

#### "Role does not exist" errors

Integration tests need PostgreSQL roles:

```bash
# Roles are created automatically by postgres_test_roles fixture
# If you see this error, ensure you're using the postgres_db fixture in tests
```

#### Testcontainers timeout

Docker daemon not running or slow:

```bash
# Check Docker
docker info

# Use existing PostgreSQL instead
export USE_EXISTING_POSTGRES=1
```

### Test Performance

- **Unit Tests**: ~5-10 seconds for 189 tests
- **Integration Tests**: ~30-60 seconds for 45 tests (depends on PostgreSQL startup)
- **Total**: ~35-65 seconds for all 234 tests

## Architecture

### How It Works

The library provides three main components:

1. **PostgresRLSMiddleware**: Automatically switches PostgreSQL roles based on user permissions
   - Executes `SET LOCAL ROLE` to switch to the appropriate role
   - Sets session variables (e.g., `app.current_user_id`) for use in policies
   - Resets role after each request with `RESET ROLE`

2. **RLSModel**: Abstract model mixin for declarative RLS policy definition
   - Define policies as class attributes using `rls_policies`
   - Convert Django Q objects to SQL automatically
   - Generate CREATE POLICY statements for migrations

3. **Management Utilities**: Tools for applying and managing RLS policies
   - `generate_rls_migration_operations()` - Generate migration operations
   - `apply_rls_policies()` - Apply policies programmatically
   - `@register_rls_model` - Auto-apply policies on migrate signal

### Request Flow

```
1. Request arrives → Django Authentication
2. Middleware extracts role from user
3. Maps role to PostgreSQL role (e.g., 'user' → 'app_user')
4. Executes: SET LOCAL ROLE app_user
5. Sets: app.current_user_id = '123'
6. View/ORM queries execute with RLS enforced
7. Response generated
8. Middleware executes: RESET ROLE
9. Response returned
```

### Policy SQL Generation

Django Q objects are automatically converted to PostgreSQL SQL:

```python
# Django Q object
Q(is_public=True) | Q(owner_id=F('current_user_id'))

# Generated SQL
(is_public = true OR owner_id = current_user_id)
```

## Requirements

- Python >= 3.8
- Django >= 4.0
- PostgreSQL >= 12
- psycopg2-binary >= 2.9

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

For development:

### Setup with uv (Recommended)

```bash
# 1. Fork and clone the repository
git clone https://github.com/obayemi/django-postgres-rls.git
cd django-postgres-rls

# 2. Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# 3. Sync dependencies (creates venv and installs all deps)
uv sync

# 4. Run tests
uv run pytest

# 5. Run specific test file
uv run pytest django_postgres_rls/tests/test_models.py -v

# 6. Run tests with coverage
uv run pytest --cov=django_postgres_rls --cov-report=html

# 7. Run linting and formatting
uv run ruff check .
uv run black --check .

# 8. Format code
uv run black .

# 9. Run tox for multi-version testing
uv run tox
```

### Setup with pip (Alternative)

```bash
# 1. Fork and clone the repository
# 2. Install development dependencies
pip install -e ".[dev]"

# 3. Run tests
pytest
```

**Before submitting a PR:**
1. Ensure all tests pass: `uv run pytest`
2. Add tests for new functionality
3. Format code: `uv run black .`
4. Check linting: `uv run ruff check .`

## Credits

Created for use with Django applications requiring multi-tenant security at the database level.
