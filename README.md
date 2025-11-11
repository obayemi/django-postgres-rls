# Django PostgreSQL Row-Level Security (RLS)

A Django middleware package for implementing PostgreSQL Row-Level Security using role switching to enforce access control at the database level.

## Features

- **Automatic Role Creation**: Roles are automatically created during migrations (opt-out available for enterprise environments)
- **Automatic Transaction Management**: Creates transactions automatically if needed - no `ATOMIC_REQUESTS` requirement
- **Transaction-Scoped Role Switching**: Uses PostgreSQL `SET LOCAL ROLE` for secure, transaction-scoped role changes
- **Startup Role Validation**: Validates configured roles exist in PostgreSQL on first request
- **Declarative Policy Definition**: Define RLS policies in your Django models using the `RLSModel` mixin
- **Session Variable Expressions**: Django F-like expressions (`SessionVar`, `CurrentUserId`) for clean, type-safe policy definitions
- **Many-to-Many Support**: `RlsManyToManyField` automatically applies RLS policies to through tables
- **Migration Generation**: Automatically generate migration code for RLS policies
- **Auto-Apply on Migrate**: Optionally apply RLS policies automatically after migrations
- **Authentication Backend**: Authenticate users while running as anonymous role using SECURITY DEFINER functions
- **Explicit Role Switching**: Context manager for programmatic role switching in views and commands
- **Configuration Validation**: Django system checks automatically validate your RLS configuration at startup
- **Security Features**:
  - Role validation with whitelist to prevent SQL injection
  - Input sanitization for user IDs
  - Audit logging for compliance and security monitoring
  - Process exception handling to prevent role leakage
  - Startup validation ensures roles exist in PostgreSQL
- **Comprehensive Error Messages**: Clear, actionable error messages with troubleshooting steps

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

By default, roles are automatically created when you run `python manage.py migrate`. Simply add `django_postgres_rls` to `INSTALLED_APPS` and configure your roles in `POSTGRES_RLS_VALID_ROLES`, and roles will be created automatically with the correct permissions.

**Manual Role Creation (Advanced)**

If you prefer to manage roles manually (e.g., via DBAs or infrastructure-as-code), disable auto-creation:

```python
# settings.py
POSTGRES_RLS_AUTO_CREATE_ROLES = False  # Disable automatic role creation
```

Then create the PostgreSQL roles manually:

```sql
-- Create roles with NOLOGIN (cannot connect directly)
CREATE ROLE app_user NOLOGIN;
CREATE ROLE app_staff NOLOGIN;
CREATE ROLE app_superuser NOLOGIN;
CREATE ROLE app_anonymous NOLOGIN;  -- For unauthenticated users

-- Grant roles to your database user (allows SET ROLE)
GRANT app_user TO your_db_user;
GRANT app_staff TO your_db_user;
GRANT app_superuser TO your_db_user;
GRANT app_anonymous TO your_db_user;

-- Grant necessary permissions
GRANT USAGE ON SCHEMA public TO app_user, app_staff, app_superuser, app_anonymous;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user, app_staff, app_superuser;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_anonymous;  -- Read-only for anonymous
```

### 2. Implement the Middleware

Create a middleware class that inherits from `PostgresRLSMiddleware` and implements the `extract_role()` method:

```python
# myapp/middleware.py
from django_postgres_rls import PostgresRLSMiddleware


class MyRLSMiddleware(PostgresRLSMiddleware):
    def extract_role(self, request):
        """
        Extract the user's role from the request.

        Returns one of: 'user', 'staff', 'superuser', 'anonymous'
        """
        if not request.user or not request.user.is_authenticated:
            return 'anonymous'

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

Configure Django with the required settings:

```python
# settings.py

# REQUIRED: Add django_postgres_rls to INSTALLED_APPS
# This registers signal handlers for automatic role creation and policy application
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    # ...
    'django_postgres_rls',  # Required for automatic role creation
    # ... your other apps
]

# Database configuration with PostgreSQL
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'your_db',
        'USER': 'your_db_user',
        'PASSWORD': 'your_password',
        'HOST': 'localhost',
        'PORT': '5432',
        'ATOMIC_REQUESTS': True,  # Recommended (middleware auto-creates transactions if needed)
    }
}

# Configure valid PostgreSQL roles (required for security)
POSTGRES_RLS_VALID_ROLES = frozenset([
    'app_user',
    'app_staff',
    'app_superuser',
    'app_anonymous',
])

# Configure role mapping
POSTGRES_RLS_ROLE_MAPPING = {
    'user': 'app_user',
    'staff': 'app_staff',
    'superuser': 'app_superuser',
    'anonymous': 'app_anonymous',
}

# Optional: Default role for unauthenticated users
POSTGRES_RLS_DEFAULT_ANONYMOUS_ROLE = 'app_anonymous'

# Optional: Whitelist paths that don't require RLS (e.g., login endpoints)
POSTGRES_RLS_WHITELIST = [
    '/api/auth/login/',
    '/api/auth/register/',
    '/api/auth/token/',
]

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
- **`django_postgres_rls` must be in `INSTALLED_APPS`** - Required for automatic role creation and policy application
- `ATOMIC_REQUESTS = True` is **recommended** - the middleware will automatically create transactions if needed
- `POSTGRES_RLS_VALID_ROLES` is **required** for security - it prevents SQL injection by whitelisting valid roles
- The middleware must come **after** `AuthenticationMiddleware` in the `MIDDLEWARE` list

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
            # Anonymous users can only see public documents
            RlsPolicy(
                role_name='app_anonymous',
                command=PolicyCommand.SELECT,
                using=Q(is_public=True)
            ),
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

Signal handlers are automatically registered when you add `django_postgres_rls` to `INSTALLED_APPS`.

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

## Authentication Backend

The library includes authentication backends that allow users to authenticate while running as the `app_anonymous` role using PostgreSQL SECURITY DEFINER functions.

### Why This Is Needed

When using RLS, the middleware switches roles based on the authenticated user. This creates a chicken-and-egg problem: how do you authenticate a user before you have their role?

The solution is to use **SECURITY DEFINER** functions that:
1. Can be executed by the `app_anonymous` role
2. Run with elevated privileges (as the database owner)
3. Verify user credentials and return user information
4. Allow Django to complete authentication before role switching

### Setup

**Step 1: Create the PostgreSQL Function**

Create a Django migration to add the SECURITY DEFINER function:

```python
# myapp/migrations/0002_create_auth_function.py

from django.db import migrations
from django_postgres_rls import get_user_fetch_function_sql

class Migration(migrations.Migration):
    dependencies = [
        ('myapp', '0001_initial'),
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.RunSQL(
            sql=get_user_fetch_function_sql(
                user_table='auth_user',  # Use your user table name
                schema='public',
                function_name='get_user_for_auth'
            ),
            reverse_sql="""
                DROP FUNCTION IF EXISTS public.get_user_for_auth(TEXT);
            """
        ),
    ]
```

**Step 2: Configure Authentication Backend**

```python
# settings.py

AUTHENTICATION_BACKENDS = [
    # RLS authentication backend (recommended)
    'django_postgres_rls.RLSAuthenticationBackendWithPythonVerification',

    # Fallback to default Django backend (optional)
    'django.contrib.auth.backends.ModelBackend',
]

# RLS Authentication Settings
POSTGRES_RLS_AUTH_FUNCTION = 'public.get_user_for_auth'
POSTGRES_RLS_AUTH_USE_EMAIL = False  # Set to True for email-based auth
```

**Step 3: Apply Migrations**

```bash
python manage.py migrate
```

**Step 4: Test Authentication**

```python
from django.contrib.auth import authenticate

# This works even when running as app_anonymous role!
user = authenticate(username='testuser', password='testpass')
if user:
    print(f"Authenticated as {user.username}")
```

### How Authentication Works

1. **Login Request**: User submits credentials to whitelisted path `/api/auth/login/`
2. **Anonymous Role**: Request runs as `app_anonymous` role (path is whitelisted)
3. **SECURITY DEFINER Call**: Backend calls the function with elevated privileges:
   ```sql
   SELECT * FROM public.get_user_for_auth('username');
   ```
4. **Return Data**: Function returns `(user_id, password_hash, is_active)`
5. **Python Verification**: Django verifies password using `check_password()`
6. **Success**: User object is returned and stored in session
7. **Next Request**: Middleware switches to appropriate role based on user

### Available Backends

#### RLSAuthenticationBackendWithPythonVerification (Recommended)

Fetches user data via SECURITY DEFINER function, then verifies password in Python.

**Pros:**
- Uses Django's built-in password hashers (more secure)
- Matches Django's authentication exactly
- Easier to maintain

#### RLSAuthenticationBackend

Simple backend that calls a SECURITY DEFINER function to authenticate users.

**Pros:**
- All authentication logic in the database
- Simpler for some use cases

**Cons:**
- Password verification must be implemented in PostgreSQL
- May not match Django's password hashing exactly

## RLS Policy Configuration

### RlsPolicy Dataclass

The `RlsPolicy` dataclass defines a PostgreSQL RLS policy with the following parameters:

- **`role_name`**: (Required) PostgreSQL role name (e.g., `'app_user'`, `'app_staff'`)
- **`using`**: (Required) USING clause expression
  - Can be a Django `Q` object or raw SQL string
  - Defines which rows are visible/accessible
- **`command`**: (Optional) Policy command
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

# Anonymous users - read-only access to public data
RlsPolicy(
    role_name='app_anonymous',
    command=PolicyCommand.SELECT,
    using=Q(is_public=True)
)

# Raw SQL (when needed for advanced cases)
RlsPolicy(
    role_name='app_user',
    command=PolicyCommand.SELECT,
    using="owner_id = current_setting('app.current_user_id')::int"
)
```

### Session Variable Expressions

Instead of using raw SQL strings for PostgreSQL session variables, use the provided Django-compatible expressions:

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
- `missing_ok` (bool, optional): If `True`, returns `NULL` when variable doesn't exist (default: `False`)

**Why use SessionVar/CurrentUserId?**

✅ **Do** use `CurrentUserId()` - clean, type-safe:
```python
using=Q(owner_id=CurrentUserId())
```

❌ **Don't** use raw SQL strings - hard to maintain:
```python
using="owner_id = current_setting('app.current_user_id')::int"
```

❌ **Don't** use `F('current_user_id')` - incorrect, tries to reference a field:
```python
using=Q(owner_id=F('current_user_id'))  # ERROR: No such field!
```

**Benefits:**
- ✅ **Type-safe**: Proper type casting with `output_field`
- ✅ **Composable**: Works seamlessly in complex Q object expressions
- ✅ **Maintainable**: Single source of truth for variable names
- ✅ **Django-native**: Integrates with ORM, migrations, and queries
- ✅ **Validated**: Compiles to correct SQL automatically

## Configuration

### Automatic Role Creation

By default, PostgreSQL roles are automatically created when you run migrations:

```python
# settings.py (default behavior)
POSTGRES_RLS_AUTO_CREATE_ROLES = True  # Enabled by default
```

**When roles are automatically created:**
- Roles are created with `NOLOGIN` attribute
- Roles are granted to the current database user
- Creation happens during the `pre_migrate` signal
- Existing roles are skipped (idempotent)
- Errors are logged but don't fail migrations

**To disable automatic role creation**:

```python
# settings.py
POSTGRES_RLS_AUTO_CREATE_ROLES = False
```

### Custom Role Mapping

Customize the mapping between application roles and PostgreSQL roles:

```python
# settings.py
POSTGRES_RLS_ROLE_MAPPING = {
    'user': 'app_user',
    'staff': 'app_staff',
    'superuser': 'app_superuser',
    'anonymous': 'app_anonymous',
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
            'anonymous': 'app_anonymous',
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

Define a whitelist of valid PostgreSQL roles:

```python
# settings.py
POSTGRES_RLS_VALID_ROLES = frozenset([
    'app_user',
    'app_staff',
    'app_superuser',
    'app_anonymous',
])
```

The middleware will reject any role not in this list, preventing SQL injection and unauthorized role usage.

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

The library includes comprehensive Django system checks that automatically validate your configuration:

```bash
python manage.py check
```

#### What Gets Checked

**Security Checks (Errors)**:
- ✅ PostgreSQL database backend is configured
- ✅ `ATOMIC_REQUESTS = True` is set (recommended)
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

#### Benefits

- **Early Detection**: Catch configuration errors during development
- **Security Enforcement**: Ensures critical security settings are configured
- **Clear Guidance**: Actionable error messages with specific hints
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

Use `RlsManyToManyField` to automatically apply policies to many-to-many through tables:

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
                with_check=Q(document__owner_id=CurrentUserId())
            ),
        ],
    )
```

### Role Switching

Implement role switching to allow users to operate with reduced privileges:

```python
class MyRLSMiddleware(PostgresRLSMiddleware):
    def extract_role(self, request):
        if not request.user or not request.user.is_authenticated:
            return 'anonymous'

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

Generate migration code as a string for quick copy-paste:

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

### Request Processing Flow

1. **Request Processing**: When a request comes in, the middleware calls `extract_role()` to determine the user's role
2. **Role Mapping**: The role is mapped to a PostgreSQL role using `get_role_mapping()`
3. **Transaction Check**: Middleware ensures request runs in a transaction (creates one if needed)
4. **Role Switch**: The middleware executes `SET LOCAL ROLE <pg_role>` to switch to the appropriate PostgreSQL role
5. **Session Variable**: Sets `app.current_user_id` session variable with the user's ID
6. **Policy Enforcement**: PostgreSQL applies RLS policies assigned to the active role
7. **Role Reset**: After the response, the middleware executes `RESET ROLE` to restore the default role

### Architecture

The library provides three main components:

1. **PostgresRLSMiddleware**: Automatically switches PostgreSQL roles based on user permissions
   - Executes `SET LOCAL ROLE` to switch to the appropriate role
   - Sets session variables (e.g., `app.current_user_id`) for use in policies
   - Resets role after each request with `RESET ROLE`
   - Handles exceptions to prevent role leakage

2. **RLSModel**: Abstract model mixin for declarative RLS policy definition
   - Define policies as class attributes using `rls_policies`
   - Convert Django Q objects to SQL automatically
   - Generate CREATE POLICY statements for migrations

3. **Management Utilities**: Tools for applying and managing RLS policies
   - `generate_rls_migration_operations()` - Generate migration operations
   - `apply_rls_policies()` - Apply policies programmatically
   - `@register_rls_model` - Auto-apply policies on migrate signal

### Policy SQL Generation

Django Q objects are automatically converted to PostgreSQL SQL:

```python
# Django Q object
Q(is_public=True) | Q(owner_id=CurrentUserId())

# Generated SQL
(is_public = true OR owner_id = current_setting('app.current_user_id', false)::integer)
```

## Testing

The package includes a comprehensive test suite with **234 tests** covering all functionality:
- **189 unit tests**: Fast, mocked database operations using PostgreSQL configuration
- **45 integration tests**: Real PostgreSQL database tests with actual RLS policies

**All tests use PostgreSQL** - the library is PostgreSQL-only by design.

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
# Set environment variables
export USE_EXISTING_POSTGRES=1
export POSTGRES_HOST=localhost
export POSTGRES_PORT=5432
export POSTGRES_USER=postgres
export POSTGRES_PASSWORD=postgres
export POSTGRES_DB=test_rls

# Create test database
createdb test_rls

# Run tests
uv run pytest django_postgres_rls/tests/ -v
```

### Run Specific Test Suites

```bash
# Run only unit tests (fast)
pytest -m "not integration" -v

# Run only integration tests (real database)
pytest -m integration -v

# Run specific test modules
pytest django_postgres_rls/tests/test_models.py -v
pytest django_postgres_rls/tests/test_middleware.py -v

# With coverage
pytest --cov=django_postgres_rls --cov-report=html --cov-report=term-missing
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
