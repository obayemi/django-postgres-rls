# RLS Authentication Backend

The RLS authentication backend allows you to authenticate users while running as the `app_anonymous` role by using PostgreSQL SECURITY DEFINER functions.

## Overview

When using Row-Level Security (RLS), the middleware switches roles based on the authenticated user. However, this creates a chicken-and-egg problem: how do you authenticate a user before you have their role?

The solution is to use **SECURITY DEFINER** functions that:
1. Can be executed by the `app_anonymous` role
2. Run with elevated privileges (as the database owner)
3. Verify user credentials and return user information
4. Allow Django to complete authentication before role switching

## Available Backends

### 1. RLSAuthenticationBackend

Simple backend that calls a SECURITY DEFINER function to authenticate users.

**Pros:**
- Simplest implementation
- All authentication logic in the database

**Cons:**
- Password verification must be implemented in PostgreSQL
- May not match Django's password hashing exactly

### 2. RLSAuthenticationBackendWithPythonVerification (Recommended)

Backend that fetches user data via SECURITY DEFINER function, then verifies password in Python.

**Pros:**
- Uses Django's built-in password hashers (more secure)
- Easier to maintain and update
- Matches Django's authentication exactly

**Cons:**
- Requires two steps (fetch + verify)

## Setup Guide

### Step 1: Choose Your Backend

We recommend `RLSAuthenticationBackendWithPythonVerification` for most use cases.

### Step 2: Create the PostgreSQL Function

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

### Step 3: Configure Django Settings

```python
# settings.py

AUTHENTICATION_BACKENDS = [
    # RLS authentication backend (for anonymous role authentication)
    'django_postgres_rls.RLSAuthenticationBackendWithPythonVerification',

    # Fallback to default Django backend (optional)
    'django.contrib.auth.backends.ModelBackend',
]

# RLS Authentication Settings
POSTGRES_RLS_AUTH_FUNCTION = 'public.get_user_for_auth'
POSTGRES_RLS_AUTH_USE_EMAIL = False  # Set to True for email-based auth

# RLS Middleware Settings
POSTGRES_RLS_DEFAULT_ANONYMOUS_ROLE = 'app_anonymous'
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

    # RLS middleware MUST come after AuthenticationMiddleware
    'myapp.middleware.MyRLSMiddleware',

    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
```

### Step 4: Apply Migrations

```bash
python manage.py migrate
```

### Step 5: Test Authentication

```python
from django.contrib.auth import authenticate

# This will now work even when running as app_anonymous role
user = authenticate(username='testuser', password='testpass')
if user:
    print(f"Authenticated as {user.username}")
```

## How It Works

### Authentication Flow

1. **Login Request**: User submits credentials to `/api/auth/login/`
2. **Whitelisted Path**: RLS middleware sees the path is whitelisted and skips role switching
3. **Anonymous Role**: Request runs as `app_anonymous` role
4. **SECURITY DEFINER Call**: Backend calls the SECURITY DEFINER function
   ```sql
   SELECT * FROM public.get_user_for_auth('username');
   ```
5. **Elevated Query**: Function runs with elevated privileges, can read `auth_user` table
6. **Return Data**: Function returns `(user_id, password_hash, is_active)`
7. **Python Verification**: Django verifies password using `check_password()`
8. **Success**: User object is returned and stored in session
9. **Next Request**: Middleware switches to appropriate role based on user

### Security Considerations

#### SECURITY DEFINER Functions

- Run with the privileges of the function owner (usually database superuser)
- Must be carefully written to prevent privilege escalation
- Should only return necessary data
- Must validate inputs properly

#### Best Practices

1. **Minimal Data Exposure**: Only return what's needed for authentication
   ```sql
   -- Good: Return only necessary fields
   RETURN QUERY SELECT id, password, is_active FROM auth_user WHERE username = p_username;

   -- Bad: Return all fields
   RETURN QUERY SELECT * FROM auth_user WHERE username = p_username;
   ```

2. **Input Validation**: Always use parameterized queries
   ```python
   # Good: Parameterized
   cursor.execute("SELECT * FROM get_user_for_auth(%s)", [username])

   # Bad: String interpolation (SQL injection risk)
   cursor.execute(f"SELECT * FROM get_user_for_auth('{username}')")
   ```

3. **Grant Minimal Permissions**:
   ```sql
   -- Only grant EXECUTE on specific function
   GRANT EXECUTE ON FUNCTION public.get_user_for_auth(TEXT) TO app_anonymous;

   -- Revoke from PUBLIC
   REVOKE ALL ON FUNCTION public.get_user_for_auth(TEXT) FROM PUBLIC;
   ```

4. **Audit Logging**: Consider logging authentication attempts
   ```sql
   INSERT INTO auth_audit_log (username, timestamp, success)
   VALUES (p_username, CURRENT_TIMESTAMP, TRUE);
   ```

## Advanced Examples

### Email-Based Authentication

```python
# settings.py
POSTGRES_RLS_AUTH_USE_EMAIL = True
```

```python
# Login with email
user = authenticate(email='user@example.com', password='pass')
```

### Custom User Model

```python
# myapp/migrations/0002_create_auth_function.py

from django.db import migrations
from django_postgres_rls import get_user_fetch_function_sql

class Migration(migrations.Migration):
    operations = [
        migrations.RunSQL(
            sql=get_user_fetch_function_sql(
                user_table='myapp_customuser',  # Your custom table
                schema='public',
                function_name='get_user_for_auth'
            ),
            reverse_sql="DROP FUNCTION IF EXISTS public.get_user_for_auth(TEXT);"
        ),
    ]
```

### Rate Limiting

See `migrations_examples.py` for a complete example with rate limiting.

### Audit Logging

See `migrations_examples.py` for a complete example with audit logging.

## Troubleshooting

### "permission denied for function"

The anonymous role doesn't have EXECUTE permission:
```sql
GRANT EXECUTE ON FUNCTION public.get_user_for_auth(TEXT) TO app_anonymous;
```

### "function does not exist"

The SECURITY DEFINER function hasn't been created:
```bash
python manage.py migrate
```

### Authentication always fails

1. Check the function name matches the setting:
   ```python
   POSTGRES_RLS_AUTH_FUNCTION = 'public.get_user_for_auth'
   ```

2. Verify the function returns correct format:
   ```sql
   SELECT * FROM public.get_user_for_auth('testuser');
   -- Should return: (user_id, password_hash, is_active)
   ```

3. Check Django logs:
   ```python
   LOGGING = {
       'loggers': {
           'django_postgres_rls': {
               'level': 'DEBUG',
           },
       },
   }
   ```

### "cannot execute ... in a read-only transaction"

The anonymous role might have read-only restrictions. Ensure SECURITY DEFINER functions can write if needed (e.g., for audit logs):
```sql
-- Grant write permissions for audit logs
GRANT INSERT ON public.auth_audit_log TO app_anonymous;
```

## Testing

```python
# tests.py

from django.test import TestCase
from django.contrib.auth import authenticate, get_user_model

User = get_user_model()

class RLSAuthenticationTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass'
        )

    def test_authenticate_with_valid_credentials(self):
        """Test authentication with valid credentials."""
        user = authenticate(username='testuser', password='testpass')
        self.assertIsNotNone(user)
        self.assertEqual(user.username, 'testuser')

    def test_authenticate_with_invalid_credentials(self):
        """Test authentication with invalid credentials."""
        user = authenticate(username='testuser', password='wrongpass')
        self.assertIsNone(user)
```

## Performance Considerations

1. **Function Performance**: SECURITY DEFINER functions run as the database owner, but they're still just SQL queries. Index your user table properly:
   ```sql
   CREATE INDEX idx_auth_user_username ON auth_user(username);
   CREATE INDEX idx_auth_user_email ON auth_user(email);
   ```

2. **Connection Pooling**: Use connection pooling to avoid repeated role switches:
   ```python
   DATABASES = {
       'default': {
           'CONN_MAX_AGE': 600,  # Keep connections open
       }
   }
   ```

3. **Caching**: Consider caching user lookups (but be careful with password changes):
   ```python
   from django.core.cache import cache

   # Cache user data (excluding password)
   cache.set(f'user:{user.id}', user, timeout=300)
   ```

## Migration from Standard Authentication

If you're migrating an existing Django app:

1. Add the RLS authentication backend to `AUTHENTICATION_BACKENDS`
2. Keep the default `ModelBackend` as a fallback
3. Create and apply the SECURITY DEFINER function migration
4. Test authentication still works
5. Deploy RLS middleware
6. Monitor logs for any authentication issues

## Resources

- [PostgreSQL SECURITY DEFINER Documentation](https://www.postgresql.org/docs/current/sql-createfunction.html)
- [Django Authentication Backends](https://docs.djangoproject.com/en/stable/topics/auth/customizing/)
- [PostgreSQL Row-Level Security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
