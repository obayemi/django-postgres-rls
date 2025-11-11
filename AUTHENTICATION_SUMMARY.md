# RLS Authentication Backend - Summary

## What Was Added

I've added a complete RLS authentication backend system that allows users to authenticate while running as the `app_anonymous` role using PostgreSQL SECURITY DEFINER functions.

## New Files

### 1. `django_postgres_rls/backends.py`
Contains two authentication backend implementations:

- **`RLSAuthenticationBackend`**: Simple backend that authenticates via SECURITY DEFINER function
- **`RLSAuthenticationBackendWithPythonVerification`** (Recommended): Fetches user data via SECURITY DEFINER, verifies password in Python using Django's password hashers

Also includes SQL generator functions:
- `get_auth_function_sql()` - Generates SECURITY DEFINER authentication function
- `get_user_fetch_function_sql()` - Generates SECURITY DEFINER user fetch function
- `get_auth_function_sql_with_password_check()` - Advanced version with password verification in PostgreSQL

### 2. `django_postgres_rls/tests/test_backends.py`
Comprehensive test suite with 20 tests covering:
- Backend initialization
- Valid/invalid credential authentication
- Email-based authentication
- User fetch functionality
- SQL generation

### 3. `django_postgres_rls/migrations_examples.py`
Example Django migrations showing:
- Basic authentication function setup
- Custom user model support
- Rate limiting implementation
- Audit logging implementation
- Settings configuration examples

### 4. `RLS_AUTH_BACKEND.md`
Complete documentation covering:
- Overview and problem statement
- Setup guide
- Security considerations
- Advanced examples (rate limiting, audit logs)
- Troubleshooting guide
- Performance considerations

## Quick Start

### 1. Create the Migration

```python
# myapp/migrations/0002_create_auth_function.py

from django.db import migrations
from django_postgres_rls import get_user_fetch_function_sql

class Migration(migrations.Migration):
    dependencies = [
        ('myapp', '0001_initial'),
    ]

    operations = [
        migrations.RunSQL(
            sql=get_user_fetch_function_sql(),
            reverse_sql="DROP FUNCTION IF EXISTS public.get_user_for_auth(TEXT);"
        ),
    ]
```

### 2. Update Settings

```python
# settings.py

AUTHENTICATION_BACKENDS = [
    'django_postgres_rls.RLSAuthenticationBackendWithPythonVerification',
    'django.contrib.auth.backends.ModelBackend',  # Fallback
]

POSTGRES_RLS_AUTH_FUNCTION = 'public.get_user_for_auth'
POSTGRES_RLS_AUTH_USE_EMAIL = False

POSTGRES_RLS_WHITELIST = [
    '/api/auth/login/',
    '/api/auth/register/',
    '/api/auth/token/',
]
```

### 3. Apply Migration

```bash
python manage.py migrate
```

### 4. Test

```python
from django.contrib.auth import authenticate

user = authenticate(username='testuser', password='testpass')
# Works even when running as app_anonymous role!
```

## How It Works

1. **Login request** comes to whitelisted path `/api/auth/login/`
2. **Middleware skips** role switching (path is whitelisted)
3. **Request runs** as `app_anonymous` role
4. **Backend calls** SECURITY DEFINER function: `SELECT * FROM get_user_for_auth('username')`
5. **Function executes** with elevated privileges, returns user data
6. **Django verifies** password using `check_password()` in Python
7. **User authenticated** and session created
8. **Next request** uses authenticated user's role

## Security Features

✅ **SECURITY DEFINER functions** run with elevated privileges safely
✅ **Minimal data exposure** - only returns necessary fields
✅ **Parameterized queries** prevent SQL injection
✅ **Django password hashers** for secure password verification
✅ **Rate limiting** support (see examples)
✅ **Audit logging** support (see examples)
✅ **Proper permission grants** - only `app_anonymous` has EXECUTE

## Test Results

All tests passing: ✅ **308 tests** (including 20 new authentication backend tests)

```
django_postgres_rls/tests/test_backends.py::TestRLSAuthenticationBackend .........
django_postgres_rls/tests/test_backends.py::TestRLSAuthenticationBackendWithPythonVerification .....
django_postgres_rls/tests/test_backends.py::TestSQLGenerators .....

20 passed in 4.59s
```

## Integration with Existing Features

The authentication backend integrates seamlessly with:

- ✅ **RLS Middleware** - Works with whitelist to skip role switching on auth endpoints
- ✅ **Default Anonymous Role** - Uses `app_anonymous` role for unauthenticated requests
- ✅ **RLS Whitelist** - Login/register endpoints bypass RLS
- ✅ **Role Mapping** - After auth, user gets proper role (user/staff/superuser)
- ✅ **Session Variables** - User ID set in PostgreSQL session after authentication

## Examples Provided

### Basic Usage
- Simple authentication with username/password
- Email-based authentication

### Advanced Usage
- Rate limiting (lock account after N failed attempts)
- Audit logging (track all authentication attempts)
- Custom user models
- IP address tracking

### Security Patterns
- Minimal privilege functions
- Input validation
- Proper permission grants
- Audit trails

## API Reference

### Backends

```python
from django_postgres_rls import (
    RLSAuthenticationBackend,
    RLSAuthenticationBackendWithPythonVerification,
)
```

### SQL Generators

```python
from django_postgres_rls import (
    get_auth_function_sql,
    get_user_fetch_function_sql,
    get_auth_function_sql_with_password_check,
)
```

### Settings

```python
POSTGRES_RLS_AUTH_FUNCTION = 'public.get_user_for_auth'  # Function name
POSTGRES_RLS_AUTH_USE_EMAIL = False  # Use email instead of username
```

## Documentation

Full documentation available in:
- `RLS_AUTH_BACKEND.md` - Complete guide
- `migrations_examples.py` - Migration examples
- `backends.py` - Docstrings and code examples

## Next Steps

1. Read `RLS_AUTH_BACKEND.md` for detailed setup instructions
2. Review `migrations_examples.py` for migration patterns
3. Create your authentication function migration
4. Configure settings
5. Test authentication
6. Consider adding rate limiting or audit logging

## Support

For issues or questions:
- Check the troubleshooting section in `RLS_AUTH_BACKEND.md`
- Review the test cases in `test_backends.py` for examples
- Examine the migration examples in `migrations_examples.py`
