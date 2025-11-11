"""Django settings for tests."""

import os

DEBUG = True

# Use PostgreSQL for all tests
# Uses same environment variables as integration tests (conftest.py)
# Works with testcontainers or existing PostgreSQL instance
#
# Environment variables:
# - POSTGRES_HOST: PostgreSQL host (default: localhost)
# - POSTGRES_PORT: PostgreSQL port (default: 5432)
# - POSTGRES_USER: PostgreSQL user (default: postgres)
# - POSTGRES_PASSWORD: PostgreSQL password (default: postgres)
# - POSTGRES_DB: PostgreSQL database (default: test_rls)
# - USE_EXISTING_POSTGRES: Set to '1' to use existing PostgreSQL
#
# For CI/CD without PostgreSQL, set POSTGRES_RLS_SKIP_ROLE_VALIDATION=True
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('POSTGRES_DB', 'test_rls'),
        'USER': os.getenv('POSTGRES_USER', 'postgres'),
        'PASSWORD': os.getenv('POSTGRES_PASSWORD', 'postgres'),
        'HOST': os.getenv('POSTGRES_HOST', 'localhost'),
        'PORT': os.getenv('POSTGRES_PORT', '5432'),
        'ATOMIC_REQUESTS': True,  # Required for RLS
        'TEST': {
            'NAME': 'test_django_postgres_rls',
        },
    }
}

INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'django_postgres_rls',
]

SECRET_KEY = 'test-secret-key'

USE_TZ = True

MIDDLEWARE = []

# Skip role validation for unit tests that mock the database connection
# Integration tests will still validate roles against real PostgreSQL
POSTGRES_RLS_SKIP_ROLE_VALIDATION = True
