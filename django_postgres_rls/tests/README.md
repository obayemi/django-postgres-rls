# Tests for django-postgres-rls

This directory contains comprehensive tests for the django-postgres-rls library.

**Total Test Suite: 234 tests**
- **189 unit tests**: Fast, mocked database operations with PostgreSQL configuration
- **45 integration tests**: Real PostgreSQL database tests with actual RLS policies

## Test Structure

### Unit Tests
- `test_models.py` - RLSModel mixin, RlsPolicy dataclass, and SQL generation (~35 tests)
- `test_management.py` - Migration generation and policy application utilities (~30 tests)
- `test_signals.py` - post_migrate signal handlers and model registration (~35 tests)
- `test_middleware.py` - Middleware role switching and security (~50 tests)
- `test_checks.py` - Django system checks for configuration validation (~41 tests)

### Integration Tests
- `test_integration_rls_enforcement.py` - RLS policy enforcement with real database (15 tests)
- `test_integration_middleware.py` - Middleware with actual database connections (12 tests)
- `test_integration_migrations.py` - Migration operations creating real policies (10 tests)
- `test_integration_context_manager.py` - Context manager with real PostgreSQL (8 tests)

### Test Infrastructure
- `conftest.py` - Pytest configuration and PostgreSQL fixtures
- `integration_utils.py` - Utility functions for integration tests
- `test_settings.py` - Django settings for tests

## Running Tests

For comprehensive testing documentation, see the main [README.md](../../README.md#testing).

### Quick Start

```bash
# Install test dependencies
pip install pytest pytest-django testcontainers

# Run all tests
pytest -v

# Run only unit tests (fast)
pytest -m "not integration" -v

# Run only integration tests
pytest -m integration -v
```

## Documentation

For detailed information about:
- Test setup and configuration
- CI/CD integration examples
- Troubleshooting guide
- Writing new tests
- Multi-version testing

Please refer to the **Testing** section in the main [README.md](../../README.md#testing).
