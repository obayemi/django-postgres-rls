"""
Django PostgreSQL Row-Level Security (RLS) Middleware

A Django middleware package for implementing PostgreSQL Row-Level Security
using role switching (SET ROLE) to enforce access control at the database level.
"""

__version__ = "0.1.0"

# Use lazy imports to avoid importing Django models before Django is configured
def __getattr__(name):
    """Lazy import to avoid loading Django models before Django is ready."""
    if name == "PostgresRLSMiddleware":
        from .middleware import PostgresRLSMiddleware
        return PostgresRLSMiddleware
    elif name == "RLSModel":
        from .models import RLSModel
        return RLSModel
    elif name == "RlsUser":
        from .models import RlsUser
        return RlsUser
    elif name == "RlsManyToManyField":
        from .models import RlsManyToManyField
        return RlsManyToManyField
    elif name == "RlsPolicy":
        from .models import RlsPolicy
        return RlsPolicy
    elif name == "PolicyCommand":
        from .models import PolicyCommand
        return PolicyCommand
    elif name == "PolicyMode":
        from .models import PolicyMode
        return PolicyMode
    elif name == "RlsAllowAll":
        from .models import RlsAllowAll
        return RlsAllowAll
    elif name == "RlsDenyAll":
        from .models import RlsDenyAll
        return RlsDenyAll
    elif name == "generate_rls_migration_operations":
        from .management_utils import generate_rls_migration_operations
        return generate_rls_migration_operations
    elif name == "generate_rls_migration_code":
        from .management_utils import generate_rls_migration_code
        return generate_rls_migration_code
    elif name == "CreateRLSPoliciesOperation":
        from .management_utils import CreateRLSPoliciesOperation
        return CreateRLSPoliciesOperation
    elif name == "EnableRLSOperation":
        from .management_utils import EnableRLSOperation
        return EnableRLSOperation
    elif name == "apply_rls_policies":
        from .management_utils import apply_rls_policies
        return apply_rls_policies
    elif name == "drop_rls_policies":
        from .management_utils import drop_rls_policies
        return drop_rls_policies
    elif name == "register_rls_model":
        from .signals import register_rls_model
        return register_rls_model
    elif name == "unregister_rls_model":
        from .signals import unregister_rls_model
        return unregister_rls_model
    elif name == "get_registered_models":
        from .signals import get_registered_models
        return get_registered_models
    elif name == "setup_rls_for_app":
        from .signals import setup_rls_for_app
        return setup_rls_for_app
    elif name == "setup_rls_for_model":
        from .signals import setup_rls_for_model
        return setup_rls_for_model
    elif name == "rls_role":
        from .middleware import rls_role
        return rls_role
    elif name == "SessionVar":
        from .expressions import SessionVar
        return SessionVar
    elif name == "CurrentUserId":
        from .expressions import CurrentUserId
        return CurrentUserId
    elif name == "RLSAuthenticationBackend":
        from .backends import RLSAuthenticationBackend
        return RLSAuthenticationBackend
    elif name == "RLSAuthenticationBackendWithPythonVerification":
        from .backends import RLSAuthenticationBackendWithPythonVerification
        return RLSAuthenticationBackendWithPythonVerification
    elif name == "get_auth_function_sql":
        from .backends import get_auth_function_sql
        return get_auth_function_sql
    elif name == "get_auth_function_sql_with_password_check":
        from .backends import get_auth_function_sql_with_password_check
        return get_auth_function_sql_with_password_check
    elif name == "get_user_fetch_function_sql":
        from .backends import get_user_fetch_function_sql
        return get_user_fetch_function_sql
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    # Middleware
    "PostgresRLSMiddleware",
    "rls_role",
    # Authentication backends
    "RLSAuthenticationBackend",
    "RLSAuthenticationBackendWithPythonVerification",
    "get_auth_function_sql",
    "get_auth_function_sql_with_password_check",
    "get_user_fetch_function_sql",
    # Models
    "RLSModel",
    "RlsUser",
    "RlsPolicy",
    "RlsManyToManyField",
    "PolicyCommand",
    "PolicyMode",
    "RlsAllowAll",
    "RlsDenyAll",
    # Database expressions
    "SessionVar",
    "CurrentUserId",
    # Migration utilities
    "generate_rls_migration_operations",
    "generate_rls_migration_code",
    "CreateRLSPoliciesOperation",
    "EnableRLSOperation",
    "apply_rls_policies",
    "drop_rls_policies",
    # Signal handlers
    "register_rls_model",
    "unregister_rls_model",
    "get_registered_models",
    "setup_rls_for_app",
    "setup_rls_for_model",
]
