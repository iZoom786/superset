import os
from urllib.parse import quote_plus

# ============================================================
# BASE CONFIGURATION
# ============================================================

SECRET_KEY = os.environ["SECRET_KEY"]

# PostgreSQL
postgres_user = quote_plus(os.environ["POSTGRES_USER"])
postgres_password = quote_plus(os.environ["POSTGRES_PASSWORD"])
postgres_host = os.environ.get("POSTGRES_HOST", "superset-postgres")
postgres_port = os.environ.get("POSTGRES_PORT", "5432")
postgres_db = quote_plus(os.environ["POSTGRES_DB"])

SQLALCHEMY_DATABASE_URI = (
    f"postgresql+psycopg2://{postgres_user}:{postgres_password}"
    f"@{postgres_host}:{postgres_port}/{postgres_db}"
)

# Redis Cache
redis_host = os.environ.get("REDIS_HOST", "superset-redis")
redis_port = os.environ.get("REDIS_PORT", "6379")
redis_password = quote_plus(os.environ["REDIS_PASSWORD"])

CACHE_CONFIG = {
    "CACHE_TYPE": "RedisCache",
    "CACHE_DEFAULT_TIMEOUT": 300,
    "CACHE_KEY_PREFIX": "superset_cache_",
    "CACHE_REDIS_URL": f"redis://:{redis_password}@{redis_host}:{redis_port}/1",
}

DATA_CACHE_CONFIG = {
    "CACHE_TYPE": "RedisCache",
    "CACHE_DEFAULT_TIMEOUT": 300,
    "CACHE_KEY_PREFIX": "superset_data_",
    "CACHE_REDIS_URL": f"redis://:{redis_password}@{redis_host}:{redis_port}/2",
}

FILTER_STATE_CACHE_CONFIG = {
    "CACHE_TYPE": "RedisCache",
    "CACHE_DEFAULT_TIMEOUT": 86400,
    "CACHE_KEY_PREFIX": "superset_filter_",
    "CACHE_REDIS_URL": f"redis://:{redis_password}@{redis_host}:{redis_port}/3",
}

EXPLORE_FORM_DATA_CACHE_CONFIG = {
    "CACHE_TYPE": "RedisCache",
    "CACHE_DEFAULT_TIMEOUT": 86400,
    "CACHE_KEY_PREFIX": "superset_explore_",
    "CACHE_REDIS_URL": f"redis://:{redis_password}@{redis_host}:{redis_port}/4",
}

WTF_CSRF_ENABLED = True
TALISMAN_ENABLED = False
ENABLE_PROXY_FIX = True

FEATURE_FLAGS = {
    "ALERT_REPORTS": False,
    "EMBEDDED_SUPERSET": True,
}

# ============================================================
# SUPABASE JWT AUTHENTICATION
# ============================================================

from superset.security import SupersetSecurityManager
from superset_auth_kit.api.blueprint import create_sso_blueprint, init_app
from superset_auth_kit.providers.jwt import JwtProvider
from superset_auth_kit.security.manager import build_manager
from superset_auth_kit.sync.role_mapper import RoleMapper
from superset_auth_kit.tenant.context import TenantContext

# ============================================================
# CUSTOM JWT PROVIDER (Reads from app_metadata)
# ============================================================

class CustomJwtProvider(JwtProvider):
    """Custom provider that reads role and tenant_id from app_metadata"""
    
    def get_claims(self, payload):
        claims = super().get_claims(payload)
        
        # Read from app_metadata (correct location)
        app_metadata = payload.get("app_metadata", {})
        claims["role"] = app_metadata.get("tenant_role", "viewer")
        claims["tenant_id"] = app_metadata.get("tenant_id")
        
        return claims

# JWT Provider
_jwt_provider = CustomJwtProvider(
    secret_or_key=os.environ.get("SUPABASE_JWT_SECRET"),
    algorithms=["HS256"],
)

# ============================================================
# ROLE MAPPING (With allowed_roles)
# ============================================================

# Define allowed Superset roles
ALLOWED_ROLES = ["Admin", "Alpha", "Gamma"]

_role_mapper = RoleMapper(
    mapping={
        "owner": ["Admin"],
        "admin": ["Admin"],
        "member": ["Alpha"],
        "viewer": ["Gamma"],
    },
    default_roles=("Gamma",),
    allowed_roles=ALLOWED_ROLES,
)

# ============================================================
# CUSTOM TENANT CONTEXT (For RLS)
# ============================================================

class CustomTenantContext(TenantContext):
    @classmethod
    def get_tenant_id(cls):
        from flask import g
        return getattr(g.user, 'tenant_id', None) if hasattr(g, 'user') else None

# Build Security Manager
CUSTOM_SECURITY_MANAGER = build_manager(
    SupersetSecurityManager,
    identity_provider=_jwt_provider,
    role_mapper=_role_mapper,
)

# SSO Blueprint
BLUEPRINTS = [create_sso_blueprint()]
FLASK_APP_MUTATOR = init_app

# Multi-Tenant RLS via Jinja
JINJA_CONTEXT_ADDONS = {
    "current_tenant": CustomTenantContext.get_tenant_id,
}

# Enable RLS feature flag
FEATURE_FLAGS["ROW_LEVEL_SECURITY"] = True
