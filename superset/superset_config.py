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
# SUPABASE JWT AUTHENTICATION (Updated)
# ============================================================

from superset.security import SupersetSecurityManager
from superset_auth_kit.api.blueprint import create_sso_blueprint, init_app
from superset_auth_kit.providers.jwt import JwtProvider
from superset_auth_kit.security.manager import build_manager
from superset_auth_kit.sync.role_mapper import RoleMapper
from superset_auth_kit.tenant.context import TenantContext

# JWT Provider (Supabase)
_jwt_provider = JwtProvider(
    secret_or_key=os.environ.get("SUPABASE_JWT_SECRET"),
    algorithms=["HS256"],
)

# ============================================================
# ROLE MAPPING: Supabase app_metadata.tenant_role → Superset Role
# ============================================================

_role_mapper = RoleMapper(
    mapping={
        "owner": ["Admin"],      # tenant_role 'owner' → Superset 'Admin'
        "admin": ["Admin"],      # tenant_role 'admin' → Superset 'Admin'
        "member": ["Alpha"],     # tenant_role 'member' → Superset 'Alpha'
        "viewer": ["Gamma"],     # tenant_role 'viewer' → Superset 'Gamma'
    },
    default_roles=("Gamma",),    # Default for unknown roles
)

# ============================================================
# CUSTOM CLAIMS EXTRACTOR (For JWT fields)
# ============================================================

class CustomJwtProvider(JwtProvider):
    """Custom provider that reads role and tenant_id from app_metadata"""
    
    def get_claims(self, payload):
        claims = super().get_claims(payload)
        
        # Read role from app_metadata.tenant_role
        app_metadata = payload.get("app_metadata", {})
        claims["role"] = app_metadata.get("tenant_role", "viewer")
        
        # Read tenant_id from app_metadata.tenant_id
        claims["tenant_id"] = app_metadata.get("tenant_id")
        
        return claims

# Use custom provider
_jwt_provider = CustomJwtProvider(
    secret_or_key=os.environ.get("SUPABASE_JWT_SECRET"),
    algorithms=["HS256"],
)

# ============================================================
# CUSTOM TENANT CONTEXT (For RLS)
# ============================================================

class CustomTenantContext(TenantContext):
    """Custom tenant context that reads tenant_id from app_metadata"""
    
    @classmethod
    def get_tenant_id(cls):
        """Returns tenant_id from the current user's JWT"""
        from flask import g
        return g.user.tenant_id if hasattr(g, 'user') else None

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
