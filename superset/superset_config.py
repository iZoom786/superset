import os
import jwt
import logging
from urllib.parse import quote_plus

logger = logging.getLogger(__name__)

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
    "ROW_LEVEL_SECURITY": True,
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
# CUSTOM JWT PROVIDER
# ============================================================

class CustomJwtProvider(JwtProvider):
    def get_claims(self, payload):
        claims = super().get_claims(payload)
        app_metadata = payload.get("app_metadata", {}) or payload.get("raw_app_meta_data", {})
        claims["role"] = app_metadata.get("tenant_role", "viewer")
        claims["tenant_id"] = app_metadata.get("tenant_id")
        claims["subscribed_services"] = app_metadata.get("subscribed_services", [])
        return claims

_jwt_provider = CustomJwtProvider(
    secret_or_key=os.environ.get("SUPABASE_JWT_SECRET"),
    algorithms=["HS256"],
)

# ============================================================
# ROLE MAPPING
# ============================================================

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
    allow_native_admin=True,
)

CUSTOM_SECURITY_MANAGER = build_manager(
    SupersetSecurityManager,
    identity_provider=_jwt_provider,
    role_mapper=_role_mapper,
)

# ============================================================
# SSO BLUEPRINT
# ============================================================

BLUEPRINTS = [create_sso_blueprint()]
FLASK_APP_MUTATOR = init_app

# ============================================================
# MULTI-TENANT RLS
# ============================================================

class CustomTenantContext(TenantContext):
    @classmethod
    def get_tenant_id(cls):
        from flask import g
        return getattr(g.user, 'tenant_id', None) if hasattr(g, 'user') else None

JINJA_CONTEXT_ADDONS = {
    "current_tenant": CustomTenantContext.get_tenant_id,
}

# ============================================================
# ⭐ FIXED: CUSTOM BLUEPRINT (No current_app usage)
# ============================================================

from flask import Blueprint, request, redirect, session

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/unauthorized')
def unauthorized():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Subscription Required</title>
        <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
            .container { max-width: 600px; margin: 0 auto; }
            h1 { color: #e74c3c; }
            .btn { 
                display: inline-block; 
                padding: 10px 20px; 
                background: #3498db; 
                color: white; 
                text-decoration: none; 
                border-radius: 5px;
                margin-top: 20px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔒 Subscription Required</h1>
            <p>You need to subscribe to Superset to access this service.</p>
            <p>Please subscribe through your account settings.</p>
            <a href="https://app.revoseek.com/subscription" class="btn">Subscribe Now</a>
        </div>
    </body>
    </html>
    """

@auth_bp.route('/sso')
def sso_callback():
    """Handle SSO callback from your app"""
    token = request.args.get('token')
    if not token:
        return redirect('https://app.revoseek.com/login')
    
    try:
        payload = jwt.decode(
            token,
            os.environ.get('SUPABASE_JWT_SECRET'),
            algorithms=['HS256']
        )
        
        app_metadata = payload.get('app_metadata', {}) or payload.get('raw_app_meta_data', {})
        services = app_metadata.get('subscribed_services', [])
        if isinstance(services, str):
            services = [s.strip() for s in services.split(',')]
        
        if 'superset' not in services:
            return redirect('/auth/unauthorized')
        
        # Store user in session
        session['access_token'] = token
        session['user'] = {
            'email': payload.get('email'),
            'tenant_id': app_metadata.get('tenant_id'),
            'role': app_metadata.get('tenant_role', 'viewer')
        }
        
        response = redirect('/superset/dashboard/')
        response.set_cookie('access_token', token, httponly=True, secure=True)
        return response
        
    except Exception as e:
        logger.error(f"SSO error: {str(e)}")
        return redirect('https://app.revoseek.com/login')

@auth_bp.route('/login')
def custom_login_redirect():
    """Redirect all login attempts to SSO"""
    if session.get('user'):
        return redirect('/superset/dashboard/')
    return redirect('https://app.revoseek.com/login?return_to=https://bi.revoseek.com/auth/sso')

# ⭐ Register the blueprint
BLUEPRINTS.append(auth_bp)

# ============================================================
# DISABLE NATIVE LOGIN
# ============================================================

# Disable Superset's built-in login
AUTH_ROLE_PUBLIC = None
PUBLIC_ROLE_LIKE_GAMMA = False
ENABLE_OAUTH = False
