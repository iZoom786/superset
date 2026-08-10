import os
import jwt
import logging
from urllib.parse import quote_plus

logger = logging.getLogger(__name__)

# ============================================================
# ⭐ DISABLE AUTHKIT ROLE RECONCILER COMPLETELY
# ============================================================

SAK_DISABLE_RECONCILER = True

# ============================================================
# ⭐ ENABLE OAUTH
# ============================================================

ENABLE_OAUTH = True

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

WTF_CSRF_ENABLED = True
TALISMAN_ENABLED = False
ENABLE_PROXY_FIX = True

FEATURE_FLAGS = {
    "ALERT_REPORTS": False,
    "EMBEDDED_SUPERSET": True,
    "ROW_LEVEL_SECURITY": True,
}

# ============================================================
# OAUTH ROLE MAPPING
# ============================================================

OAUTH_PROVIDERS = [
    {
        "name": "supabase",
        "icon": "fa-database",
        "token_key": "access_token",
        "remote_app": {
            "client_id": "",
            "client_secret": "",
            "server_metadata_url": "",
            "request_token_params": {},
            "access_token_method": "POST",
            "access_token_params": {},
            "authorize_url": "",
        },
    }
]

def get_oauth_user_info(provider, response=None):
    """Map JWT claims to Superset user and role."""
    if provider == "supabase":
        token = response.get("access_token")
        if not token:
            return {}
        try:
            payload = jwt.decode(
                token,
                os.environ.get("SUPABASE_JWT_SECRET"),
                algorithms=["HS256"]
            )
            app_metadata = payload.get("app_metadata", {}) or payload.get("raw_app_meta_data", {})
            
            # Role mapping
            role_mapping = {
                "authenticated": "Gamma",
                "owner": "Admin",
                "admin": "Admin",
                "member": "Alpha",
                "viewer": "Gamma",
            }
            jwt_role = app_metadata.get("tenant_role", "authenticated")
            superset_role = role_mapping.get(jwt_role, "Gamma")
            
            return {
                "username": payload.get("email", "").split("@")[0],
                "email": payload.get("email", ""),
                "first_name": payload.get("user_metadata", {}).get("full_name", ""),
                "last_name": "",
                "role": superset_role,
                "tenant_id": app_metadata.get("tenant_id"),
                "subscribed_services": app_metadata.get("subscribed_services", []),
            }
        except Exception as e:
            logger.error(f"Error decoding JWT: {str(e)}")
            return {}
    return {}

# ============================================================
# SUPABASE JWT AUTHENTICATION (Minimal)
# ============================================================

from superset.security import SupersetSecurityManager
from superset_auth_kit.api.blueprint import create_sso_blueprint, init_app
from superset_auth_kit.providers.jwt import JwtProvider
from superset_auth_kit.security.manager import build_manager

class CustomJwtProvider(JwtProvider):
    def get_claims(self, payload):
        claims = super().get_claims(payload)
        app_metadata = payload.get("app_metadata", {}) or payload.get("raw_app_meta_data", {})
        claims["role"] = app_metadata.get("tenant_role", "authenticated")
        claims["tenant_id"] = app_metadata.get("tenant_id")
        return claims

_jwt_provider = CustomJwtProvider(
    secret_or_key=os.environ.get("SUPABASE_JWT_SECRET"),
    algorithms=["HS256"],
)

# ⭐ Minimal security manager (no role mapper)
CUSTOM_SECURITY_MANAGER = build_manager(
    SupersetSecurityManager,
    identity_provider=_jwt_provider,
)

BLUEPRINTS = [create_sso_blueprint()]
FLASK_APP_MUTATOR = init_app

# ============================================================
# AUTH BLUEPRINT
# ============================================================

from flask import Blueprint, request, redirect, session

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/unauthorized')
def unauthorized():
    return """
    <h1>🔒 Subscription Required</h1>
    <p>You need to subscribe to Superset to access this service.</p>
    <a href="https://www.primelakehouse.com/subscription">Subscribe Now</a>
    """

@auth_bp.route('/sso')
def sso_callback():
    token = request.args.get('token')
    if not token:
        return redirect('https://www.primelakehouse.com/login')
    try:
        payload = jwt.decode(
            token,
            os.environ.get('SUPABASE_JWT_SECRET'),
            algorithms=['HS256']
        )
        session['access_token'] = token
        session['user'] = {
            'email': payload.get('email'),
            'tenant_id': payload.get('app_metadata', {}).get('tenant_id'),
            'role': payload.get('app_metadata', {}).get('tenant_role', 'authenticated')
        }
        response = redirect('/superset/dashboard/')
        response.set_cookie('access_token', token, httponly=True, secure=True)
        return response
    except Exception as e:
        logger.error(f"SSO error: {str(e)}")
        return redirect('https://www.primelakehouse.com/login')

@auth_bp.route('/login')
def custom_login_redirect():
    if session.get('user'):
        return redirect('/superset/dashboard/')
    return redirect('https://www.primelakehouse.com/login')

BLUEPRINTS.append(auth_bp)

# ============================================================
# DISABLE NATIVE LOGIN
# ============================================================

AUTH_ROLE_PUBLIC = None
PUBLIC_ROLE_LIKE_GAMMA = False
LOGOUT_REDIRECT_URL = 'https://www.primelakehouse.com/logout'
