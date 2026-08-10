# superset_config.py

# ============================================================
# DISABLE NATIVE LOGIN
# ============================================================

# Disable Superset's built-in login form
AUTH_ROLE_PUBLIC = None  # No public access
PUBLIC_ROLE_LIKE_GAMMA = False  # Don't allow public role

# Force OAuth/JWT only
OAUTH_PROVIDERS = []  # Disable OAuth if not needed

# Set authentication type to JWT only
CUSTOM_SECURITY_MANAGER = build_manager(
    SupersetSecurityManager,
    identity_provider=_jwt_provider,
    role_mapper=_role_mapper,
    # Disable default login form
    auth_view_class=None,
    user_view_class=None,
)

# Prevent login via username/password
ENABLE_OAUTH = False
AUTH_TYPE = None  # Force JWT only

# ============================================================
# OVERRIDE LOGIN ROUTE
# ============================================================

from flask import redirect, request, session, jsonify
from functools import wraps
import jwt
import os
import logging

logger = logging.getLogger(__name__)

# ============================================================
# SUBSCRIPTION CHECK DECORATOR (Enhanced)
# ============================================================

def requires_subscription(f):
    """Decorator to check if user has subscribed to Superset"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Skip public endpoints
        public_endpoints = [
            '/health', '/static/', '/assets/', '/favicon.ico',
            '/api/v1/security/login/', '/api/v1/security/refresh/'
        ]
        
        if any(request.path.startswith(endpoint) for endpoint in public_endpoints):
            return f(*args, **kwargs)
        
        # Get token from multiple sources
        token = (request.headers.get('Authorization', '').replace('Bearer ', '') or
                 request.cookies.get('access_token') or
                 session.get('access_token') or
                 request.args.get('token'))
        
        if not token:
            return redirect('/auth/login?next=' + request.path)
        
        try:
            payload = jwt.decode(
                token,
                os.environ.get('SUPABASE_JWT_SECRET'),
                algorithms=['HS256']
            )
            
            # Extract from app_metadata or raw_app_meta_data
            app_metadata = payload.get('app_metadata', {}) or payload.get('raw_app_meta_data', {})
            
            # Store user context
            g.user = {
                'id': payload.get('sub'),
                'email': payload.get('email'),
                'tenant_id': app_metadata.get('tenant_id'),
                'tenant_role': app_metadata.get('tenant_role', 'viewer'),
                'subscribed_services': app_metadata.get('subscribed_services', [])
            }
            
            session['user'] = g.user
            
            # Check subscription
            services = app_metadata.get('subscribed_services', [])
            if isinstance(services, str):
                services = [s.strip() for s in services.split(',')]
            
            if 'superset' not in services:
                logger.warning(f"User {g.user['email']} not subscribed to Superset")
                return redirect('/auth/unauthorized?reason=subscription_required')
            
            return f(*args, **kwargs)
            
        except jwt.ExpiredSignatureError:
            return redirect('/auth/login?reason=expired')
        except jwt.InvalidTokenError as e:
            logger.error(f"Invalid token: {str(e)}")
            return redirect('/auth/login?reason=invalid')
        except Exception as e:
            logger.error(f"Auth error: {str(e)}")
            return redirect('/auth/login?reason=error')
    
    return decorated_function

# ============================================================
# OVERRIDE SUPERSET'S LOGIN ROUTE
# ============================================================

# Patch the login view to bypass default login
from superset import app

@app.route('/login/', methods=['GET', 'POST'])
def custom_login():
    """Custom login that redirects to your app"""
    token = (request.cookies.get('access_token') or 
             session.get('access_token') or
             request.headers.get('Authorization', '').replace('Bearer ', ''))
    
    if token:
        try:
            payload = jwt.decode(
                token,
                os.environ.get('SUPABASE_JWT_SECRET'),
                algorithms=['HS256']
            )
            app_metadata = payload.get('app_metadata', {}) or payload.get('raw_app_meta_data', {})
            if 'superset' in app_metadata.get('subscribed_services', []):
                return redirect('/superset/dashboard/')
        except:
            pass
    
    # Redirect to your app's login
    return redirect('https://app.revoseek.com/login?return_to=https://bi.revoseek.com/auth/sso')

# ============================================================
# SSO ROUTE
# ============================================================

@app.route('/auth/sso')
def sso_login():
    """SSO entry point from your app"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
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
        
        # Check subscription
        services = app_metadata.get('subscribed_services', [])
        if isinstance(services, str):
            services = [s.strip() for s in services.split(',')]
        
        if 'superset' not in services:
            return redirect('/auth/unauthorized')
        
        # Create session
        session['access_token'] = token
        session['user'] = {
            'email': payload.get('email'),
            'tenant_id': app_metadata.get('tenant_id'),
            'role': app_metadata.get('tenant_role', 'viewer')
        }
        
        # Set cookie
        response = redirect('/superset/dashboard/')
        response.set_cookie('access_token', token, httponly=True, secure=True)
        return response
        
    except Exception as e:
        logger.error(f"SSO error: {str(e)}")
        return redirect('https://app.revoseek.com/login')

# ============================================================
# UNAUTHORIZED ROUTE
# ============================================================

@app.route('/auth/unauthorized')
def unauthorized():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Unauthorized</title>
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

# ============================================================
# APPLY SUBSCRIPTION CHECK TO ALL ROUTES
# ============================================================

from flask import g

@app.before_request
def before_request():
    """Apply subscription check before every request"""
    # Skip public endpoints
    public_paths = ['/health', '/static', '/assets', '/favicon.ico', '/auth/unauthorized']
    if any(request.path.startswith(p) for p in public_paths):
        return
    
    # Skip SSO endpoint
    if request.path.startswith('/auth/sso'):
        return
    
    # Apply check
    token = (request.headers.get('Authorization', '').replace('Bearer ', '') or
             request.cookies.get('access_token') or
             session.get('access_token') or
             request.args.get('token'))
    
    if not token:
        return redirect('/auth/login?next=' + request.path)
    
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
        
        # Store user context
        g.user = {
            'email': payload.get('email'),
            'tenant_id': app_metadata.get('tenant_id'),
            'role': app_metadata.get('tenant_role', 'viewer')
        }
        session['user'] = g.user
        
    except Exception as e:
        logger.error(f"Auth error: {str(e)}")
        return redirect('/auth/login?next=' + request.path)
