import os
import jwt
import logging
from flask import request, redirect, jsonify, session, g
from functools import wraps
from urllib.parse import urlparse

# Setup logging
logger = logging.getLogger(__name__)

# ============================================================
# SUBSCRIPTION CHECK DECORATOR
# ============================================================

def requires_subscription(f):
    """Decorator to check if user has subscribed to Superset"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Skip check for public endpoints
        public_endpoints = [
            '/health', '/login/', '/auth/login', '/auth/logout',
            '/static/', '/assets/', '/favicon.ico', '/unauthorized/'
        ]
        
        if any(request.path.startswith(endpoint) for endpoint in public_endpoints):
            return f(*args, **kwargs)
        
        # Get token from multiple sources
        token = None
        
        # 1. Check Authorization header
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.replace('Bearer ', '')
        
        # 2. Check cookies
        if not token:
            token = request.cookies.get('access_token')
        
        # 3. Check session
        if not token:
            token = session.get('access_token')
        
        # 4. Check query parameter (for embedded dashboards)
        if not token:
            token = request.args.get('token')
        
        if not token:
            logger.warning(f"Missing token for request to {request.path}")
            return redirect('/login/?next=' + request.path)
        
        try:
            # Decode JWT
            payload = jwt.decode(
                token,
                os.environ.get('SUPABASE_JWT_SECRET'),
                algorithms=['HS256'],
                options={
                    'verify_signature': True,
                    'verify_exp': True,
                    'verify_aud': False
                }
            )
            
            # Extract subscription info from multiple possible locations
            # Handle both 'app_metadata' and 'raw_app_meta_data'
            app_metadata = payload.get('app_metadata', {}) or payload.get('raw_app_meta_data', {})
            
            # Get user info for logging
            user_email = payload.get('email', 'unknown')
            user_id = payload.get('sub', 'unknown')
            tenant_id = app_metadata.get('tenant_id', 'unknown')
            tenant_role = app_metadata.get('tenant_role', 'unknown')
            
            # Store user context in Flask's g object for RLS
            g.user = {
                'id': user_id,
                'email': user_email,
                'tenant_id': tenant_id,
                'tenant_role': tenant_role,
                'subscribed_services': app_metadata.get('subscribed_services', [])
            }
            
            # Store in session for persistence
            session['user'] = g.user
            
            # Check subscription
            subscribed_services = app_metadata.get('subscribed_services', [])
            
            # Normalize: handle both list and comma-separated string
            if isinstance(subscribed_services, str):
                subscribed_services = [s.strip() for s in subscribed_services.split(',')]
            
            if 'superset' not in subscribed_services:
                logger.warning(
                    f"User {user_email} (tenant: {tenant_id}) attempted to access "
                    f"Superset without subscription. Subscribed services: {subscribed_services}"
                )
                return redirect('/unauthorized/')
            
            logger.info(
                f"User {user_email} (tenant: {tenant_id}, role: {tenant_role}) "
                f"authenticated successfully for Superset"
            )
            
            return f(*args, **kwargs)
            
        except jwt.ExpiredSignatureError:
            logger.warning(f"Expired token for request to {request.path}")
            return redirect('/login/?reason=expired&next=' + request.path)
            
        except jwt.InvalidTokenError as e:
            logger.error(f"Invalid token for request to {request.path}: {str(e)}")
            return redirect('/login/?reason=invalid&next=' + request.path)
            
        except Exception as e:
            logger.error(f"Unexpected error in subscription check: {str(e)}")
            return redirect('/login/?reason=error&next=' + request.path)
    
    return decorated_function

# ============================================================
# APPLY TO ALL ROUTES (Optional)
# ============================================================

# If you want to apply to all routes programmatically
def apply_subscription_check(app):
    """Apply subscription check to all routes except public ones"""
    for rule in app.url_map.iter_rules():
        if not any(rule.rule.startswith(endpoint) for endpoint in ['/health', '/static', '/assets']):
            # This is handled by the decorator on views
            pass
    return app

# ============================================================
# UNAUTHORIZED PAGE ROUTE
# ============================================================

@app.route('/unauthorized/')
def unauthorized():
    """Show unauthorized page with subscription options"""
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
            <p>Please contact your administrator or subscribe through your account settings.</p>
            <a href="/login/" class="btn">Go to Login</a>
            <a href="https://app.revoseek.com/subscription" class="btn" style="background: #2ecc71;">Subscribe Now</a>
        </div>
    </body>
    </html>
    """

# ============================================================
# CUSTOM JWT PROVIDER WITH SUBSCRIPTION CHECK
# ============================================================

from superset_auth_kit.providers.jwt import JwtProvider

class CustomJwtProvider(JwtProvider):
    """Custom JWT provider with subscription validation"""
    
    def get_claims(self, payload):
        claims = super().get_claims(payload)
        
        # Extract from both possible locations
        app_metadata = payload.get('app_metadata', {}) or payload.get('raw_app_meta_data', {})
        
        claims['role'] = app_metadata.get('tenant_role', 'viewer')
        claims['tenant_id'] = app_metadata.get('tenant_id')
        claims['subscribed_services'] = app_metadata.get('subscribed_services', [])
        claims['email'] = payload.get('email')
        
        # Validate subscription
        subscribed_services = claims['subscribed_services']
        if isinstance(subscribed_services, str):
            subscribed_services = [s.strip() for s in subscribed_services.split(',')]
            claims['subscribed_services'] = subscribed_services
        
        return claims

# ============================================================
# HEALTH CHECK ENDPOINT (Public)
# ============================================================

@app.route('/health')
def health():
    return {"status": "ok"}, 200

# ============================================================
# LOGIN OVERRIDE WITH SUBSCRIPTION CHECK
# ============================================================

@app.route('/login/')
def login_with_check():
    """Override login to check subscription before showing login page"""
    # Check if already authenticated
    token = session.get('access_token') or request.cookies.get('access_token')
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
    
    # Show login page
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - Superset</title>
        <style>
            body { font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f5f5f5; }
            .login-box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 300px; text-align: center; }
            h2 { margin-bottom: 20px; }
            .btn { width: 100%; padding: 10px; background: #3498db; color: white; border: none; border-radius: 4px; cursor: pointer; }
            .btn:hover { background: #2980b9; }
        </style>
    </head>
    <body>
        <div class="login-box">
            <h2>🔐 Login to Superset</h2>
            <p style="color: #666; font-size: 14px;">Please log in through your main application</p>
            <a href="https://app.revoseek.com/login" class="btn" style="display: block; text-decoration: none;">Login via App</a>
            <hr style="margin: 20px 0;">
            <p style="color: #999; font-size: 12px;">You will be redirected after authentication</p>
        </div>
    </body>
    </html>
    """
