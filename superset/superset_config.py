import os

# Base configuration
SECRET_KEY = os.environ.get("SECRET_KEY", "this-is-a-dev-key")
SQLALCHEMY_DATABASE_URI = f"postgresql://{os.environ.get('POSTGRES_USER')}:{os.environ.get('POSTGRES_PASSWORD')}@{os.environ.get('POSTGRES_HOST')}:{os.environ.get('POSTGRES_PORT')}/{os.environ.get('POSTGRES_DB')}"
ENABLE_PROXY_FIX = True

# Feature Flags
FEATURE_FLAGS = {
    "ROW_LEVEL_SECURITY": True,
}

# Disable the built-in login to redirect to your app
AUTH_ROLE_PUBLIC = None
PUBLIC_ROLE_LIKE_GAMMA = False

# Logging
LOG_LEVEL = "INFO"
