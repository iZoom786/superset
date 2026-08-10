import os

SECRET_KEY = os.environ.get("SECRET_KEY", "fallback-secret-key")

# PostgreSQL
POSTGRES_USER = os.environ.get("POSTGRES_USER", "superset")
POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "")
POSTGRES_HOST = os.environ.get("POSTGRES_HOST", "superset-postgres")
POSTGRES_PORT = os.environ.get("POSTGRES_PORT", "5432")
POSTGRES_DB = os.environ.get("POSTGRES_DB", "superset-db")

SQLALCHEMY_DATABASE_URI = (
    f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
)

ENABLE_PROXY_FIX = True

FEATURE_FLAGS = {
    "ROW_LEVEL_SECURITY": True,
}

AUTH_ROLE_PUBLIC = None
PUBLIC_ROLE_LIKE_GAMMA = False

LOG_LEVEL = "INFO"
