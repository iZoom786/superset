import os
from urllib.parse import quote_plus

SECRET_KEY = os.environ["SECRET_KEY"]

postgres_user = quote_plus(os.environ["POSTGRES_USER"])
postgres_password = quote_plus(os.environ["POSTGRES_PASSWORD"])
postgres_host = os.environ.get("POSTGRES_HOST", "superset-postgres")
postgres_port = os.environ.get("POSTGRES_PORT", "5432")
postgres_db = quote_plus(os.environ["POSTGRES_DB"])

SQLALCHEMY_DATABASE_URI = (
    f"postgresql+psycopg2://{postgres_user}:{postgres_password}"
    f"@{postgres_host}:{postgres_port}/{postgres_db}"
)

redis_host = os.environ.get("REDIS_HOST", "superset-redis")
redis_port = os.environ.get("REDIS_PORT", "6379")
redis_password = quote_plus(os.environ["REDIS_PASSWORD"])

CACHE_CONFIG = {
    "CACHE_TYPE": "RedisCache",
    "CACHE_DEFAULT_TIMEOUT": 300,
    "CACHE_KEY_PREFIX": "superset_cache_",
    "CACHE_REDIS_URL": (
        f"redis://:{redis_password}@{redis_host}:{redis_port}/1"
    ),
}

DATA_CACHE_CONFIG = {
    "CACHE_TYPE": "RedisCache",
    "CACHE_DEFAULT_TIMEOUT": 300,
    "CACHE_KEY_PREFIX": "superset_data_",
    "CACHE_REDIS_URL": (
        f"redis://:{redis_password}@{redis_host}:{redis_port}/2"
    ),
}

FILTER_STATE_CACHE_CONFIG = {
    "CACHE_TYPE": "RedisCache",
    "CACHE_DEFAULT_TIMEOUT": 86400,
    "CACHE_KEY_PREFIX": "superset_filter_",
    "CACHE_REDIS_URL": (
        f"redis://:{redis_password}@{redis_host}:{redis_port}/3"
    ),
}

EXPLORE_FORM_DATA_CACHE_CONFIG = {
    "CACHE_TYPE": "RedisCache",
    "CACHE_DEFAULT_TIMEOUT": 86400,
    "CACHE_KEY_PREFIX": "superset_explore_",
    "CACHE_REDIS_URL": (
        f"redis://:{redis_password}@{redis_host}:{redis_port}/4"
    ),
}

WTF_CSRF_ENABLED = True
TALISMAN_ENABLED = False
ENABLE_PROXY_FIX = True

FEATURE_FLAGS = {
    "ALERT_REPORTS": False,
    "EMBEDDED_SUPERSET": True,
}
