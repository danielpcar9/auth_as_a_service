import redis
from src.core.config import settings

# Create a Redis client instance
redis_client = redis.from_url(
    settings.REDIS_URL,
    encoding="utf-8",
    decode_responses=True
)

def get_redis_client():
    """Return the global Redis client"""
    return redis_client
