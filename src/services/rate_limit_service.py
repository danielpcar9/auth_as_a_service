from src.core.redis import redis_client
from src.core.config import settings

class RateLimitService:
    """
    Service to handle rate limiting using Redis.
    """
    
    def is_rate_limited(self, key: str, max_attempts: int, window: int) -> bool:
        """
        Check if a key (IP or Email) has exceeded the max attempts within the window.
        """
        current_attempts = redis_client.get(f"ratelimit:{key}")
        
        if current_attempts and int(current_attempts) >= max_attempts:
            return True
            
        return False

    def increment_attempts(self, key: str, window: int):
        """
        Increment the attempt counter for a key.
        """
        redis_key = f"ratelimit:{key}"
        pipe = redis_client.pipeline()
        pipe.incr(redis_key)
        pipe.expire(redis_key, window)
        pipe.execute()

    def reset_attempts(self, key: str):
        """
        Reset attempts for a key (e.g., after successful login).
        """
        redis_client.delete(f"ratelimit:{key}")

rate_limit_service = RateLimitService()
