import time
from typing import Dict, Any, Protocol

from oak_runner.auth.credentials.models import Credential


# Cache interface and implementations
class CredentialCache(Protocol):
    """Protocol for credential caching implementations."""
    
    async def get(self, key: str) -> Credential | None:
        """Retrieve credential from cache."""
        ...
    
    async def set(self, key: str, credential: Credential, ttl: int | None = None) -> None:
        """Store credential in cache with optional TTL."""
        ...
    
    async def delete(self, key: str) -> None:
        """Remove credential from cache."""
        ...
    
    async def clear(self) -> None:
        """Clear all cached credentials."""
        ...


class InMemoryCredentialCache(CredentialCache):
    """In-memory implementation of credential cache."""
    
    def __init__(self):
        self._cache: Dict[str, Dict[str, Any]] = {}
    
    async def get(self, key: str) -> Credential | None:
        """Retrieve credential from memory cache."""
        entry = self._cache.get(key)
        if not entry:
            return None
        
        # Check TTL expiration
        if entry.get('expires_at') and time.time() > entry['expires_at']:
            del self._cache[key]
            return None
        
        return entry['credential']
    
    async def set(self, key: str, credential: Credential, ttl: int | None = None) -> None:
        """Store credential in memory cache."""
        entry = {
            'credential': credential,
            'expires_at': time.time() + ttl if ttl else None
        }
        self._cache[key] = entry
    
    async def delete(self, key: str) -> None:
        """Remove credential from cache."""
        self._cache.pop(key, None)
    
    async def clear(self) -> None:
        """Clear all cached credentials."""
        self._cache.clear()
