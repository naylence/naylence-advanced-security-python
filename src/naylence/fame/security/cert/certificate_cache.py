"""
Thread-safe LRU cache for certificate validation results.

Caches validated public keys by certificate chain fingerprint to avoid
re-validating the same certificates repeatedly.
"""

from __future__ import annotations

import datetime
import hashlib
import threading
from typing import Any, Callable, Tuple

from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)

# Cache entry: (public_key, not_after_datetime)
CacheEntry = Tuple[Any, datetime.datetime]

# Global cache state
_TRUST_CACHE: dict[bytes, CacheEntry] = {}
_TRUST_LOCK = threading.RLock()
_CACHE_SIZE = 512  # Configurable if needed


def get_or_validate(
    chain_bytes: bytes,
    validator_callback: Callable[[], Tuple[Any, datetime.datetime]],
) -> Any:
    """
    Get cached public key or validate and cache the result.

    Args:
        chain_bytes: Raw bytes of the certificate chain
        validator_callback: Function that validates the chain and returns (public_key, not_after)

    Returns:
        The public key from the certificate chain
    """
    # Build cache key: SHA-256 over the full chain bytes
    fp = hashlib.sha256(chain_bytes).digest()
    cache_key_hex = fp.hex()[:16]

    with _TRUST_LOCK:
        cached = _TRUST_CACHE.get(fp)
        if cached:
            pub_key, not_after = cached
            # Use timezone-aware current time for comparison
            now = datetime.datetime.now(datetime.timezone.utc)
            if now <= not_after:
                return (pub_key, not_after)  # Fast path: still valid
            else:
                # Expired, remove from cache
                logger.debug(
                    "certificate_cache_expired",
                    cache_key=cache_key_hex,
                    expired_at=not_after.isoformat(),
                    current_time=now.isoformat(),
                )
                _TRUST_CACHE.pop(fp, None)

    # Slow path: validate the chain
    logger.debug(
        "certificate_cache_miss",
        cache_key=cache_key_hex,
        reason="not_found" if not cached else "expired",
        calling_validation=True,
    )

    result = validator_callback()
    pub_key, not_after = result

    # Cache the result
    with _TRUST_LOCK:
        # Simple FIFO eviction if cache is full
        if len(_TRUST_CACHE) >= _CACHE_SIZE:
            evicted_key = next(iter(_TRUST_CACHE))
            _TRUST_CACHE.pop(evicted_key)
            logger.debug(
                "certificate_cache_evicted",
                evicted_key=evicted_key.hex()[:16],
                cache_size_before=_CACHE_SIZE,
            )

        _TRUST_CACHE[fp] = (pub_key, not_after)
        logger.debug(
            "certificate_cache_stored",
            cache_key=cache_key_hex,
            expires_at=not_after.isoformat(),
            new_cache_size=len(_TRUST_CACHE),
            public_key_type=type(pub_key).__name__,
        )

    return result


def clear_cache() -> None:
    """Clear all cached entries (useful for testing)."""
    with _TRUST_LOCK:
        _TRUST_CACHE.clear()


def cache_stats() -> dict[str, int]:
    """Get cache statistics."""
    with _TRUST_LOCK:
        return {
            "size": len(_TRUST_CACHE),
            "max_size": _CACHE_SIZE,
        }
