"""
Rate limiting middleware for R6 FHIR routes.

Per-tenant rate limiting using an in-memory token bucket.
Production deployments should use Redis-backed rate limiting.
"""

import logging
import time
from flask import request, jsonify

logger = logging.getLogger(__name__)

# Configuration
DEFAULT_RATE_LIMIT = 120  # requests per minute
DEFAULT_WINDOW_SECONDS = 60

# In-memory store: tenant_id -> {count, reset_at}
_rate_limits = {}


def check_rate_limit(tenant_id, max_requests=DEFAULT_RATE_LIMIT,
                     window_seconds=DEFAULT_WINDOW_SECONDS):
    """
    Check if a tenant has exceeded their rate limit.

    Returns:
        tuple: (allowed: bool, remaining: int, reset_at: float)
    """
    now = time.time()
    entry = _rate_limits.get(tenant_id)

    if not entry or now > entry['reset_at']:
        _rate_limits[tenant_id] = {
            'count': 1,
            'reset_at': now + window_seconds,
        }
        return True, max_requests - 1, now + window_seconds

    entry['count'] += 1
    remaining = max(0, max_requests - entry['count'])
    return entry['count'] <= max_requests, remaining, entry['reset_at']


def rate_limit_middleware(blueprint):
    """
    Register rate limiting as a before_request hook on the blueprint.
    Adds X-RateLimit-* headers to responses.
    """

    @blueprint.after_request
    def add_rate_limit_headers(response):
        """Add rate limit headers to every response."""
        tenant_id = request.headers.get('X-Tenant-Id', 'anonymous')
        entry = _rate_limits.get(tenant_id)
        if entry:
            remaining = max(0, DEFAULT_RATE_LIMIT - entry['count'])
            response.headers['X-RateLimit-Limit'] = str(DEFAULT_RATE_LIMIT)
            response.headers['X-RateLimit-Remaining'] = str(remaining)
            response.headers['X-RateLimit-Reset'] = str(int(entry['reset_at']))
        return response

    @blueprint.before_request
    def enforce_rate_limit():
        """Block requests that exceed the rate limit."""
        # Skip rate limiting for metadata (discovery)
        if request.path.endswith('/metadata'):
            return None
        if request.path.endswith('/oauth-authorization-server'):
            return None
        if request.path.endswith('/smart-configuration'):
            return None

        tenant_id = request.headers.get('X-Tenant-Id', 'anonymous')
        allowed, remaining, reset_at = check_rate_limit(tenant_id)

        if not allowed:
            response = jsonify({
                'resourceType': 'OperationOutcome',
                'issue': [{
                    'severity': 'error',
                    'code': 'throttled',
                    'diagnostics': 'Rate limit exceeded. Try again later.'
                }]
            })
            response.status_code = 429
            response.headers['X-RateLimit-Limit'] = str(DEFAULT_RATE_LIMIT)
            response.headers['X-RateLimit-Remaining'] = '0'
            response.headers['X-RateLimit-Reset'] = str(int(reset_at))
            response.headers['Retry-After'] = str(int(reset_at - time.time()))
            return response
