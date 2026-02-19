"""
Step-up token generation and validation.

Tokens are HMAC-SHA256 signed with a shared secret and include:
- Expiration timestamp
- Tenant ID binding
- Random nonce for replay prevention

Token format: {base64url_payload}.{hmac_hex_signature}
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time

logger = logging.getLogger(__name__)

# Default TTL for step-up tokens (5 minutes)
DEFAULT_TOKEN_TTL_SECONDS = 300


def _get_secret():
    """Get the HMAC secret from environment."""
    return os.environ.get('STEP_UP_SECRET', '')


def generate_step_up_token(tenant_id, agent_id=None,
                           ttl_seconds=DEFAULT_TOKEN_TTL_SECONDS):
    """
    Generate a signed step-up authorization token.

    Args:
        tenant_id: Tenant the token is scoped to
        agent_id: Optional agent identifier
        ttl_seconds: Token lifetime in seconds

    Returns:
        Signed token string: {base64_payload}.{hmac_signature}

    Raises:
        ValueError: If STEP_UP_SECRET is not configured
    """
    secret = _get_secret()
    if not secret:
        raise ValueError('STEP_UP_SECRET environment variable is required')

    payload = {
        'exp': int(time.time()) + ttl_seconds,
        'tid': tenant_id,
        'sub': agent_id or 'system',
        'nonce': secrets.token_hex(16)
    }
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(',', ':')).encode()
    ).decode()
    sig = hmac.new(
        secret.encode(), payload_b64.encode(), hashlib.sha256
    ).hexdigest()
    return f'{payload_b64}.{sig}'


def validate_step_up_token(token, tenant_id):
    """
    Validate a step-up authorization token.

    Checks:
    - HMAC signature matches
    - Token is not expired
    - Tenant ID matches

    Args:
        token: The token string to validate
        tenant_id: Expected tenant ID

    Returns:
        tuple: (is_valid: bool, error_message: str or None)
    """
    secret = _get_secret()
    if not secret:
        logger.warning('STEP_UP_SECRET not configured; rejecting step-up token')
        return False, 'Server step-up validation not configured'

    if not token or '.' not in token:
        return False, 'Malformed step-up token'

    parts = token.rsplit('.', 1)
    if len(parts) != 2:
        return False, 'Malformed step-up token'

    payload_b64, sig = parts

    # Verify HMAC signature (constant-time comparison)
    expected_sig = hmac.new(
        secret.encode(), payload_b64.encode(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return False, 'Invalid token signature'

    # Decode and validate payload
    try:
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception:
        return False, 'Malformed token payload'

    # Check expiry
    if payload.get('exp', 0) < time.time():
        return False, 'Step-up token expired'

    # Check tenant binding
    if payload.get('tid') != tenant_id:
        return False, 'Token tenant mismatch'

    return True, None
