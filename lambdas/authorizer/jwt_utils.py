"""
JWT utilities for the ZeroWall authorizer.

Handles:
- Fetching and caching Cognito's JWKS (public keys)
- Verifying JWT signature, expiration, issuer, and token_use
- Returning decoded claims for downstream RBAC checks

We verify Cognito ID tokens (not access tokens) because custom attributes
like 'custom:role' live in the ID token. Cognito only adds custom claims
to the access token if the user pool is on the Essentials/Plus feature
plan, which this project intentionally avoids to stay on Free Tier.
"""

import json
import os
import time
import urllib.request

import jwt
from jwt.algorithms import RSAAlgorithm


# Module-level cache. Persists across warm invocations of the same
# Lambda container, so we only hit the JWKS endpoint on cold start.
_jwks_cache = {
    "keys_by_kid": None,
    "fetched_at": 0,
}

# Refresh JWKS every 24 hours as a safety net. Cognito rotates keys rarely,
# but if a rotation happens we don't want to be stuck with stale keys forever.
_JWKS_TTL_SECONDS = 24 * 60 * 60


def _get_jwks_url():
    region = os.environ["APP_REGION"]
    pool_id = os.environ["COGNITO_USER_POOL_ID"]
    return f"https://cognito-idp.{region}.amazonaws.com/{pool_id}/.well-known/jwks.json"


def _get_issuer():
    region = os.environ["APP_REGION"]
    pool_id = os.environ["COGNITO_USER_POOL_ID"]
    return f"https://cognito-idp.{region}.amazonaws.com/{pool_id}"


def _fetch_jwks():
    """Download JWKS from Cognito and index keys by their kid."""
    url = _get_jwks_url()
    with urllib.request.urlopen(url, timeout=5) as response:
        jwks = json.loads(response.read().decode("utf-8"))

    keys_by_kid = {}
    for key in jwks["keys"]:
        keys_by_kid[key["kid"]] = RSAAlgorithm.from_jwk(json.dumps(key))
    return keys_by_kid


def _get_signing_key(kid):
    """Return the public key for the given kid, refreshing JWKS if needed."""
    now = time.time()
    cache_expired = (now - _jwks_cache["fetched_at"]) > _JWKS_TTL_SECONDS

    if _jwks_cache["keys_by_kid"] is None or cache_expired:
        _jwks_cache["keys_by_kid"] = _fetch_jwks()
        _jwks_cache["fetched_at"] = now

    key = _jwks_cache["keys_by_kid"].get(kid)

    # Possible the token was signed with a key we haven't seen yet
    # (e.g. Cognito just rotated). Force a refresh and try once more.
    if key is None:
        _jwks_cache["keys_by_kid"] = _fetch_jwks()
        _jwks_cache["fetched_at"] = now
        key = _jwks_cache["keys_by_kid"].get(kid)

    if key is None:
        raise jwt.InvalidTokenError(f"No matching JWKS key for kid={kid}")

    return key


def verify_token(token):
    """
    Verify a Cognito ID token end to end.

    Returns the decoded claims dict on success.
    Raises jwt.InvalidTokenError (or a subclass like ExpiredSignatureError)
    on any failure.

    ID tokens contain the 'aud' claim (set to the app client ID) and
    custom user attributes such as 'custom:role'.
    """
    expected_client_id = os.environ["COGNITO_CLIENT_ID"]
    expected_issuer = _get_issuer()

    # Pull the kid from the token header so we know which public key to use
    headers = jwt.get_unverified_header(token)
    kid = headers.get("kid")
    if not kid:
        raise jwt.InvalidTokenError("Token header missing 'kid'")

    signing_key = _get_signing_key(kid)

    # PyJWT verifies signature, exp, nbf, iat, iss, and aud for us.
    claims = jwt.decode(
        token,
        key=signing_key,
        algorithms=["RS256"],
        issuer=expected_issuer,
        audience=expected_client_id,
        options={"require": ["exp", "iss", "sub", "token_use", "aud"]},
    )

    # Cognito-specific check PyJWT doesn't do for us
    if claims.get("token_use") != "id":
        raise jwt.InvalidTokenError(
            f"Expected ID token, got token_use={claims.get('token_use')}"
        )

    return claims