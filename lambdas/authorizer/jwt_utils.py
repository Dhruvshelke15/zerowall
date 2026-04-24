"""
JWT utility functions - decode, verify, and cache JWKS.
"""

# TODO: Phase 2
# - download_jwks(region, user_pool_id) -> cache keys
# - verify_token(token, jwks) -> decoded claims or raise
# - extract_claims(decoded) -> { userId, role }