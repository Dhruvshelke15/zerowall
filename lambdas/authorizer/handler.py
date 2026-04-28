"""
ZeroWall Lambda Authorizer.

Runs on every protected API request. Validates the JWT, looks up the
caller's role permissions, and returns an IAM policy that either allows
or denies the specific method+resource being requested.

Returned context (userId, role, email) is forwarded to downstream
Lambdas via event.requestContext.authorizer.
"""

import json
import logging
import os

import boto3
import jwt

from jwt_utils import verify_token


logger = logging.getLogger()
logger.setLevel(logging.INFO)


REGION = os.environ["APP_REGION"]
ROLES_TABLE_NAME = os.environ.get("ROLES_TABLE", "zerowall-roles")

dynamodb = boto3.resource("dynamodb", region_name=REGION)
roles_table = dynamodb.Table(ROLES_TABLE_NAME) # type: ignore


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def lambda_handler(event, context):
    """
    REQUEST authorizer entry point.

    event contains:
      - methodArn: the full ARN of the method being invoked
      - headers: request headers (case-insensitive lookup needed)
      - httpMethod, path, resource: routing info
    """
    method_arn = event.get("methodArn", "*")

    # 1. Extract token. Missing or malformed = 401.
    try:
        token = _extract_token(event)
    except _UnauthorizedError as e:
        logger.info("Auth failed (no token): %s", e)
        # Raising this exact string makes API Gateway return 401 Unauthorized
        raise Exception("Unauthorized")

    # 2. Verify token. Any failure = 401.
    try:
        claims = verify_token(token)
    except jwt.ExpiredSignatureError:
        logger.info("Auth failed: token expired")
        raise Exception("Unauthorized")
    except jwt.InvalidTokenError as e:
        logger.info("Auth failed: invalid token (%s)", e)
        raise Exception("Unauthorized")
    except Exception as e:
        # Network errors fetching JWKS, etc. Treat as auth failure but log loud.
        logger.exception("Unexpected error verifying token: %s", e)
        raise Exception("Unauthorized")

    user_id = claims.get("sub")
    role = claims.get("custom:role") or claims.get("cognito:groups") or "user"
    # 'username' is on access tokens; ID token uses 'cognito:username'
    username = claims.get("username") or claims.get("cognito:username", "")

    # 3. Pull HTTP method and resource path from the methodArn.
    # methodArn format:
    #   arn:aws:execute-api:<region>:<account>:<api-id>/<stage>/<METHOD>/<resource-path>
    http_method, resource_path = _parse_method_arn(method_arn)

    # 4. RBAC check.
    allowed = _is_allowed(role, http_method, resource_path)

    effect = "Allow" if allowed else "Deny"
    logger.info(
        "Authz decision: user=%s role=%s method=%s path=%s -> %s",
        user_id, role, http_method, resource_path, effect,
    )

    return _build_policy(
        principal_id=user_id,
        effect=effect,
        method_arn=method_arn,
        context={
            "userId": user_id,
            "role": role,
            "username": username,
        },
    )


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

class _UnauthorizedError(Exception):
    pass


def _extract_token(event):
    """Pull the bearer token from the Authorization header (case-insensitive)."""
    headers = event.get("headers") or {}
    auth_header = None
    for key, value in headers.items():
        if key.lower() == "authorization":
            auth_header = value
            break

    if not auth_header:
        raise _UnauthorizedError("Authorization header missing")

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise _UnauthorizedError("Authorization header must be 'Bearer <token>'")

    return parts[1]


def _parse_method_arn(method_arn):
    """
    Parse out the HTTP method and resource path from the methodArn.

    Example methodArn:
      arn:aws:execute-api:us-east-2:123456:abcd1234/dev/GET/notes/xyz

    The portion after the stage is "<METHOD>/<resource-path>".
    """
    try:
        # Split off the ARN prefix to get "<api-id>/<stage>/<METHOD>/<path...>"
        suffix = method_arn.split(":", 5)[5]
        parts = suffix.split("/", 3)
        # parts: [api_id, stage, METHOD, path]
        method = parts[2].upper()
        path = "/" + (parts[3] if len(parts) > 3 else "")
        return method, path
    except (IndexError, AttributeError):
        # Defensive: malformed methodArn shouldn't happen from API Gateway
        return "UNKNOWN", "/"


def _is_allowed(role, http_method, resource_path):
    """
    Look up the role in DynamoDB and check if it has permission for this
    method + resource. Permission entries support a single-segment '*' wildcard
    in the resource pattern (e.g. '/notes/*' matches '/notes/abc' but not
    '/notes/abc/comments').
    """
    try:
        result = roles_table.get_item(Key={"role": role})
    except Exception as e:
        logger.exception("Failed to query roles table: %s", e)
        return False

    item = result.get("Item")
    if not item:
        logger.info("RBAC deny: role '%s' not found in roles table", role)
        return False

    permissions = item.get("permissions", [])
    for perm in permissions:
        pattern = perm.get("resource", "")
        actions = perm.get("actions", [])
        if _path_matches(pattern, resource_path) and http_method in actions:
            return True

    return False


def _path_matches(pattern, path):
    """
    Match a path against a pattern where '*' is a single-segment wildcard.

    Examples:
      '/notes'      matches '/notes'
      '/notes/*'    matches '/notes/abc' but NOT '/notes/abc/comments'
      '/notes'      does NOT match '/notes/abc'
    """
    pattern_parts = [p for p in pattern.split("/") if p]
    path_parts = [p for p in path.split("/") if p]

    if len(pattern_parts) != len(path_parts):
        return False

    for pat, actual in zip(pattern_parts, path_parts):
        if pat == "*":
            continue
        if pat != actual:
            return False
    return True


def _build_policy(principal_id, effect, method_arn, context):
    """Build the IAM policy document API Gateway expects from an authorizer."""
    return {
        "principalId": principal_id or "anonymous",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": method_arn,
                }
            ],
        },
        # All values in context must be strings, numbers, or booleans.
        "context": {k: (v if v is not None else "") for k, v in context.items()},
    }