

import json
import logging
import os
from datetime import datetime, timezone

import boto3
import jwt

from jwt_utils import verify_token


logger = logging.getLogger()
logger.setLevel(logging.INFO)


REGION = os.environ["APP_REGION"]
ROLES_TABLE_NAME = os.environ.get("ROLES_TABLE", "zerowall-roles")

dynamodb = boto3.resource("dynamodb", region_name=REGION)
roles_table = dynamodb.Table(ROLES_TABLE_NAME)  # type: ignore


# --------------------------------------------------------------------------
# Structured logging
# --------------------------------------------------------------------------

def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _emit(result, **fields):
    """
    Emit a single-line JSON log entry to CloudWatch.
    'result' is one of: ALLOWED, DENIED_AUTH, DENIED_RBAC.
    Metric filters key off this field.
    """
    payload = {
        "logType": "authz",
        "timestamp": _now_iso(),
        "result": result,
        **fields,
    }
    print(json.dumps(payload, default=str))


def _extract_source_ip(event):
    rc = event.get("requestContext") or {}
    identity = rc.get("identity") or {}
    return identity.get("sourceIp", "unknown")


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def lambda_handler(event, context):
    method_arn = event.get("methodArn", "*")
    source_ip = _extract_source_ip(event)
    http_method, resource_path = _parse_method_arn(method_arn)

    # 1. Extract token. Missing or malformed = 401.
    try:
        token = _extract_token(event)
    except _UnauthorizedError as e:
        _emit("DENIED_AUTH", reason="no_token", detail=str(e),
              action=http_method, resource=resource_path, sourceIp=source_ip)
        raise Exception("Unauthorized")

    # 2. Verify token. Any failure = 401.
    try:
        claims = verify_token(token)
    except jwt.ExpiredSignatureError:
        _emit("DENIED_AUTH", reason="token_expired",
              action=http_method, resource=resource_path, sourceIp=source_ip)
        raise Exception("Unauthorized")
    except jwt.InvalidTokenError as e:
        _emit("DENIED_AUTH", reason="invalid_token", detail=str(e),
              action=http_method, resource=resource_path, sourceIp=source_ip)
        raise Exception("Unauthorized")
    except Exception as e:
        logger.exception("Unexpected error verifying token")
        _emit("DENIED_AUTH", reason="verify_error", detail=str(e),
              action=http_method, resource=resource_path, sourceIp=source_ip)
        raise Exception("Unauthorized")

    user_id = claims.get("sub")
    role = claims.get("custom:role")

    if not role:
        _emit("DENIED_AUTH", reason="missing_role_claim", userId=user_id,
              action=http_method, resource=resource_path, sourceIp=source_ip)
        raise Exception("Unauthorized")

    username = claims.get("cognito:username") or claims.get("username", "")

    # 3. RBAC check.
    allowed, rbac_reason = _is_allowed(role, http_method, resource_path)

    if allowed:
        _emit("ALLOWED", userId=user_id, role=role,
              action=http_method, resource=resource_path, sourceIp=source_ip)
        effect = "Allow"
    else:
        _emit("DENIED_RBAC", reason=rbac_reason, userId=user_id, role=role,
              action=http_method, resource=resource_path, sourceIp=source_ip)
        effect = "Deny"

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
    try:
        suffix = method_arn.split(":", 5)[5]
        parts = suffix.split("/", 3)
        method = parts[2].upper()
        path = "/" + (parts[3] if len(parts) > 3 else "")
        return method, path
    except (IndexError, AttributeError):
        return "UNKNOWN", "/"


def _is_allowed(role, http_method, resource_path):
    """
    Returns (allowed: bool, reason: str). Reason is meaningful only on deny.
    """
    try:
        result = roles_table.get_item(Key={"role": role})
    except Exception as e:
        logger.exception("Failed to query roles table")
        return False, f"roles_lookup_error:{e}"

    item = result.get("Item")
    if not item:
        return False, "role_not_found"

    permissions = item.get("permissions", [])
    for perm in permissions:
        pattern = perm.get("resource", "")
        actions = perm.get("actions", [])
        if _path_matches(pattern, resource_path) and http_method in actions:
            return True, ""

    return False, "no_matching_permission"


def _path_matches(pattern, path):
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
        "context": {k: (v if v is not None else "") for k, v in context.items()},
    }