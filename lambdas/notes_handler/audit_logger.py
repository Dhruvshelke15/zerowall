import os
from datetime import datetime, timezone, timedelta

import boto3

APP_REGION = os.environ.get("APP_REGION", "us-east-2")
AUDIT_LOG_TABLE = os.environ.get("AUDIT_LOG_TABLE", "zerowall-audit-log")
AUDIT_LOG_TTL_DAYS = int(os.environ.get("AUDIT_LOG_TTL_DAYS", "30"))

_dynamodb = boto3.resource("dynamodb", region_name=APP_REGION)
_table = _dynamodb.Table(AUDIT_LOG_TABLE) # type: ignore


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _ttl():
    return int((datetime.now(timezone.utc) + timedelta(days=AUDIT_LOG_TTL_DAYS)).timestamp())


def log(user_id, action, resource, source_ip, user_agent, result, status_code, latency_ms):
    """
    Write one audit entry per request. Never raises - audit failures must not break the request.
    """
    try:
        item = {
            "userId": user_id,
            "timestamp": _now_iso(),
            "action": action,
            "resource": resource,
            "sourceIp": source_ip,
            "userAgent": user_agent,
            "result": result,
            "statusCode": int(status_code),
            "latencyMs": int(latency_ms),
            "ttl": _ttl(),
        }
        _table.put_item(Item=item)
    except Exception as e:
        print(f"Audit log write failed: {e}")