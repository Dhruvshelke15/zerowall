import os
from datetime import datetime, timezone, timedelta

import boto3

APP_REGION = os.environ.get("APP_REGION", "us-east-2")
RATE_LIMITS_TABLE = os.environ.get("RATE_LIMITS_TABLE", "zerowall-rate-limits")

_dynamodb = boto3.resource("dynamodb", region_name=APP_REGION)
_table = _dynamodb.Table(RATE_LIMITS_TABLE) # type: ignore


def _current_window():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M")


def _window_ttl():
    # Keep window record for ~5 min after window end so DynamoDB TTL cleans it up.
    return int((datetime.now(timezone.utc) + timedelta(minutes=6)).timestamp())


def check_and_increment(user_id, limit):
    """
    Atomically increment the request count for the user's current 1-minute window.
    Returns (allowed, current_count, retry_after_seconds).
    """
    window = _current_window()
    ttl = _window_ttl()

    response = _table.update_item(
        Key={"userId": user_id, "windowTimestamp": window},
        UpdateExpression="ADD requestCount :one SET #ttl = if_not_exists(#ttl, :ttl)",
        ExpressionAttributeNames={"#ttl": "ttl"},
        ExpressionAttributeValues={":one": 1, ":ttl": ttl},
        ReturnValues="ALL_NEW",
    )

    current_count = int(response["Attributes"]["requestCount"])

    if current_count > limit:
        now = datetime.now(timezone.utc)
        next_window = (now + timedelta(minutes=1)).replace(second=0, microsecond=0)
        retry_after = max(1, int((next_window - now).total_seconds()))
        return (False, current_count, retry_after)

    return (True, current_count, 0)