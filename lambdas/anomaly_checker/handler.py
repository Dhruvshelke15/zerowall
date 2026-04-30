"""
ZeroWall Anomaly Checker.

Scheduled Lambda that runs every 5 minutes via EventBridge.
Scans the audit log for the last LOOKBACK_MINUTES and flags suspicious
patterns:

  1. Brute force        - one user with too many denied/error requests
  2. Multi-IP           - one user hitting from multiple distinct IPs
  3. Rate-limit spike   - cross-user 429 surge (coordinated abuse)

Findings are published as a single SNS message to zerowall-alerts.

Env vars (all configurable, sensible demo defaults):
  APP_REGION                       AWS region (us-east-2)
  AUDIT_LOG_TABLE                  DynamoDB table name (default: zerowall-audit-log)
  SNS_TOPIC_ARN                    target SNS topic ARN (required)
  LOOKBACK_MINUTES                 window size in minutes (default: 5)
  BRUTE_FORCE_DENIED_THRESHOLD     denials per user to flag brute force (default: 5)
  MULTI_IP_THRESHOLD               distinct IPs per user to flag (default: 2)
  RATE_LIMIT_SPIKE_THRESHOLD       cross-user 429s to flag spike (default: 20)
"""

import json
import os
from collections import defaultdict
from datetime import datetime, timezone, timedelta

import boto3
from boto3.dynamodb.conditions import Attr


APP_REGION = os.environ.get("APP_REGION", "us-east-2")
AUDIT_LOG_TABLE = os.environ.get("AUDIT_LOG_TABLE", "zerowall-audit-log")
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]

LOOKBACK_MINUTES = int(os.environ.get("LOOKBACK_MINUTES", "5"))
BRUTE_FORCE_DENIED_THRESHOLD = int(os.environ.get("BRUTE_FORCE_DENIED_THRESHOLD", "5"))
MULTI_IP_THRESHOLD = int(os.environ.get("MULTI_IP_THRESHOLD", "2"))
RATE_LIMIT_SPIKE_THRESHOLD = int(os.environ.get("RATE_LIMIT_SPIKE_THRESHOLD", "20"))

# Result values from the notes handler we treat as "denied" for brute-force counting.
DENIED_RESULTS = {"DENIED_RATE_LIMIT", "ERROR"}

dynamodb = boto3.resource("dynamodb", region_name=APP_REGION)
audit_table = dynamodb.Table(AUDIT_LOG_TABLE)  # type: ignore
sns = boto3.client("sns", region_name=APP_REGION)


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _cutoff_iso(minutes_ago):
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return cutoff.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def lambda_handler(event, context):
    cutoff = _cutoff_iso(LOOKBACK_MINUTES)
    print(json.dumps({
        "logType": "anomaly_check_start",
        "cutoff": cutoff,
        "lookbackMinutes": LOOKBACK_MINUTES,
    }))

    items = _scan_recent(cutoff)
    print(json.dumps({"logType": "anomaly_scan_complete", "itemsRead": len(items)}))

    findings = _analyze(items)

    if findings:
        _publish_findings(findings, cutoff)
        print(json.dumps({"logType": "anomaly_published", "findingCount": len(findings)}))
    else:
        print(json.dumps({"logType": "anomaly_clean"}))

    return {
        "statusCode": 200,
        "body": json.dumps({
            "itemsRead": len(items),
            "findings": findings,
        }),
    }


# --------------------------------------------------------------------------
# DynamoDB scan
# --------------------------------------------------------------------------

def _scan_recent(cutoff_iso):
    """
    Scan the audit log for entries with timestamp >= cutoff.

    Note: Scan is wasteful at scale. Fine for demo since audit log is small
    (30-day TTL) and we run only every 5 minutes. Production would use a GSI
    on a coarse time bucket.
    """
    items = []
    kwargs = {
        "FilterExpression": Attr("timestamp").gte(cutoff_iso),
    }
    while True:
        resp = audit_table.scan(**kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        kwargs["ExclusiveStartKey"] = last_key
    return items


# --------------------------------------------------------------------------
# Pattern analysis
# --------------------------------------------------------------------------

def _analyze(items):
    """
    Returns a list of findings. Each finding is a dict with at least
    {pattern, severity, summary, details}.
    """
    findings = []

    # Per-user aggregations.
    denied_by_user = defaultdict(int)
    ips_by_user = defaultdict(set)
    rate_limit_total = 0

    for it in items:
        user = it.get("userId", "unknown")
        result = it.get("result", "")
        ip = it.get("sourceIp", "unknown")

        if result in DENIED_RESULTS:
            denied_by_user[user] += 1
        if result == "DENIED_RATE_LIMIT":
            rate_limit_total += 1

        # Track IPs for users with at least one request.
        if ip and ip != "unknown":
            ips_by_user[user].add(ip)

    # 1. Brute force: a single user with too many denied/error requests.
    for user, count in denied_by_user.items():
        if count >= BRUTE_FORCE_DENIED_THRESHOLD:
            findings.append({
                "pattern": "BRUTE_FORCE",
                "severity": "high",
                "summary": f"User {user} had {count} denied requests in the last {LOOKBACK_MINUTES}m (threshold: {BRUTE_FORCE_DENIED_THRESHOLD}).",
                "details": {"userId": user, "deniedCount": count},
            })

    # 2. Multi-IP: a single user hitting from multiple distinct IPs.
    for user, ip_set in ips_by_user.items():
        if len(ip_set) >= MULTI_IP_THRESHOLD:
            findings.append({
                "pattern": "MULTI_IP",
                "severity": "medium",
                "summary": f"User {user} accessed from {len(ip_set)} distinct IPs in the last {LOOKBACK_MINUTES}m (threshold: {MULTI_IP_THRESHOLD}).",
                "details": {"userId": user, "ipCount": len(ip_set), "ips": sorted(ip_set)},
            })

    # 3. Rate-limit spike: too many 429s across all users.
    if rate_limit_total >= RATE_LIMIT_SPIKE_THRESHOLD:
        findings.append({
            "pattern": "RATE_LIMIT_SPIKE",
            "severity": "medium",
            "summary": f"{rate_limit_total} rate-limit denials across all users in the last {LOOKBACK_MINUTES}m (threshold: {RATE_LIMIT_SPIKE_THRESHOLD}).",
            "details": {"rateLimitCount": rate_limit_total},
        })

    return findings


# --------------------------------------------------------------------------
# SNS publish
# --------------------------------------------------------------------------

def _publish_findings(findings, cutoff):
    subject = f"ZeroWall anomaly detected ({len(findings)} finding{'s' if len(findings) != 1 else ''})"
    # Subject must be <= 100 chars per SNS limits.
    subject = subject[:100]

    lines = [
        "ZeroWall Anomaly Checker",
        f"Detected at: {_now_iso()}",
        f"Lookback window: last {LOOKBACK_MINUTES} minutes (since {cutoff})",
        "",
        f"{len(findings)} anomaly pattern(s) detected:",
        "",
    ]

    for i, f in enumerate(findings, start=1):
        lines.append(f"{i}. [{f['pattern']} / severity: {f['severity']}]")
        lines.append(f"   {f['summary']}")
        details_str = json.dumps(f["details"], default=str)
        lines.append(f"   details: {details_str}")
        lines.append("")

    lines.append("This alert was generated by zerowall-anomaly-checker.")

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject,
        Message="\n".join(lines),
    )