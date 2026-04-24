import json

def lambda_handler(event, context):
    """
    Anomaly Checker - runs every 5 minutes via CloudWatch Events.
    Scans audit log for suspicious patterns.
    """
    # TODO: Phase 4
    # 1. Query zerowall-audit-log for last 5 minutes
    # 2. Check for brute force (many denied requests from one user)
    # 3. Check for multi-IP access (same user, different IPs)
    # 4. Check for rate-limit abuse spike
    # 5. Publish to SNS if anomaly found

    return {
        "statusCode": 200,
        "body": json.dumps({"status": "no anomalies detected"})
    }