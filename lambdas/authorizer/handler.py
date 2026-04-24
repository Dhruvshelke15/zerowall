import json

def lambda_handler(event, context):
    """
    Lambda Authorizer - validates JWT and checks RBAC permissions.
    Triggered by API Gateway on every protected request.
    """
    # TODO: Phase 2
    # 1. Extract token from Authorization header
    # 2. Verify JWT against Cognito JWKS
    # 3. Extract userId and role from claims
    # 4. Query zerowall-roles table for permissions
    # 5. Return Allow/Deny IAM policy

    return {
        "principalId": "user",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": "Deny",
                    "Resource": event.get("methodArn", "*")
                }
            ]
        }
    }