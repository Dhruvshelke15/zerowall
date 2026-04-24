"""
Auth handler - wraps Cognito sign-up, login, and token refresh.
Public endpoints (no authorizer).
"""

import json
import os
import boto3

REGION = os.environ.get("AWS_REGION", "us-east-2")
USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID")
CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID")

cognito = boto3.client("cognito-idp", region_name=REGION)


def lambda_handler(event, context):
    """Main entry point - routes to signup, login, or refresh."""
    path = event.get("path", "")
    method = event.get("httpMethod", "")
    
    try:
        body = json.loads(event.get("body", "{}") or "{}")
    except json.JSONDecodeError:
        return response(400, {"status": "error", "error": "INVALID_JSON", "message": "Request body must be valid JSON."})

    if method != "POST":
        return response(405, {"status": "error", "error": "METHOD_NOT_ALLOWED", "message": "Only POST is allowed."})

    if path == "/auth/signup":
        return handle_signup(body)
    elif path == "/auth/login":
        return handle_login(body)
    elif path == "/auth/refresh":
        return handle_refresh(body)
    else:
        return response(404, {"status": "error", "error": "NOT_FOUND", "message": f"Unknown path: {path}"})


def handle_signup(body):
    """Register a new user with Cognito."""
    email = body.get("email")
    password = body.get("password")

    if not email or not password:
        return response(400, {
            "status": "error",
            "error": "MISSING_FIELDS",
            "message": "Both 'email' and 'password' are required."
        })

    try:
        # Sign up the user
        cognito.sign_up(
            ClientId=CLIENT_ID,
            Username=email,
            Password=password,
            UserAttributes=[
                {"Name": "email", "Value": email},
                {"Name": "custom:role", "Value": "user"}  # default role
            ]
        )

        # Auto-confirm for demo purposes (skip email verification)
        cognito.admin_confirm_sign_up(
            UserPoolId=USER_POOL_ID,
            Username=email
        )

        return response(201, {
            "status": "success",
            "message": f"User {email} created and confirmed.",
            "data": {"email": email, "role": "user"}
        })

    except cognito.exceptions.UsernameExistsException:
        return response(409, {
            "status": "error",
            "error": "USER_EXISTS",
            "message": "A user with this email already exists."
        })
    except cognito.exceptions.InvalidPasswordException as e:
        return response(400, {
            "status": "error",
            "error": "INVALID_PASSWORD",
            "message": str(e)
        })
    except Exception as e:
        return response(500, {
            "status": "error",
            "error": "SIGNUP_FAILED",
            "message": str(e)
        })


def handle_login(body):
    """Authenticate user and return JWT tokens."""
    email = body.get("email")
    password = body.get("password")

    if not email or not password:
        return response(400, {
            "status": "error",
            "error": "MISSING_FIELDS",
            "message": "Both 'email' and 'password' are required."
        })

    try:
        auth_result = cognito.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": email,
                "PASSWORD": password
            }
        )

        tokens = auth_result["AuthenticationResult"]

        return response(200, {
            "status": "success",
            "message": "Login successful.",
            "data": {
                "accessToken": tokens["AccessToken"],
                "idToken": tokens["IdToken"],
                "refreshToken": tokens["RefreshToken"],
                "expiresIn": tokens["ExpiresIn"],
                "tokenType": tokens["TokenType"]
            }
        })

    except cognito.exceptions.NotAuthorizedException:
        return response(401, {
            "status": "error",
            "error": "INVALID_CREDENTIALS",
            "message": "Incorrect email or password."
        })
    except cognito.exceptions.UserNotFoundException:
        return response(401, {
            "status": "error",
            "error": "INVALID_CREDENTIALS",
            "message": "Incorrect email or password."  # same message to not leak user existence
        })
    except Exception as e:
        return response(500, {
            "status": "error",
            "error": "LOGIN_FAILED",
            "message": str(e)
        })


def handle_refresh(body):
    """Refresh an expired access token."""
    refresh_token = body.get("refreshToken")

    if not refresh_token:
        return response(400, {
            "status": "error",
            "error": "MISSING_FIELDS",
            "message": "'refreshToken' is required."
        })

    try:
        auth_result = cognito.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters={
                "REFRESH_TOKEN": refresh_token
            }
        )

        tokens = auth_result["AuthenticationResult"]

        return response(200, {
            "status": "success",
            "message": "Token refreshed.",
            "data": {
                "accessToken": tokens["AccessToken"],
                "idToken": tokens["IdToken"],
                "expiresIn": tokens["ExpiresIn"],
                "tokenType": tokens["TokenType"]
            }
        })

    except cognito.exceptions.NotAuthorizedException:
        return response(401, {
            "status": "error",
            "error": "INVALID_REFRESH_TOKEN",
            "message": "Refresh token is invalid or expired."
        })
    except Exception as e:
        return response(500, {
            "status": "error",
            "error": "REFRESH_FAILED",
            "message": str(e)
        })


def response(status_code, body):
    """Build a standard API Gateway response."""
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
        },
        "body": json.dumps(body)
    }