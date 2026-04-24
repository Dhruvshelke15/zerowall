"""
Creates the Cognito User Pool and App Client for ZeroWall.
Run once during Phase 1 setup.

Usage: python scripts/setup_cognito.py

After running, copy the User Pool ID and Client ID into your .env file.
"""

import boto3

REGION = "us-east-2"
POOL_NAME = "zerowall-user-pool"
CLIENT_NAME = "zerowall-client"

cognito = boto3.client("cognito-idp", region_name=REGION)


def main():
    print("=" * 50)
    print("ZeroWall - Cognito Setup")
    print(f"Region: {REGION}")
    print("=" * 50)
    print()

    # Step 1: Create User Pool
    print("Creating User Pool...")
    pool_response = cognito.create_user_pool(
        PoolName=POOL_NAME,
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
                "TemporaryPasswordValidityDays": 7
            }
        },
        AutoVerifiedAttributes=["email"],
        UsernameAttributes=["email"],
        Schema=[
            {
                "Name": "email",
                "Required": True,
                "Mutable": True,
                "AttributeDataType": "String"
            },
            {
                "Name": "role",
                "Required": False,
                "Mutable": True,
                "AttributeDataType": "String",
                "StringAttributeConstraints": {
                    "MinLength": "1",
                    "MaxLength": "20"
                }
            }
        ],
        AccountRecoverySetting={
            "RecoveryMechanisms": [
                {"Priority": 1, "Name": "verified_email"}
            ]
        }
    )

    user_pool_id = pool_response["UserPool"]["Id"]
    print(f"User Pool created: {user_pool_id}")
    print()

    # Step 2: Create App Client
    print("Creating App Client...")
    client_response = cognito.create_user_pool_client(
        UserPoolId=user_pool_id,
        ClientName=CLIENT_NAME,
        GenerateSecret=False,  # no secret for public client (Postman testing)
        ExplicitAuthFlows=[
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH"
        ],
        AccessTokenValidity=1,      # 1 hour
        IdTokenValidity=1,          # 1 hour
        RefreshTokenValidity=30,    # 30 days
        TokenValidityUnits={
            "AccessToken": "hours",
            "IdToken": "hours",
            "RefreshToken": "days"
        },
        PreventUserExistenceErrors="ENABLED"  # don't leak if a user exists
    )

    client_id = client_response["UserPoolClient"]["ClientId"]
    print(f"App Client created: {client_id}")
    print()

    # Summary
    print("=" * 50)
    print("SETUP COMPLETE - Save these values in your .env file:")
    print("=" * 50)
    print()
    print(f"  COGNITO_USER_POOL_ID={user_pool_id}")
    print(f"  COGNITO_CLIENT_ID={client_id}")
    print()
    print("To make a user an admin later, run:")
    print(f"  aws cognito-idp admin-update-user-attributes \\")
    print(f"    --user-pool-id {user_pool_id} \\")
    print(f"    --username <email> \\")
    print(f'    --user-attributes Name="custom:role",Value="admin"')


if __name__ == "__main__":
    main()