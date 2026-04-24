"""
Seeds the zerowall-roles DynamoDB table with default roles.
Run once during Phase 1 setup.

Usage: python scripts/seed_roles.py
"""

import boto3
import json

REGION = "us-east-2"
TABLE_NAME = "zerowall-roles"

dynamodb = boto3.resource("dynamodb", region_name=REGION)
table = dynamodb.Table(TABLE_NAME) # type: ignore


ROLES = [
    {
        "role": "user",
        "permissions": [
            {"resource": "/notes", "actions": ["GET", "POST"]},
            {"resource": "/notes/*", "actions": ["GET", "PUT"]}
        ]
    },
    {
        "role": "admin",
        "permissions": [
            {"resource": "/notes", "actions": ["GET", "POST"]},
            {"resource": "/notes/*", "actions": ["GET", "PUT", "DELETE"]}
        ]
    }
]


def main():
    print("=" * 50)
    print("ZeroWall - Seeding Roles Table")
    print(f"Table: {TABLE_NAME}")
    print(f"Region: {REGION}")
    print("=" * 50)
    print()

    for role_data in ROLES:
        table.put_item(Item=role_data)
        print(f"Seeded role: {role_data['role']}")
        print(f"  Permissions:")
        for perm in role_data["permissions"]:
            print(f"    {perm['resource']} -> {perm['actions']}")
        print()

    print("Verifying...")
    print()

    # Read back and confirm
    for role_data in ROLES:
        response = table.get_item(Key={"role": role_data["role"]})
        item = response.get("Item")
        if item:
            print(f"  {item['role']}: {json.dumps(item['permissions'])}")
        else:
            print(f"  WARNING: {role_data['role']} not found!")

    print()
    print("Seeding complete!")


if __name__ == "__main__":
    main()