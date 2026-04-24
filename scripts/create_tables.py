"""
Creates all DynamoDB tables for ZeroWall.
Run once during Phase 1 setup.

Usage: python scripts/create_tables.py
"""

import boto3
import time

REGION = "us-east-2"
dynamodb = boto3.client("dynamodb", region_name=REGION)


def create_table(table_name, key_schema, attribute_definitions, ttl_attribute=None):
    """Create a DynamoDB table and optionally enable TTL."""
    try:
        dynamodb.create_table(
            TableName=table_name,
            KeySchema=key_schema,
            AttributeDefinitions=attribute_definitions,
            BillingMode="PAY_PER_REQUEST"  # no need to manage capacity, free tier covers it
        )
        print(f"Creating {table_name}...")

        # Wait until the table is active
        waiter = dynamodb.get_waiter("table_exists")
        waiter.wait(TableName=table_name)
        print(f"{table_name} is ACTIVE.")

        # Enable TTL if specified
        if ttl_attribute:
            dynamodb.update_time_to_live(
                TableName=table_name,
                TimeToLiveSpecification={
                    "Enabled": True,
                    "AttributeName": ttl_attribute
                }
            )
            print(f"  TTL enabled on '{ttl_attribute}'")

    except dynamodb.exceptions.ResourceInUseException:
        print(f"{table_name} already exists. Skipping.")


def main():
    print("=" * 50)
    print("ZeroWall - Creating DynamoDB Tables")
    print(f"Region: {REGION}")
    print("=" * 50)
    print()

    # 1. Notes table
    create_table(
        table_name="zerowall-notes",
        key_schema=[
            {"AttributeName": "userId", "KeyType": "HASH"},
            {"AttributeName": "noteId", "KeyType": "RANGE"}
        ],
        attribute_definitions=[
            {"AttributeName": "userId", "AttributeType": "S"},
            {"AttributeName": "noteId", "AttributeType": "S"}
        ]
    )
    print()

    # 2. Roles table
    create_table(
        table_name="zerowall-roles",
        key_schema=[
            {"AttributeName": "role", "KeyType": "HASH"}
        ],
        attribute_definitions=[
            {"AttributeName": "role", "AttributeType": "S"}
        ]
    )
    print()

    # 3. Rate limits table (with TTL for auto-cleanup)
    create_table(
        table_name="zerowall-rate-limits",
        key_schema=[
            {"AttributeName": "userId", "KeyType": "HASH"},
            {"AttributeName": "windowTimestamp", "KeyType": "RANGE"}
        ],
        attribute_definitions=[
            {"AttributeName": "userId", "AttributeType": "S"},
            {"AttributeName": "windowTimestamp", "AttributeType": "S"}
        ],
        ttl_attribute="ttl"
    )
    print()

    # 4. Audit log table (with TTL for 30-day auto-cleanup)
    create_table(
        table_name="zerowall-audit-log",
        key_schema=[
            {"AttributeName": "userId", "KeyType": "HASH"},
            {"AttributeName": "timestamp", "KeyType": "RANGE"}
        ],
        attribute_definitions=[
            {"AttributeName": "userId", "AttributeType": "S"},
            {"AttributeName": "timestamp", "AttributeType": "S"}
        ],
        ttl_attribute="ttl"
    )
    print()

    print("=" * 50)
    print("All tables created successfully!")
    print("=" * 50)


if __name__ == "__main__":
    main()