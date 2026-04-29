import os
import uuid
from datetime import datetime, timezone

import boto3

APP_REGION = os.environ.get("APP_REGION", "us-east-2")
NOTES_TABLE = os.environ.get("NOTES_TABLE", "zerowall-notes")

_dynamodb = boto3.resource("dynamodb", region_name=APP_REGION)
_table = _dynamodb.Table(NOTES_TABLE) # type: ignore


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def list_notes(user_id):
    response = _table.query(
        KeyConditionExpression="userId = :uid",
        ExpressionAttributeValues={":uid": user_id},
    )
    return {"notes": response.get("Items", [])}


def create_note(user_id, title, content):
    note_id = str(uuid.uuid4())
    now = _now_iso()
    item = {
        "userId": user_id,
        "noteId": note_id,
        "title": title,
        "content": content,
        "createdAt": now,
        "updatedAt": now,
    }
    _table.put_item(Item=item)
    return item


def get_note(user_id, note_id):
    response = _table.get_item(Key={"userId": user_id, "noteId": note_id})
    return response.get("Item")


def update_note(user_id, note_id, title, content):
    # Confirm ownership and existence before updating.
    if get_note(user_id, note_id) is None:
        return None

    update_parts = []
    expression_values = {":updatedAt": _now_iso()}
    expression_names = {}

    if title is not None:
        update_parts.append("#title = :title")
        expression_values[":title"] = title
        expression_names["#title"] = "title"

    if content is not None:
        update_parts.append("#content = :content")
        expression_values[":content"] = content
        expression_names["#content"] = "content"

    update_parts.append("updatedAt = :updatedAt")

    kwargs = {
        "Key": {"userId": user_id, "noteId": note_id},
        "UpdateExpression": "SET " + ", ".join(update_parts),
        "ExpressionAttributeValues": expression_values,
        "ReturnValues": "ALL_NEW",
    }
    if expression_names:
        kwargs["ExpressionAttributeNames"] = expression_names

    response = _table.update_item(**kwargs)
    return response.get("Attributes")


def delete_note(user_id, note_id):
    if get_note(user_id, note_id) is None:
        return False
    _table.delete_item(Key={"userId": user_id, "noteId": note_id})
    return True