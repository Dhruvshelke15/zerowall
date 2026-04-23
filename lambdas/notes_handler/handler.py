# Notes CRUD Lambda Handler

import json
import os
import uuid
from datetime import datetime, timezone

import boto3
from boto3.dynamodb.conditions import Key

dynamodb = boto3.resource("dynamodb", region_name=os.environ.get("AWS_REGION", "us-east-1"))
notes_table = dynamodb.Table("zerowall-notes")



def lambda_handler(event, context):
    """Routes incoming API Gateway requests to the correct CRUD handler."""
    path = event.get("path", "")
    method = event.get("httpMethod", "")
    path_params = event.get("pathParameters") or {}

    authorizer = event.get("requestContext", {}).get("authorizer", {})
    user_id = authorizer.get("userId")
    role = authorizer.get("role", "user")

    if not user_id:
        return response(401, {"error": "UNAUTHORIZED", "message": "Missing user context from authorizer."})

    try:
        body = json.loads(event.get("body", "{}") or "{}")
    except json.JSONDecodeError:
        return response(400, {"error": "INVALID_JSON", "message": "Request body must be valid JSON."})

    note_id = path_params.get("noteId")

    if path == "/notes" and method == "GET":
        return handle_list_notes(user_id)
    elif path == "/notes" and method == "POST":
        return handle_create_note(user_id, body)
    elif note_id and method == "GET":
        return handle_get_note(user_id, note_id)
    elif note_id and method == "PUT":
        return handle_update_note(user_id, note_id, body)
    elif note_id and method == "DELETE":
        return handle_delete_note(user_id, note_id, role)
    else:
        return response(404, {"error": "NOT_FOUND", "message": "Route not found."})



def handle_list_notes(user_id):
    try:
        result = notes_table.query(
            KeyConditionExpression=Key("userId").eq(user_id)
        )
        notes = result.get("Items", [])
        return response(200, {
            "status": "success",
            "data": {
                "notes": notes,
                "count": len(notes)
            }
        })
    except Exception as e:
        return response(500, {"error": "LIST_FAILED", "message": str(e)})


def handle_create_note(user_id, body):
    title = body.get("title", "").strip()
    content = body.get("content", "").strip()

    if not title:
        return response(400, {"error": "MISSING_FIELDS", "message": "title is required."})

    note_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    item = {
        "userId": user_id,
        "noteId": note_id,
        "title": title,
        "content": content,
        "createdAt": now,
        "updatedAt": now,
    }

    try:
        notes_table.put_item(Item=item)
        return response(201, {"status": "success", "data": item})
    except Exception as e:
        return response(500, {"error": "CREATE_FAILED", "message": str(e)})


def handle_get_note(user_id, note_id):
    try:
        result = notes_table.get_item(
            Key={"userId": user_id, "noteId": note_id}
        )
        note = result.get("Item")
        if not note:
            return response(404, {"error": "NOT_FOUND", "message": "Note not found."})
        return response(200, {"status": "success", "data": note})
    except Exception as e:
        return response(500, {"error": "GET_FAILED", "message": str(e)})



def handle_update_note(user_id, note_id, body):
    title = body.get("title", "").strip()
    content = body.get("content")  

    if not title and content is None:
        return response(400, {"error": "MISSING_FIELDS", "message": "At least one of title or content is required."})

    try:
        result = notes_table.get_item(
            Key={"userId": user_id, "noteId": note_id}
        )
        if not result.get("Item"):
            return response(404, {"error": "NOT_FOUND", "message": "Note not found."})
    except Exception as e:
        return response(500, {"error": "UPDATE_FAILED", "message": str(e)})

    now = datetime.now(timezone.utc).isoformat()

    update_parts = ["updatedAt = :updatedAt"]
    expr_values = {":updatedAt": now}

    if title:
        update_parts.append("title = :title")
        expr_values[":title"] = title
    if content is not None:
        update_parts.append("content = :content")
        expr_values[":content"] = content

    update_expression = "SET " + ", ".join(update_parts)

    try:
        result = notes_table.update_item(
            Key={"userId": user_id, "noteId": note_id},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expr_values,
            ReturnValues="ALL_NEW"
        )
        return response(200, {"status": "success", "data": result.get("Attributes", {})})
    except Exception as e:
        return response(500, {"error": "UPDATE_FAILED", "message": str(e)})



def handle_delete_note(user_id, note_id, role):
    if role != "admin":
        return response(403, {"error": "FORBIDDEN", "message": "Only admins can delete notes."})

    try:
        result = notes_table.get_item(
            Key={"userId": user_id, "noteId": note_id}
        )
        if not result.get("Item"):
            return response(404, {"error": "NOT_FOUND", "message": "Note not found."})
    except Exception as e:
        return response(500, {"error": "DELETE_FAILED", "message": str(e)})

    try:
        notes_table.delete_item(
            Key={"userId": user_id, "noteId": note_id}
        )
        return response(200, {"status": "success", "message": f"Note {note_id} deleted."})
    except Exception as e:
        return response(500, {"error": "DELETE_FAILED", "message": str(e)})


def response(status_code, body):
    """Build API Gateway compatible response."""
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
        },
        "body": json.dumps(body, default=str)
    }