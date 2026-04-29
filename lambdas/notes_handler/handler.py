# Notes CRUD Lambda Handler

import json
import os
import time
import uuid
from datetime import datetime, timezone

import boto3
from boto3.dynamodb.conditions import Key

import rate_limiter
import audit_logger

APP_REGION = os.environ.get("APP_REGION", "us-east-2")
RATE_LIMIT_PER_MINUTE = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "100"))

dynamodb = boto3.resource("dynamodb", region_name=APP_REGION)
notes_table = dynamodb.Table("zerowall-notes")  # type: ignore

# Title and content length limits
MAX_TITLE_LENGTH = 200
MAX_CONTENT_LENGTH = 5000


def lambda_handler(event, context):
    """Routes incoming API Gateway requests to the correct CRUD handler."""
    start_ms = int(time.time() * 1000)

    path = event.get("path", "")
    method = event.get("httpMethod", "")
    path_params = event.get("pathParameters") or {}

    request_context = event.get("requestContext", {}) or {}
    authorizer = request_context.get("authorizer", {}) or {}
    user_id = authorizer.get("userId")
    role = authorizer.get("role", "user")

    identity = request_context.get("identity") or {}
    source_ip = identity.get("sourceIp", "unknown")
    user_agent = identity.get("userAgent", "unknown")

    if not user_id:
        return response(401, {"status": "error", "error": "UNAUTHORIZED", "message": "Missing user context from authorizer."})

    # Rate limit check before any business logic.
    try:
        allowed, _count, retry_after = rate_limiter.check_and_increment(user_id, RATE_LIMIT_PER_MINUTE)
    except Exception as e:
        print(f"Rate limiter error: {e}")
        latency = int(time.time() * 1000) - start_ms
        audit_logger.log(user_id, method, path, source_ip, user_agent, "ERROR", 500, latency)
        return response(500, {"status": "error", "error": "RATE_LIMITER_ERROR", "message": "Rate limiter unavailable."})

    if not allowed:
        latency = int(time.time() * 1000) - start_ms
        audit_logger.log(user_id, method, path, source_ip, user_agent, "DENIED_RATE_LIMIT", 429, latency)
        return response(
            429,
            {"status": "error", "error": "RATE_LIMITED", "message": f"Too many requests. Try again in {retry_after} seconds.", "retryAfter": retry_after},
            extra_headers={"Retry-After": str(retry_after)},
        )

    try:
        body = json.loads(event.get("body", "{}") or "{}")
    except json.JSONDecodeError:
        latency = int(time.time() * 1000) - start_ms
        audit_logger.log(user_id, method, path, source_ip, user_agent, "ERROR", 400, latency)
        return response(400, {"status": "error", "error": "INVALID_JSON", "message": "Request body must be valid JSON."})

    note_id = path_params.get("noteId")

    if path == "/notes" and method == "GET":
        result = handle_list_notes(user_id)
    elif path == "/notes" and method == "POST":
        result = handle_create_note(user_id, body)
    elif note_id and method == "GET":
        result = handle_get_note(user_id, note_id)
    elif note_id and method == "PUT":
        result = handle_update_note(user_id, note_id, body)
    elif note_id and method == "DELETE":
        result = handle_delete_note(user_id, note_id, role)
    else:
        result = response(404, {"status": "error", "error": "NOT_FOUND", "message": "Route not found."})

    # Audit log every request that made it past rate limiting.
    status_code = result.get("statusCode", 500)
    audit_result = "ERROR" if status_code >= 500 else "ALLOWED"
    latency = int(time.time() * 1000) - start_ms
    audit_logger.log(user_id, method, path, source_ip, user_agent, audit_result, status_code, latency)

    return result


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
        return response(500, {"status": "error", "error": "LIST_FAILED", "message": str(e)})


def handle_create_note(user_id, body):
    title = body.get("title", "").strip()
    content = body.get("content", "").strip()

    if not title:
        return response(400, {"status": "error", "error": "MISSING_FIELDS", "message": "title is required."})

    if len(title) > MAX_TITLE_LENGTH:
        return response(400, {"status": "error", "error": "VALIDATION_ERROR", "message": f"Title must be under {MAX_TITLE_LENGTH} characters."})

    if len(content) > MAX_CONTENT_LENGTH:
        return response(400, {"status": "error", "error": "VALIDATION_ERROR", "message": f"Content must be under {MAX_CONTENT_LENGTH} characters."})

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
        return response(500, {"status": "error", "error": "CREATE_FAILED", "message": str(e)})


def handle_get_note(user_id, note_id):
    try:
        result = notes_table.get_item(
            Key={"userId": user_id, "noteId": note_id}
        )
        note = result.get("Item")
        if not note:
            return response(404, {"status": "error", "error": "NOT_FOUND", "message": "Note not found."})
        return response(200, {"status": "success", "data": note})
    except Exception as e:
        return response(500, {"status": "error", "error": "GET_FAILED", "message": str(e)})


def handle_update_note(user_id, note_id, body):
    title = body.get("title", "").strip()
    content = body.get("content")

    if not title and content is None:
        return response(400, {"status": "error", "error": "MISSING_FIELDS", "message": "At least one of title or content is required."})

    if title and len(title) > MAX_TITLE_LENGTH:
        return response(400, {"status": "error", "error": "VALIDATION_ERROR", "message": f"Title must be under {MAX_TITLE_LENGTH} characters."})

    if content is not None and len(content) > MAX_CONTENT_LENGTH:
        return response(400, {"status": "error", "error": "VALIDATION_ERROR", "message": f"Content must be under {MAX_CONTENT_LENGTH} characters."})

    try:
        result = notes_table.get_item(
            Key={"userId": user_id, "noteId": note_id}
        )
        if not result.get("Item"):
            return response(404, {"status": "error", "error": "NOT_FOUND", "message": "Note not found."})
    except Exception as e:
        return response(500, {"status": "error", "error": "UPDATE_FAILED", "message": str(e)})

    now = datetime.now(timezone.utc).isoformat()

    update_parts = ["updatedAt = :updatedAt"]
    expr_values = {":updatedAt": now}
    expr_names = {}

    if title:
        update_parts.append("#title = :title")
        expr_values[":title"] = title
        expr_names["#title"] = "title"
    if content is not None:
        update_parts.append("#content = :content")
        expr_values[":content"] = content
        expr_names["#content"] = "content"

    update_expression = "SET " + ", ".join(update_parts)

    try:
        kwargs = {
            "Key": {"userId": user_id, "noteId": note_id},
            "UpdateExpression": update_expression,
            "ExpressionAttributeValues": expr_values,
            "ReturnValues": "ALL_NEW",
        }
        if expr_names:
            kwargs["ExpressionAttributeNames"] = expr_names
        result = notes_table.update_item(**kwargs)
        return response(200, {"status": "success", "data": result.get("Attributes", {})})
    except Exception as e:
        return response(500, {"status": "error", "error": "UPDATE_FAILED", "message": str(e)})


def handle_delete_note(user_id, note_id, role):
    # Defense in depth: Lambda Authorizer also blocks non-admins from DELETE,
    # but we enforce it here too as a safety net.
    if role != "admin":
        return response(403, {"status": "error", "error": "FORBIDDEN", "message": "Only admins can delete notes."})

    try:
        result = notes_table.get_item(
            Key={"userId": user_id, "noteId": note_id}
        )
        if not result.get("Item"):
            return response(404, {"status": "error", "error": "NOT_FOUND", "message": "Note not found."})
    except Exception as e:
        return response(500, {"status": "error", "error": "DELETE_FAILED", "message": str(e)})

    try:
        notes_table.delete_item(
            Key={"userId": user_id, "noteId": note_id}
        )
        return response(200, {"status": "success", "message": f"Note {note_id} deleted."})
    except Exception as e:
        return response(500, {"status": "error", "error": "DELETE_FAILED", "message": str(e)})


def response(status_code, body, extra_headers=None):
    """Build API Gateway compatible response."""
    headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*"
    }
    if extra_headers:
        headers.update(extra_headers)
    return {
        "statusCode": status_code,
        "headers": headers,
        "body": json.dumps(body, default=str)
    }