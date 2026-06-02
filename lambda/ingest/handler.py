import json
import os
import boto3
from datetime import datetime

dynamodb = boto3.resource("dynamodb")
TABLE = os.environ.get("TABLE_NAME", "linux-agent-reports")

def lambda_handler(event, context):
    try:
        body = json.loads(event.get("body", "{}"))
    except (json.JSONDecodeError, TypeError):
        return _resp(400, {"error": "Invalid JSON body"})

    agent_id = body.get("agent_id")
    timestamp = body.get("timestamp", datetime.utcnow().isoformat() + "Z")

    if not agent_id:
        return _resp(400, {"error": "agent_id is required"})

    table = dynamodb.Table(TABLE)

    # Store packages and CIS checks as JSON strings (DynamoDB size limit workaround)
    item = {
        "agent_id": agent_id,
        "timestamp": timestamp,
        "host": body.get("host", {}),
        "packages": body.get("packages", []),
        "cis_checks": body.get("cis_checks", []),
        "package_count": len(body.get("packages", [])),
        "cis_pass": sum(1 for c in body.get("cis_checks", []) if c.get("status") == "PASS"),
        "cis_total": len(body.get("cis_checks", [])),
        "ttl": int(datetime.utcnow().timestamp()) + (90 * 86400),  # 90-day TTL
    }

    table.put_item(Item=item)

    return _resp(200, {
        "message": "Report ingested",
        "agent_id": agent_id,
        "timestamp": timestamp,
    })


def _resp(status, body):
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body),
    }
