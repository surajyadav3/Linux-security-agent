import json
import os
import boto3
from boto3.dynamodb.conditions import Key

dynamodb = boto3.resource("dynamodb")
TABLE = os.environ.get("TABLE_NAME", "linux-agent-reports")


def lambda_handler(event, context):
    raw = event.get("rawPath") or event.get("path", "/")
    # Strip stage prefix (e.g. /prod/hosts -> /hosts)
    path = "/" + raw.lstrip("/").split("/", 1)[-1] if raw.count("/") > 1 else raw
    method = event.get("requestContext", {}).get("http", {}).get("method", "GET")
    params = event.get("pathParameters") or {}

    if method == "OPTIONS":
        return _resp(200, {})

    table = dynamodb.Table(TABLE)

    # GET /hosts — list all known agents (latest report per host)
    if path == "/hosts":
        result = table.scan(
            ProjectionExpression="agent_id, #ts, host, package_count, cis_pass, cis_total",
            ExpressionAttributeNames={"#ts": "timestamp"},
        )
        # Deduplicate: keep latest report per agent
        latest = {}
        for item in result.get("Items", []):
            aid = item["agent_id"]
            if aid not in latest or item["timestamp"] > latest[aid]["timestamp"]:
                latest[aid] = item
        return _resp(200, list(latest.values()))

    # GET /apps/{agent_id} — installed packages for a host
    if path.startswith("/apps/"):
        agent_id = params.get("agent_id") or path.split("/apps/", 1)[1]
        result = table.query(
            KeyConditionExpression=Key("agent_id").eq(agent_id),
            ScanIndexForward=False,
            Limit=1,
            ProjectionExpression="agent_id, #ts, packages",
            ExpressionAttributeNames={"#ts": "timestamp"},
        )
        items = result.get("Items", [])
        if not items:
            return _resp(404, {"error": "Agent not found"})
        return _resp(200, items[0])

    # GET /cis-results/{agent_id} — CIS check results for a host
    if path.startswith("/cis-results/"):
        agent_id = params.get("agent_id") or path.split("/cis-results/", 1)[1]
        result = table.query(
            KeyConditionExpression=Key("agent_id").eq(agent_id),
            ScanIndexForward=False,
            Limit=1,
            ProjectionExpression="agent_id, #ts, cis_checks, host",
            ExpressionAttributeNames={"#ts": "timestamp"},
        )
        items = result.get("Items", [])
        if not items:
            return _resp(404, {"error": "Agent not found"})
        return _resp(200, items[0])

    return _resp(404, {"error": "Unknown path: " + path})


def _resp(status, body):
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type",
        },
        "body": json.dumps(body, default=str),
    }
