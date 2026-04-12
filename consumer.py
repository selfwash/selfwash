"""
Poll Nayax transaction messages from Amazon SQS and process them.

Uses the same DATABASE_URL as api.py (PostgreSQL on Railway — reference one Postgres plugin on
both services). Locally, omit DATABASE_URL to use SQLite ./transactions.db.

Credentials: default boto3 chain (env vars, ~/.aws/credentials, or IAM role).
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from typing import Any

import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

load_dotenv()

from db import init_db, save_transaction_payload

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)
log = logging.getLogger(__name__)

WAIT_SECONDS = 20
MAX_MESSAGES = 10
VISIBILITY_TIMEOUT = 60


def process_transaction(payload: dict[str, Any], sqs_message_id: str | None) -> None:
    """
    Called for each successfully parsed JSON body.
    Raise on failure so the message is not deleted and can be retried.
    """
    save_transaction_payload(payload, sqs_message_id=sqs_message_id)
    tid = payload.get("TransactionId") or payload.get("Data", {}).get("Transaction ID")
    log.info("Transaction persisted: %s", tid)


def _parse_sqs_body(body: str) -> dict[str, Any]:
    """Parse JSON; unwrap SNS->SQS envelope if present."""
    data: Any = json.loads(body)
    if not isinstance(data, dict):
        raise ValueError("Message body must be a JSON object")
    if data.get("Type") == "Notification" and "Message" in data:
        inner = data["Message"]
        if isinstance(inner, str):
            data = json.loads(inner)
        else:
            data = inner
    if not isinstance(data, dict):
        raise ValueError("Inner message must be a JSON object")
    return data


def handle_message_body(body: str, sqs_message_id: str | None) -> None:
    data = _parse_sqs_body(body)
    process_transaction(data, sqs_message_id)


def run_forever(queue_url: str, region: str) -> None:
    client = boto3.client("sqs", region_name=region)
    log.info("Polling %s in %s", queue_url, region)

    while True:
        try:
            resp = client.receive_message(
                QueueUrl=queue_url,
                MaxNumberOfMessages=MAX_MESSAGES,
                WaitTimeSeconds=WAIT_SECONDS,
                VisibilityTimeout=VISIBILITY_TIMEOUT,
                AttributeNames=["ApproximateReceiveCount"],
            )
        except ClientError as e:
            log.error("receive_message failed: %s", e)
            time.sleep(5)
            continue

        messages = resp.get("Messages") or []
        if not messages:
            continue

        for msg in messages:
            receipt = msg["ReceiptHandle"]
            mid = msg.get("MessageId", "?")
            body = msg.get("Body", "")

            try:
                handle_message_body(body, mid if mid != "?" else None)
            except (json.JSONDecodeError, ValueError) as e:
                log.exception("Bad message %s, deleting to unblock queue: %s", mid, e)
                try:
                    client.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt)
                except ClientError as del_err:
                    log.error("delete_message failed for bad message %s: %s", mid, del_err)
                continue
            except Exception:
                log.exception("Handler failed for message %s; leaving in queue for retry", mid)
                continue

            try:
                client.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt)
                log.info("Deleted message %s from queue", mid)
            except ClientError as e:
                log.error("delete_message failed for %s: %s", mid, e)


def main() -> int:
    queue_url = os.environ.get("SQS_QUEUE_URL", "").strip()
    region = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "")).strip()

    if not queue_url:
        log.error("Set SQS_QUEUE_URL (see .env.example)")
        return 1
    if not region:
        log.error("Set AWS_REGION (e.g. eu-north-1)")
        return 1

    init_db()

    try:
        run_forever(queue_url, region)
    except KeyboardInterrupt:
        log.info("Stopped")
        return 0


if __name__ == "__main__":
    sys.exit(main())
