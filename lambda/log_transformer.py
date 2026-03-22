"""
Sentinel-AWS Cyber-Optimizer — Lambda Log Transformer
=====================================================
Kinesis Firehose transformation function that performs:
1. PII Redaction   — Masks SSNs, credit cards, emails, IPv4/IPv6 addresses
2. Noise Filtering — Drops HTTP 200/2XX success logs, retains errors & security events
3. Enrichment      — Adds processing metadata for observability

Architecture: EKS → Kinesis Firehose → [THIS LAMBDA] → S3 → SQS → SIEM
"""

import base64
import json
import re
import os
import logging
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
PROJECT_NAME = os.environ.get("PROJECT_NAME", "sentinel-cyber-optimizer")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "dev")

logger = logging.getLogger()
logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

# ---------------------------------------------------------------------------
# PII Redaction Patterns
# ---------------------------------------------------------------------------
PII_PATTERNS = {
    "ssn": {
        "pattern": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        "replacement": "***-**-****",
        "description": "Social Security Number"
    },
    "credit_card": {
        "pattern": re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
        "replacement": "****-****-****-****",
        "description": "Credit Card Number"
    },
    "email": {
        "pattern": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        "replacement": "***@***.***",
        "description": "Email Address"
    },
    "ipv4": {
        "pattern": re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ),
        "replacement": "xxx.xxx.xxx.xxx",
        "description": "IPv4 Address"
    },
    "phone": {
        "pattern": re.compile(r'\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
        "replacement": "***-***-****",
        "description": "Phone Number"
    },
    "aws_access_key": {
        "pattern": re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
        "replacement": "****REDACTED_KEY****",
        "description": "AWS Access Key ID"
    },
    "aws_secret_key": {
        "pattern": re.compile(r'\b[A-Za-z0-9/+=]{40}\b'),
        "replacement": "****REDACTED_SECRET****",
        "description": "Potential AWS Secret Key"
    }
}

# ---------------------------------------------------------------------------
# Security Event Keywords (always retain these logs)
# ---------------------------------------------------------------------------
SECURITY_KEYWORDS = [
    "unauthorized", "forbidden", "denied",
    "authentication", "auth_failure", "login_failed",
    "privilege", "escalation", "sudo",
    "injection", "xss", "csrf", "sqli",
    "brute_force", "rate_limit", "throttle",
    "malware", "suspicious", "anomaly",
    "certificate", "tls", "ssl_error",
    "access_denied", "permission_denied",
    "security_group", "nacl", "firewall",
    "guardduty", "inspector", "securityhub",
    "iam", "assume_role", "sts",
    "kms", "decrypt", "encrypt",
    "critical", "emergency", "alert"
]

# HTTP status codes to RETAIN (drop everything else)
RETAIN_STATUS_CODES = set(range(400, 600))  # 4XX and 5XX errors

# HTTP 2XX codes to DROP (noise)
DROP_STATUS_CODES = set(range(200, 300))


def redact_pii(text: str) -> tuple[str, dict]:
    """
    Redact PII from text using regex patterns.

    Returns:
        tuple: (redacted_text, redaction_summary)
    """
    redaction_summary = {}

    for pii_type, config in PII_PATTERNS.items():
        matches = config["pattern"].findall(text)
        if matches:
            redaction_summary[pii_type] = len(matches)
            text = config["pattern"].sub(config["replacement"], text)

    return text, redaction_summary


def is_security_event(log_data: dict | str) -> bool:
    """
    Check if log contains security-relevant content.

    Args:
        log_data: Parsed log dictionary or raw string

    Returns:
        bool: True if the log is security-relevant
    """
    if isinstance(log_data, dict):
        log_text = json.dumps(log_data).lower()
    else:
        log_text = str(log_data).lower()

    return any(keyword in log_text for keyword in SECURITY_KEYWORDS)


def extract_status_code(log_data: dict | str) -> int | None:
    """
    Extract HTTP status code from log data.

    Args:
        log_data: Parsed log dictionary or raw string

    Returns:
        int or None: HTTP status code if found
    """
    if isinstance(log_data, dict):
        # Check common status code field names
        for field in ["status", "status_code", "http_status", "statusCode",
                      "response_code", "http_response_code"]:
            code = log_data.get(field)
            if code is not None:
                try:
                    return int(code)
                except (ValueError, TypeError):
                    continue

        # Check nested response objects
        response = log_data.get("response", {})
        if isinstance(response, dict):
            code = response.get("status") or response.get("status_code")
            if code is not None:
                try:
                    return int(code)
                except (ValueError, TypeError):
                    pass

    # Try regex extraction from raw text
    text = json.dumps(log_data) if isinstance(log_data, dict) else str(log_data)
    match = re.search(r'"(?:status|status_code|http_status)":\s*(\d{3})', text)
    if match:
        return int(match.group(1))

    # Try common log format: "GET /path HTTP/1.1" 200 1234
    match = re.search(r'"\s+(\d{3})\s+\d+', text)
    if match:
        return int(match.group(1))

    return None


def should_retain_log(log_data: dict | str) -> tuple[bool, str]:
    """
    Determine if a log record should be retained or dropped.

    Retention rules:
    1. Always retain security events
    2. Retain 4XX/5XX HTTP errors
    3. Drop 2XX success responses (noise)
    4. Retain logs without clear status codes (unknown = keep)

    Returns:
        tuple: (should_retain, reason)
    """
    # Rule 1: Always retain security events
    if is_security_event(log_data):
        return True, "security_event"

    # Rule 2/3: Filter by HTTP status code
    status_code = extract_status_code(log_data)
    if status_code is not None:
        if status_code in DROP_STATUS_CODES:
            return False, f"noise_http_{status_code}"
        if status_code in RETAIN_STATUS_CODES:
            return True, f"error_http_{status_code}"

    # Rule 4: Unknown logs are retained (conservative approach)
    return True, "unknown_retained"


def process_record(record_data: str) -> tuple[str | None, dict]:
    """
    Process a single log record: redact PII and apply noise filtering.

    Args:
        record_data: Raw log data string

    Returns:
        tuple: (processed_data or None if dropped, processing_metadata)
    """
    metadata = {
        "processed_at": datetime.now(timezone.utc).isoformat(),
        "processor": f"{PROJECT_NAME}-lambda",
        "environment": ENVIRONMENT,
        "pii_redacted": {},
        "action": "unknown"
    }

    # Try to parse as JSON
    try:
        log_data = json.loads(record_data)
        is_json = True
    except (json.JSONDecodeError, TypeError):
        log_data = record_data
        is_json = False

    # Step 1: Noise filtering
    should_keep, reason = should_retain_log(log_data)
    metadata["filter_reason"] = reason

    if not should_keep:
        metadata["action"] = "dropped"
        logger.debug(f"Dropped log: reason={reason}")
        return None, metadata

    # Step 2: PII redaction
    if is_json:
        raw_text = json.dumps(log_data)
        redacted_text, redaction_summary = redact_pii(raw_text)
        metadata["pii_redacted"] = redaction_summary

        try:
            processed_data = json.loads(redacted_text)
        except json.JSONDecodeError:
            processed_data = redacted_text
    else:
        redacted_text, redaction_summary = redact_pii(str(log_data))
        processed_data = redacted_text
        metadata["pii_redacted"] = redaction_summary

    # Step 3: Enrich with processing metadata
    if isinstance(processed_data, dict):
        processed_data["_sentinel_metadata"] = {
            "processed_at": metadata["processed_at"],
            "filter_reason": reason,
            "pii_fields_redacted": list(redaction_summary.keys()),
            "environment": ENVIRONMENT
        }

    metadata["action"] = "retained"
    result = json.dumps(processed_data) if isinstance(processed_data, dict) else str(processed_data)

    return result, metadata


def lambda_handler(event, context):
    """
    AWS Lambda handler for Kinesis Firehose data transformation.

    Processes each record in the Firehose batch:
    - Decodes base64 data
    - Applies PII redaction
    - Filters noise (HTTP 200)
    - Returns transformed records to Firehose

    Firehose result codes:
    - Ok:              Record processed successfully
    - Dropped:         Record intentionally dropped (noise)
    - ProcessingFailed: Error during processing (sent to error bucket)
    """
    logger.info(f"Processing {len(event.get('records', []))} records")

    output_records = []
    stats = {
        "total": 0,
        "retained": 0,
        "dropped": 0,
        "failed": 0,
        "pii_redactions": {}
    }

    for record in event.get("records", []):
        stats["total"] += 1
        record_id = record["recordId"]

        try:
            # Decode the base64-encoded Firehose record
            raw_data = base64.b64decode(record["data"]).decode("utf-8")

            # Process the record
            processed_data, metadata = process_record(raw_data)

            if processed_data is None:
                # Record dropped (noise filtering)
                output_records.append({
                    "recordId": record_id,
                    "result": "Dropped",
                    "data": record["data"]  # Original data for Firehose compatibility
                })
                stats["dropped"] += 1
            else:
                # Record retained — encode and return
                encoded_data = base64.b64encode(
                    (processed_data + "\n").encode("utf-8")
                ).decode("utf-8")

                output_records.append({
                    "recordId": record_id,
                    "result": "Ok",
                    "data": encoded_data
                })
                stats["retained"] += 1

                # Aggregate PII stats
                for pii_type, count in metadata.get("pii_redacted", {}).items():
                    stats["pii_redactions"][pii_type] = (
                        stats["pii_redactions"].get(pii_type, 0) + count
                    )

        except Exception as e:
            logger.error(f"Error processing record {record_id}: {str(e)}")
            output_records.append({
                "recordId": record_id,
                "result": "ProcessingFailed",
                "data": record["data"]
            })
            stats["failed"] += 1

    # Log processing summary
    logger.info(
        f"Processing complete: "
        f"total={stats['total']}, "
        f"retained={stats['retained']}, "
        f"dropped={stats['dropped']}, "
        f"failed={stats['failed']}, "
        f"pii_redactions={json.dumps(stats['pii_redactions'])}"
    )

    # Calculate cost savings metric
    if stats["total"] > 0:
        reduction_pct = (stats["dropped"] / stats["total"]) * 100
        logger.info(f"Log volume reduction: {reduction_pct:.1f}%")

    return {"records": output_records}
