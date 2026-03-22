"""
Tests for Lambda Log Transformer
=================================
Validates PII redaction, noise filtering, and Firehose record handling.
"""

import base64
import json
import pytest
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from log_transformer import (
    redact_pii,
    is_security_event,
    extract_status_code,
    should_retain_log,
    process_record,
    lambda_handler,
)


# =============================================================================
# PII Redaction Tests
# =============================================================================
class TestPIIRedaction:
    """Test PII redaction across all supported patterns."""

    def test_redact_ssn(self):
        text = "User SSN is 123-45-6789"
        result, summary = redact_pii(text)
        assert "123-45-6789" not in result
        assert "***-**-****" in result
        assert summary["ssn"] == 1

    def test_redact_credit_card(self):
        text = "Card number: 4532-1234-5678-9012"
        result, summary = redact_pii(text)
        assert "4532-1234-5678-9012" not in result
        assert summary["credit_card"] == 1

    def test_redact_email(self):
        text = "Contact user@example.com for details"
        result, summary = redact_pii(text)
        assert "user@example.com" not in result
        assert "***@***.***" in result
        assert summary["email"] == 1

    def test_redact_ipv4(self):
        text = "Request from 192.168.1.100"
        result, summary = redact_pii(text)
        assert "192.168.1.100" not in result
        assert "xxx.xxx.xxx.xxx" in result
        assert summary["ipv4"] == 1

    def test_redact_aws_access_key(self):
        text = "Key: AKIAIOSFODNN7EXAMPLE"
        result, summary = redact_pii(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert summary["aws_access_key"] == 1

    def test_redact_multiple_pii(self):
        text = "User 123-45-6789 from 10.0.0.1 emailed admin@corp.com"
        result, summary = redact_pii(text)
        assert "123-45-6789" not in result
        assert "10.0.0.1" not in result
        assert "admin@corp.com" not in result
        assert len(summary) >= 3

    def test_no_pii_unchanged(self):
        text = "Normal log message with no PII"
        result, summary = redact_pii(text)
        assert result == text
        assert len(summary) == 0


# =============================================================================
# Security Event Detection Tests
# =============================================================================
class TestSecurityEventDetection:
    """Test identification of security-relevant log entries."""

    def test_auth_failure_detected(self):
        log = {"message": "authentication failed for user admin", "level": "error"}
        assert is_security_event(log) is True

    def test_access_denied_detected(self):
        log = {"message": "Access denied to resource", "status": 403}
        assert is_security_event(log) is True

    def test_privilege_escalation_detected(self):
        log = {"event": "privilege escalation attempt", "source": "guardduty"}
        assert is_security_event(log) is True

    def test_sql_injection_detected(self):
        log = {"message": "Potential SQL injection detected in parameter"}
        assert is_security_event(log) is True

    def test_normal_log_not_security(self):
        log = {"message": "User viewed dashboard", "status": 200}
        assert is_security_event(log) is False

    def test_string_input_security(self):
        log_str = "CRITICAL: unauthorized access attempt from external IP"
        assert is_security_event(log_str) is True

    def test_iam_event_detected(self):
        log = {"eventName": "AssumeRole", "service": "iam", "sourceIP": "1.2.3.4"}
        assert is_security_event(log) is True


# =============================================================================
# HTTP Status Code Extraction Tests
# =============================================================================
class TestStatusCodeExtraction:
    """Test HTTP status code extraction from various log formats."""

    def test_status_field(self):
        assert extract_status_code({"status": 200}) == 200

    def test_status_code_field(self):
        assert extract_status_code({"status_code": 404}) == 404

    def test_http_status_field(self):
        assert extract_status_code({"http_status": 500}) == 500

    def test_nested_response_status(self):
        log = {"response": {"status": 502}}
        assert extract_status_code(log) == 502

    def test_string_status_code(self):
        assert extract_status_code({"status": "201"}) == 201

    def test_no_status_code(self):
        assert extract_status_code({"message": "Hello"}) is None


# =============================================================================
# Noise Filtering Tests
# =============================================================================
class TestNoiseFiltering:
    """Test log retention/drop decisions."""

    def test_drop_http_200(self):
        log = {"path": "/api/health", "status": 200}
        retain, reason = should_retain_log(log)
        assert retain is False
        assert "noise" in reason

    def test_drop_http_204(self):
        log = {"path": "/api/data", "status": 204}
        retain, reason = should_retain_log(log)
        assert retain is False

    def test_retain_http_401(self):
        log = {"path": "/api/admin", "status": 401}
        retain, reason = should_retain_log(log)
        assert retain is True
        assert "error" in reason

    def test_retain_http_500(self):
        log = {"path": "/api/process", "status": 500}
        retain, reason = should_retain_log(log)
        assert retain is True

    def test_retain_security_event_even_200(self):
        """Security events are retained even if status is 200."""
        log = {"status": 200, "message": "unauthorized access attempt"}
        retain, reason = should_retain_log(log)
        assert retain is True
        assert reason == "security_event"

    def test_retain_unknown_log(self):
        """Logs without status codes are retained (conservative approach)."""
        log = {"message": "Application started"}
        retain, reason = should_retain_log(log)
        assert retain is True


# =============================================================================
# Record Processing Tests
# =============================================================================
class TestRecordProcessing:
    """Test end-to-end record processing."""

    def test_json_record_retained_with_redaction(self):
        record = json.dumps({
            "status": 500,
            "message": "Error for user 123-45-6789",
            "source_ip": "10.0.0.1"
        })
        result, metadata = process_record(record)
        assert result is not None
        assert "123-45-6789" not in result
        assert metadata["action"] == "retained"

    def test_json_record_dropped(self):
        record = json.dumps({
            "status": 200,
            "message": "Success",
            "path": "/health"
        })
        result, metadata = process_record(record)
        assert result is None
        assert metadata["action"] == "dropped"

    def test_plain_text_record(self):
        record = "ERROR: Connection refused from 192.168.1.1"
        result, metadata = process_record(record)
        assert result is not None
        assert "192.168.1.1" not in result

    def test_metadata_enrichment(self):
        record = json.dumps({"status": 404, "path": "/missing"})
        result, metadata = process_record(record)
        parsed = json.loads(result)
        assert "_sentinel_metadata" in parsed
        assert "processed_at" in parsed["_sentinel_metadata"]


# =============================================================================
# Lambda Handler Tests (Firehose Integration)
# =============================================================================
class TestLambdaHandler:
    """Test the full Lambda handler with Firehose-formatted events."""

    def _make_firehose_event(self, records: list[dict]) -> dict:
        """Create a Firehose-style event from a list of log dicts."""
        firehose_records = []
        for i, record in enumerate(records):
            data = base64.b64encode(
                json.dumps(record).encode("utf-8")
            ).decode("utf-8")
            firehose_records.append({
                "recordId": f"record-{i}",
                "data": data
            })
        return {"records": firehose_records}

    def test_handler_processes_batch(self):
        event = self._make_firehose_event([
            {"status": 200, "path": "/health"},       # Should be DROPPED
            {"status": 500, "error": "DB timeout"},    # Should be RETAINED
            {"status": 401, "message": "Unauthorized"} # Should be RETAINED
        ])

        result = lambda_handler(event, None)
        assert len(result["records"]) == 3

        results = {r["recordId"]: r["result"] for r in result["records"]}
        assert results["record-0"] == "Dropped"
        assert results["record-1"] == "Ok"
        assert results["record-2"] == "Ok"

    def test_handler_redacts_pii_in_output(self):
        event = self._make_firehose_event([
            {"status": 500, "user_ssn": "123-45-6789", "ip": "10.0.0.1"}
        ])

        result = lambda_handler(event, None)
        output_data = base64.b64decode(result["records"][0]["data"]).decode("utf-8")
        assert "123-45-6789" not in output_data
        assert "10.0.0.1" not in output_data

    def test_handler_empty_event(self):
        result = lambda_handler({"records": []}, None)
        assert result["records"] == []

    def test_handler_malformed_record(self):
        """Malformed records should return ProcessingFailed."""
        event = {
            "records": [{
                "recordId": "bad-record",
                "data": "not-valid-base64!!!"
            }]
        }
        result = lambda_handler(event, None)
        assert result["records"][0]["result"] == "ProcessingFailed"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
