"""Slack request signature verification (https://api.slack.com/authentication/verifying-requests-from-slack)."""

import hashlib
import hmac
import time

from flask import current_app, g, request

__author__ = "lundberg"

SLACK_TIMESTAMP_HEADER = "X-Slack-Request-Timestamp"
SLACK_SIGNATURE_HEADER = "X-Slack-Signature"
SLACK_MAX_AGE_SECONDS = 300


SLACK_MAX_BODY_BYTES = 65536
FAILURE_REASON_KEY = "exempt_failure_reason"


def slack_signature_failure_reason() -> str | None:
    """Return a short reason code if the request is not validly signed by Slack, else None."""
    secret = current_app.config.get("SLACK_SIGNING_SECRET")
    if not secret:
        return "no_secret"
    timestamp = request.headers.get(SLACK_TIMESTAMP_HEADER)
    signature = request.headers.get(SLACK_SIGNATURE_HEADER)
    if not timestamp or not signature:
        return "missing_headers"
    try:
        ts = int(timestamp)
    except ValueError:
        return "bad_timestamp"
    # Integer arithmetic: a huge ts must not overflow a float conversion
    if abs(int(time.time()) - ts) > SLACK_MAX_AGE_SECONDS:
        return "stale"
    length = request.content_length
    if length is None or length < 0 or length > SLACK_MAX_BODY_BYTES:
        return "body_too_large"
    body = request.get_data(cache=True)
    base = f"v0:{ts}:".encode() + body
    expected = "v0=" + hmac.new(str(secret).encode(), base, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected.encode(), signature.encode()):
        return "bad_signature"
    return None


def verify_slack_signature() -> bool:
    """True only if a signing secret is configured and the request carries a valid, fresh Slack signature."""
    reason = slack_signature_failure_reason()
    setattr(g, FAILURE_REASON_KEY, reason)
    return reason is None
