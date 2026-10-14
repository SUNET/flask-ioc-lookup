"""CSRF protection: Origin/Referer verification plus a per-session synchroniser token."""

import hmac
import secrets
from collections.abc import Callable, Iterable, Mapping
from urllib.parse import urlsplit

from flask import Flask, Response, current_app, g, jsonify, render_template, request, session
from flask.globals import request_ctx
from werkzeug.exceptions import BadRequest, Forbidden

__author__ = "lundberg"

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
CSRF_SESSION_KEY = "csrf_token"
CSRF_IDENTITY_KEY = "csrf_identity"
CSRF_FORM_FIELD = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"
API_TOKEN_HEADER = "API-TOKEN"
DEFAULT_PORTS = {"http": 80, "https": 443}


class CSRFError(BadRequest):
    description = "The security token is missing, invalid or expired."


class VerificationError(Forbidden):
    description = "Request verification failed."


class OriginError(Forbidden):
    description = "The request origin is not allowed. If this keeps happening, contact the administrator."


def _current_identity() -> str:
    """The REMOTE_USER the token is bound to (empty if absent); read directly, never aborts."""
    return str(request.environ.get("HTTP_REMOTE_USER") or "")


def generate_csrf_token() -> str:
    """Return the session's CSRF token for the current identity, creating a fresh one if needed."""
    token = session.get(CSRF_SESSION_KEY)
    identity = _current_identity()
    if not token or session.get(CSRF_IDENTITY_KEY) != identity:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
        session[CSRF_IDENTITY_KEY] = identity
    return str(token)


def _api_token_owner() -> str | None:
    """Return the owner of the API-TOKEN header's key, or None. Compares against every key in constant time."""
    token = request.headers.get(API_TOKEN_HEADER)
    if not token or not token.strip():
        return None
    api_keys = getattr(current_app, "api_keys", None) or {}
    token_bytes = token.encode()
    owner: str | None = None
    for key, key_owner in api_keys.items():
        if hmac.compare_digest(token_bytes, str(key).encode()):
            owner = str(key_owner)  # no early exit, so timing does not reveal which key matched
    return owner


def _is_api_token_request() -> bool:
    """True only if a JSON request carries an API-TOKEN header that is a known api key."""
    owner = _api_token_owner()
    if owner is None:
        return False
    if not request.is_json:
        current_app.logger.warning(
            f"API key rejected for CSRF exemption: non-JSON content type endpoint={request.endpoint} "
            f"method={request.method} Content-Type={_safe_log_value(request.content_type)}"
        )
        return False
    current_app.logger.info(
        f"CSRF exempt via API key: endpoint={request.endpoint} method={request.method} owner={_safe_log_value(owner)}"
    )
    return True


def _normalise_origin(value: str) -> str | None:
    """Normalise to lowercase scheme://host[:port] with default ports stripped."""
    try:
        parts = urlsplit(value.strip())
        scheme = (parts.scheme or "").lower()
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return None
    if not scheme or not host:
        return None
    if ":" in host:
        host = f"[{host}]"
    if port is not None and DEFAULT_PORTS.get(scheme) != port:
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


def _configured_origins(raw: object) -> set[str]:
    """Normalise TRUSTED_ORIGINS (a string or a list of strings), raising ValueError on a bad entry."""
    if not raw:
        return set()
    items = [raw] if isinstance(raw, str) else list(raw)  # type: ignore[call-overload]
    origins: set[str] = set()
    for item in items:
        normalised = _normalise_origin(str(item))
        if normalised is None:
            raise ValueError(f"Invalid TRUSTED_ORIGINS entry {item!r}, expected scheme://host[:port]")
        origins.add(normalised)
    return origins


def _safe_log_value(value: str | None) -> str:
    """Truncate to 200 chars and escape control characters for logging."""
    if value is None:
        return "None"
    return repr(value[:200])


def _allowed_origins() -> set[str]:
    allowed = _configured_origins(current_app.config.get("TRUSTED_ORIGINS"))
    if not allowed:
        own = _normalise_origin(f"{request.scheme}://{request.host}")
        if own:
            allowed.add(own)
    return allowed


def _log_origin_rejection(allowed: set[str], origin: str, normalised: str | None, header: str = "Origin") -> None:
    message = (
        f"{header} rejected: expected one of {sorted(allowed)}, got {_safe_log_value(origin)}; "
        "set TRUSTED_ORIGINS if behind a proxy that changes scheme/host"
    )
    if normalised is not None:
        got = urlsplit(normalised)
        for item in allowed:
            exp = urlsplit(item)
            if exp.scheme != got.scheme and exp.hostname == got.hostname and exp.port == got.port:
                message += "; scheme mismatch: check proxy sends X-Forwarded-Proto"
                break
    current_app.logger.warning(message)


def check_origin() -> None:
    """Raise OriginError unless Origin (or else Referer) is an allowed origin."""
    allowed = _allowed_origins()
    origin = request.headers.get("Origin")
    if origin is not None:
        normalised = _normalise_origin(origin) if origin.strip().lower() != "null" else None
        if normalised is None or normalised not in allowed:
            _log_origin_rejection(allowed, origin, normalised)
            raise OriginError()
        return
    referer = request.headers.get("Referer")
    if referer:
        normalised = _normalise_origin(referer)
        if normalised is not None and normalised in allowed:
            return
        _log_origin_rejection(allowed, referer, normalised, header="Referer")
    else:
        current_app.logger.warning(
            f"Origin rejected: no Origin or Referer header, expected one of {sorted(allowed)}; "
            "set TRUSTED_ORIGINS if behind a proxy that changes scheme/host"
        )
    raise OriginError()


def validate_csrf_token() -> None:
    """Raise CSRFError unless the submitted token matches the session token."""
    expected = session.get(CSRF_SESSION_KEY)
    submitted = request.form.get(CSRF_FORM_FIELD) or request.headers.get(CSRF_HEADER)
    if not expected or not submitted:
        raise CSRFError()
    if session.get(CSRF_IDENTITY_KEY) != _current_identity():
        current_app.logger.warning("CSRF token rejected: reason=identity_mismatch")
        raise CSRFError()
    if not hmac.compare_digest(str(expected).encode(), str(submitted).encode()):
        raise CSRFError()


ExemptVerifier = Callable[[], bool]


def csrf_protect(exempt_endpoints: Mapping[str, ExemptVerifier | None]) -> None:
    if request.method in SAFE_METHODS:
        return
    endpoint = request.endpoint or ""
    if endpoint in exempt_endpoints:
        verifier = exempt_endpoints[endpoint]
        # No verifier means unconditionally exempt; otherwise exempt only if the verifier succeeds (fail closed)
        if verifier is None or verifier():
            return
        # Fail closed: a verifier-backed endpoint is never reachable via session token, Origin or API key
        current_app.logger.warning(
            f"Exemption verification failed: endpoint={endpoint} reason={getattr(g, 'exempt_failure_reason', None)}"
        )
        raise VerificationError()
    if _is_api_token_request():
        return
    try:
        check_origin()
        validate_csrf_token()
    except (OriginError, CSRFError) as e:
        current_app.logger.warning(
            f"CSRF rejection ({e.code}): endpoint={request.endpoint} method={request.method} "
            f"Origin={_safe_log_value(request.headers.get('Origin'))} "
            f"Referer={_safe_log_value(request.headers.get('Referer'))}"
        )
        raise


def init_csrf(app: Flask, exempt_endpoints: Iterable[str] | Mapping[str, ExemptVerifier | None] = ()) -> None:
    """Exempt endpoints are either names (always exempt) or a mapping of name to verifier (exempt if it passes)."""
    exempt: dict[str, ExemptVerifier | None] = (
        dict(exempt_endpoints) if isinstance(exempt_endpoints, Mapping) else dict.fromkeys(exempt_endpoints)
    )
    _configured_origins(app.config.get("TRUSTED_ORIGINS"))  # fail at startup on invalid config

    @app.before_request
    def _csrf_protect() -> None:
        csrf_protect(exempt)

    @app.after_request
    def _no_store_session_responses(response: Response) -> Response:
        # Responses that set the session cookie or may embed the CSRF token must not be shared-cached
        # Read the context's session directly: touching the `session` proxy would itself mark it accessed
        raw_session = getattr(request_ctx, "_session", None)
        used = raw_session is None or raw_session.accessed or raw_session.modified  # fail closed if unknown
        if used or "Set-Cookie" in response.headers:
            response.headers["Cache-Control"] = "no-store"
            response.vary.add("Cookie")
        return response

    app.jinja_env.globals["csrf_token"] = generate_csrf_token

    def _handle(error: BadRequest | Forbidden) -> Response | tuple[Response, int] | tuple[str, int]:
        status = error.code or 400
        if (
            request.is_json
            or request.accept_mimetypes.best_match(["application/json", "text/html"]) == "application/json"
        ):
            return jsonify({"status": status, "message": error.description}), status
        return render_template("csrf_error.jinja2", status=status, message=error.description), status

    app.register_error_handler(CSRFError, _handle)
    app.register_error_handler(OriginError, _handle)
    app.register_error_handler(VerificationError, _handle)
