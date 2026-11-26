"""Secure user registration and login service (Python 3.11, Flask 3, SQLite).

Required environment variables
    SECRET_KEY               Random secret (>= 32 chars) used to sign session cookies.
                             Generate one with:
                             python -c "import secrets; print(secrets.token_hex(32))"

Optional environment variables
    DATABASE_PATH            SQLite file path (default: users.db)
    LOG_FILE                 Log to this file (rotated) instead of stderr
    LOG_LEVEL                Logging level (default: INFO)
    SESSION_COOKIE_SECURE    Set to "false" ONLY for local HTTP development
                             (default: true, cookies are sent over HTTPS only)
"""
from __future__ import annotations

import logging
import os
import re
import secrets
import sqlite3
import sys
from contextlib import closing
from datetime import timedelta
from logging.handlers import RotatingFileHandler

from flask import Flask, g, jsonify, request, session, abort
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

# --------------------------------------------------------------------------- #
# Validation rules
# --------------------------------------------------------------------------- #
# Explicit ASCII class (not \w, which matches Unicode) and fullmatch()
# (not match()/$, which tolerate a trailing newline).
USERNAME_RE = re.compile(r"[A-Za-z0-9_]{3,30}")
PASSWORD_MIN_LEN = 12
PASSWORD_MAX_LEN = 128  # bounds the CPU cost of hashing attacker-supplied data

COMMON_PASSWORDS = frozenset(
    {
        "password1234", "password12345", "passw0rd1234", "123456789012",
        "1234567890123", "qwertyuiop12", "qwertyuiopas", "letmein123456",
        "iloveyou1234", "admin1234567", "welcome12345", "changeme1234",
        "abcdefghijkl", "abc123abc123", "000000000000", "111111111111",
    }
)

# Client-facing messages. These are deliberately generic / safe to expose.
MESSAGES = {
    "invalid_body": "Request body must be a JSON object.",
    "missing_fields": "Both 'username' and 'password' are required strings.",
    "username_format": (
        "Username must be 3-30 characters and contain only letters, "
        "numbers, and underscores."
    ),
    "password_length": (
        f"Password must be between {PASSWORD_MIN_LEN} and {PASSWORD_MAX_LEN} characters."
    ),
    "password_chars": "Password contains invalid characters.",
    "password_weak": (
        "Password is too weak. Use a mix of at least three of: lowercase, "
        "uppercase, digits, symbols; avoid common passwords and your username."
    ),
}

GENERIC_HTTP_ERRORS = {
    400: "Bad request.",
    401: "Authentication required.",
    404: "Resource not found.",
    405: "Method not allowed.",
    413: "Request too large.",
    415: "Unsupported media type.",
    429: "Too many requests.",
}

# Used to equalise timing when a username does not exist (limits user enumeration).
_DUMMY_HASH = generate_password_hash(secrets.token_urlsafe(24), method="scrypt")


def validate_username(value: object) -> str | None:
    """Return an error key, or None if the username is acceptable."""
    if not isinstance(value, str) or not USERNAME_RE.fullmatch(value):
        return "username_format"
    return None


def validate_password(value: object, username: str) -> str | None:
    """Return an error key, or None if the password is acceptable."""
    if not isinstance(value, str):
        return "missing_fields"
    if not (PASSWORD_MIN_LEN <= len(value) <= PASSWORD_MAX_LEN):
        return "password_length"
    if any(ord(c) < 32 or ord(c) == 127 for c in value):  # control chars / NUL
        return "password_chars"

    classes = sum(
        (
            any(c.islower() for c in value),
            any(c.isupper() for c in value),
            any(c.isdigit() for c in value),
            any(not c.isalnum() for c in value),
        )
    )
    lowered = value.lower()
    if (
        classes < 3
        or len(set(value)) < 6
        or lowered in COMMON_PASSWORDS
        or username.lower() in lowered
    ):
        return "password_weak"
    return None


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _safe(value: object, limit: int = 60) -> str:
    """Make untrusted text safe for logs (escapes newlines -> no log forging)."""
    return repr(str(value))[:limit]


def _json_body() -> dict | None:
    """Return the parsed JSON object, or None if absent/malformed."""
    if not request.is_json:
        return None
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


def _bad_request(app: Flask, key: str, **log_ctx: object):
    # Never log passwords. Only the reason code, client IP, and a sanitised username.
    app.logger.warning(
        "Validation failure: reason=%s endpoint=%s ip=%s %s",
        key,
        request.endpoint,
        request.remote_addr,
        " ".join(f"{k}={_safe(v)}" for k, v in log_ctx.items()),
    )
    return jsonify(error=MESSAGES[key]), 400


def _configure_logging(app: Flask) -> None:
    log_file = os.environ.get("LOG_FILE")
    if log_file:
        # Create the log file owner-readable only.
        os.close(os.open(log_file, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600))
        handler: logging.Handler = RotatingFileHandler(
            log_file, maxBytes=1_000_000, backupCount=5
        )
    else:
        handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    )
    app.logger.handlers.clear()
    app.logger.addHandler(handler)
    level = os.environ.get("LOG_LEVEL", "INFO").upper()
    app.logger.setLevel(level if level in logging.getLevelNamesMapping() else "INFO")


def _init_db(path: str) -> None:
    with closing(sqlite3.connect(path, timeout=10)) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # best effort (e.g. unsupported filesystem)


# --------------------------------------------------------------------------- #
# Application factory
# --------------------------------------------------------------------------- #
def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY"),
        DATABASE=os.environ.get("DATABASE_PATH", "users.db"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "true").lower()
        != "false",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    if test_config:
        app.config.update(test_config)

    secret = app.config.get("SECRET_KEY")
    if not secret or len(secret) < 32:
        # Fail fast; message does not echo the value.
        raise RuntimeError("SECRET_KEY environment variable must be set (>= 32 chars).")

    _configure_logging(app)
    _init_db(app.config["DATABASE"])

    # ---- database access (one connection per request) --------------------- #
    def get_db() -> sqlite3.Connection:
        if "db" not in g:
            conn = sqlite3.connect(app.config["DATABASE"], timeout=10)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            g.db = conn
        return g.db

    @app.teardown_appcontext
    def close_db(_exc: BaseException | None) -> None:
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    @app.before_request
    def csrf_protect():
        """
        Require a valid CSRF token for authenticated POST requests.
        Login and registration are excluded because users do not yet
        have a session token.
        """
        if (
            request.method == "POST"
            and request.endpoint not in ("login", "register")
        ):
            token = session.get("csrf_token")
            supplied = request.headers.get("X-CSRF-Token")

            if not token or token != supplied:
                app.logger.warning(
                    "CSRF validation failed: endpoint=%s ip=%s",
                    request.endpoint,
                    request.remote_addr,
                )
                return jsonify(error="CSRF validation failed."), 403

            
    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Content-Security-Policy"] = "default-src 'none'"
        return resp

    # ---- routes ------------------------------------------------------------ #
    @app.post("/register")
    def register():
        data = _json_body()
        if data is None:
            return _bad_request(app, "invalid_body")

        username, password = data.get("username"), data.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            return _bad_request(app, "missing_fields")

        if (key := validate_username(username)) is not None:
            return _bad_request(app, key, username=username)
        if (key := validate_password(password, username)) is not None:
            return _bad_request(app, key, username=username)

        password_hash = generate_password_hash(password, method="scrypt")
        try:
            db = get_db()
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
            db.commit()
        except sqlite3.IntegrityError:
            app.logger.warning(
                "Registration rejected: duplicate username=%s ip=%s",
                _safe(username),
                request.remote_addr,
            )
            return jsonify(error="Username is not available."), 409

        app.logger.info("User registered: username=%s", _safe(username))
        return jsonify(message="Registration successful."), 201

    @app.post("/login")
    def login():
        data = _json_body()
        if data is None:
            return _bad_request(app, "invalid_body")

        username, password = data.get("username"), data.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            return _bad_request(app, "missing_fields")
        if validate_username(username) is not None:
            return _bad_request(app, "username_format", username=username)
        if not (1 <= len(password) <= PASSWORD_MAX_LEN):
            return _bad_request(app, "password_length")

        row = get_db().execute(
            "SELECT id, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()

        # Always perform one hash verification so timing doesn't reveal
        # whether the username exists.
        stored = row["password_hash"] if row else _DUMMY_HASH
        ok = check_password_hash(stored, password)

        if not row or not ok:
            app.logger.warning(
                "Failed login: username=%s ip=%s", _safe(username), request.remote_addr
            )
            return jsonify(error="Invalid username or password."), 401

        session.clear()  # prevent session fixation
        session["user_id"] = row["id"]
        session["csrf_token"] = secrets.token_hex(32)
        session.permanent = True
        app.logger.info("Login success: username=%s", _safe(username))
        return jsonify(message="Login successful."), 200

    @app.post("/logout")
    def logout():
        session.clear()
        return jsonify(message="Logged out."), 200

    @app.get("/me")
    def me():
        user_id = session.get("user_id")
        row = None
        if isinstance(user_id, int):
            row = get_db().execute(
                "SELECT username FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        if row is None:
            session.clear()
            return jsonify(error=GENERIC_HTTP_ERRORS[401]), 401
        return jsonify(
            username=row["username"],
            csrf_token=session.get("csrf_token")
        ), 200

    # ---- error handling (generic client messages, details only in logs) ---- #
    @app.errorhandler(HTTPException)
    def handle_http_error(err: HTTPException):
        code = err.code or 500
        app.logger.info(
            "HTTP %s: method=%s path=%s ip=%s",
            code,
            request.method,
            _safe(request.path, 100),
            request.remote_addr,
        )
        return jsonify(error=GENERIC_HTTP_ERRORS.get(code, "Request failed.")), code

    @app.errorhandler(Exception)
    def handle_unexpected_error(_err: Exception):
        # Full traceback goes to the server log only.
        app.logger.exception("Unhandled server error: ip=%s", request.remote_addr)
        return jsonify(error="An internal error occurred."), 500

    return app


if __name__ == "__main__":
    # Development server only; use a production WSGI server (e.g. gunicorn)
    # behind HTTPS in production. Debug mode is intentionally never enabled.
    create_app().run(host="127.0.0.1", port=5000, debug=False)
