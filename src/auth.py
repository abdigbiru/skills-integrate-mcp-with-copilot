"""Teacher credentials and short-lived, server-side sessions."""

import getpass
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import secrets
import sys
import tempfile
import threading
import time

from fastapi import Cookie, HTTPException


COOKIE_NAME = "teacher_session"
SESSION_SECONDS = 8 * 60 * 60
HASH_ITERATIONS = 600_000
sessions: dict[str, tuple[str, float]] = {}
session_lock = threading.Lock()
logger = logging.getLogger(__name__)


def credentials_path() -> Path:
    return Path(os.environ.get(
        "TEACHER_CREDENTIALS_FILE", str(Path(__file__).with_name("teachers.json"))
    ))


def load_teachers() -> dict[str, dict[str, str]]:
    with credentials_path().open(encoding="utf-8") as file:
        teachers = json.load(file)
    if not isinstance(teachers, dict):
        raise ValueError("Teacher credentials must be a JSON object")
    for username, record in teachers.items():
        if not username or not isinstance(record, dict):
            raise ValueError("Invalid teacher credential record")
        for field, length in (("salt", 32), ("password_hash", 64)):
            value = record.get(field)
            if (not isinstance(value, str) or len(value) != length
                    or any(char not in "0123456789abcdef" for char in value)):
                raise ValueError(f"Invalid teacher credential field: {field}")
    return teachers


def password_hash(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt), HASH_ITERATIONS
    ).hex()


def authenticate(username: str, password: str) -> str:
    try:
        teachers = load_teachers()
    except (OSError, ValueError):
        logger.exception("Unable to load teacher credentials")
        raise HTTPException(
            status_code=503, detail="Teacher login is unavailable. Contact the administrator."
        ) from None
    record = teachers.get(username)
    salt = record["salt"] if record else "0" * 32
    expected = record["password_hash"] if record else "0" * 64
    matches = hmac.compare_digest(password_hash(password, salt), expected)
    if not record or not matches:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = secrets.token_urlsafe(32)
    now = time.monotonic()
    with session_lock:
        for expired in [key for key, (_, expiry) in sessions.items() if expiry <= now]:
            del sessions[expired]
        sessions[token] = (username, now + SESSION_SECONDS)
    return token


def current_teacher(
    teacher_session: str | None = Cookie(default=None, alias=COOKIE_NAME),
) -> str | None:
    with session_lock:
        session = sessions.get(teacher_session) if teacher_session else None
        if session and session[1] > time.monotonic():
            return session[0]
        if teacher_session:
            sessions.pop(teacher_session, None)
    return None


def require_teacher(
    teacher_session: str | None = Cookie(default=None, alias=COOKIE_NAME),
) -> str:
    username = current_teacher(teacher_session)
    if username is None:
        raise HTTPException(status_code=401, detail="Teacher login required")
    return username


def add_teacher(username: str) -> None:
    if not username.strip() or len(username) > 100:
        raise ValueError("Username must contain between 1 and 100 characters")
    password = getpass.getpass("Assigned password (at least 12 characters): ")
    if len(password) < 12 or len(password) > 1024:
        raise ValueError("Password must contain between 12 and 1024 characters")
    if password != getpass.getpass("Confirm password: "):
        raise ValueError("Passwords do not match")
    path = credentials_path()
    teachers = load_teachers() if path.exists() else {}
    salt = secrets.token_hex(16)
    teachers[username] = {"salt": salt, "password_hash": password_hash(password, salt)}
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False
        ) as file:
            temporary_path = Path(file.name)
            json.dump(teachers, file, indent=2)
            file.write("\n")
        temporary_path.replace(path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    print(f"Teacher account saved to {path}. Restart the server to revoke existing sessions.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python -m src.auth USERNAME")
    try:
        add_teacher(sys.argv[1])
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
