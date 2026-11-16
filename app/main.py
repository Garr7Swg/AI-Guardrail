from __future__ import annotations

import hashlib
import hmac
import io
import json
import logging
import os
import re
import secrets
import sqlite3
import time
import threading
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import anyio
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from PIL import Image, UnidentifiedImageError
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile as StarletteUploadFile
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.config import Settings, load_settings
from app.database import connect, initialize
from app.guardrails import MAX_PROMPT_CHARS, inspect_prompt
from app.llm import DISCLAIMER, arbitrate, fallback_payload


logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("guardrail")
settings = load_settings()
password_hasher = PasswordHasher(time_cost=3, memory_cost=65_536, parallelism=2)
argon_slots = threading.BoundedSemaphore(2)
dummy_password_hash = password_hasher.hash("not-a-real-user-password")
SESSION_COOKIE = "guardrail_session"
SESSION_TTL = 12 * 60 * 60
AUTH_WINDOW = 15 * 60
AUTH_LIMIT = 12
MAX_DOCUMENT_BYTES = 25 * 1024 * 1024
USER_DOCUMENT_QUOTA = 100 * 1024 * 1024
MAX_AVATAR_BYTES = 2 * 1024 * 1024
MAX_CHAT_BODY_BYTES = 64 * 1024
MAX_API_BODY_BYTES = 256 * 1024


@dataclass(frozen=True)
class AuthContext:
    user_id: int
    email: str
    display_name: str
    csrf_token: str
    has_avatar: bool


class RegisterBody(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    display_name: str = Field(min_length=1, max_length=60)
    password: str = Field(min_length=12, max_length=128)


class LoginBody(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=128)


class ChatBody(BaseModel):
    prompt: str = Field(min_length=1, max_length=MAX_PROMPT_CHARS)


def _secure_dirs() -> None:
    for directory in (settings.data_dir, settings.database_path.parent, settings.upload_dir):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass


@asynccontextmanager
async def lifespan(_: FastAPI):
    _secure_dirs()
    initialize(settings)
    yield


app = FastAPI(
    title="AI Guardrail & Real-Time Content Arbitration",
    description=(
        "Prompt screening, dual-model arbitration, authenticated document storage, and a fail-closed fallback. "
        "Interactive API documentation is available at /docs. For authenticated write calls, sign in, read "
        "csrf_token from GET /api/auth/me, and send it in the X-CSRF-Token header."
    ),
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)


class SecurityHeadersMiddleware:
    def __init__(self, inner: Any):
        self.inner = inner

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        async def send_with_headers(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                existing = {key.lower() for key, _ in headers}
                defaults = {
                    b"x-content-type-options": b"nosniff",
                    b"x-frame-options": b"DENY",
                    b"referrer-policy": b"no-referrer",
                    b"permissions-policy": b"camera=(), microphone=(), geolocation=()",
                    b"content-security-policy": (
                        b"default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; "
                        b"object-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                        b"script-src 'self' https://cdn.jsdelivr.net; connect-src 'self'"
                    ),
                }
                if settings.cookie_secure:
                    defaults[b"strict-transport-security"] = b"max-age=31536000; includeSubDomains"
                if scope.get("type") == "http" and scope.get("path", "").startswith("/api/"):
                    defaults[b"cache-control"] = b"no-store"
                headers.extend((key, value) for key, value in defaults.items() if key not in existing)
                message["headers"] = headers
            await send(message)

        await self.inner(scope, receive, send_with_headers)


class OriginChecksMiddleware:
    def __init__(self, inner: Any):
        self.inner = inner

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") == "http" and scope.get("method") in {"POST", "PUT", "PATCH", "DELETE"}:
            headers = {key.decode("latin1").lower(): value.decode("latin1") for key, value in scope.get("headers", [])}
            origin = headers.get("origin")
            fetch_site = headers.get("sec-fetch-site", "").lower()
            host = headers.get("host", "").lower()
            origin_host = urlsplit(origin).netloc.lower() if origin else ""
            if fetch_site == "cross-site" or (origin and (not origin_host or origin_host != host)):
                response = JSONResponse({"detail": "Cross-origin request rejected"}, status_code=403)
                await response(scope, receive, send)
                return
        await self.inner(scope, receive, send)


class PromptGateMiddleware:
    """Screens chat prompts before route handling and passes the decision downstream."""

    def __init__(self, inner: Any):
        self.inner = inner

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http" or scope.get("path") != "/api/chat" or scope.get("method") != "POST":
            await self.inner(scope, receive, send)
            return

        body = bytearray()
        disconnected = False
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                disconnected = True
                break
            body.extend(message.get("body", b""))
            if len(body) > MAX_CHAT_BODY_BYTES:
                response = JSONResponse(fallback_payload(blocked=True, reason="request_too_large"))
                await response(scope, receive, send)
                return
            if not message.get("more_body", False):
                break
        if disconnected:
            return

        state = scope.setdefault("state", {})
        try:
            payload = json.loads(body)
            prompt = payload.get("prompt") if isinstance(payload, dict) else None
            if isinstance(prompt, str):
                state["prompt_guardrail"] = inspect_prompt(prompt, settings.blocked_brands)
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass

        sent_body = False

        async def replay_receive() -> dict[str, Any]:
            nonlocal sent_body
            if not sent_body:
                sent_body = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.inner(scope, replay_receive, send)


class BodyLimitMiddleware:
    """Bounds request bodies, including chunked uploads, before multipart parsing."""

    def __init__(self, inner: Any):
        self.inner = inner

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http" or scope.get("method") not in {"POST", "PUT", "PATCH"}:
            await self.inner(scope, receive, send)
            return
        path = scope.get("path", "")
        limit = MAX_API_BODY_BYTES
        if path == "/api/chat":
            limit = MAX_CHAT_BODY_BYTES
        elif path == "/api/files":
            limit = MAX_DOCUMENT_BYTES + 512 * 1024
        elif path == "/api/auth/avatar":
            limit = MAX_AVATAR_BYTES + 512 * 1024
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_length = headers.get(b"content-length", b"")
        if content_length.isdigit() and int(content_length) > limit:
            await self._too_large(scope, receive, send, path)
            return

        consumed = 0
        oversized = False

        async def limited_receive() -> dict[str, Any]:
            nonlocal consumed, oversized
            if oversized:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                consumed += len(message.get("body", b""))
                if consumed > limit:
                    oversized = True
                    return {"type": "http.disconnect"}
            return message

        async def quiet_send(message: dict[str, Any]) -> None:
            if not oversized:
                await send(message)

        try:
            await self.inner(scope, limited_receive, quiet_send)
        except Exception:
            if not oversized:
                raise
        if oversized:
            await self._too_large(scope, receive, send, path)

    async def _too_large(self, scope: dict[str, Any], receive: Any, send: Any, path: str) -> None:
        if path == "/api/chat":
            response = JSONResponse(fallback_payload(blocked=True, reason="request_too_large"), status_code=413)
        else:
            response = JSONResponse({"detail": "Request body is too large"}, status_code=413)
        await response(scope, receive, send)


# Starlette makes the most recently added middleware the outermost layer.
app.add_middleware(PromptGateMiddleware)
app.add_middleware(BodyLimitMiddleware)
app.add_middleware(OriginChecksMiddleware)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts))
app.add_middleware(SecurityHeadersMiddleware)

static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")


def _now() -> int:
    return int(time.time())


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _auth_context(request: Request) -> AuthContext | None:
    token = request.cookies.get(SESSION_COOKIE, "")
    if not token or len(token) > 128:
        return None
    with connect(settings) as db:
        row = db.execute(
            """SELECT u.id, u.email, u.display_name, u.avatar, s.csrf_token
               FROM sessions s JOIN users u ON u.id = s.user_id
               WHERE s.token_hash = ? AND s.expires_at > ?""",
            (_token_hash(token), _now()),
        ).fetchone()
    if row is None:
        return None
    return AuthContext(
        user_id=row["id"],
        email=row["email"],
        display_name=row["display_name"],
        csrf_token=row["csrf_token"],
        has_avatar=row["avatar"] is not None,
    )


def require_auth(request: Request) -> AuthContext:
    auth = _auth_context(request)
    if auth is None:
        raise HTTPException(status_code=401, detail="Sign in to continue")
    return auth


def require_csrf(
    csrf_header: str = Header(..., alias="X-CSRF-Token", description="Copy csrf_token from GET /api/auth/me."),
    auth: AuthContext = Depends(require_auth),
) -> AuthContext:
    supplied = csrf_header
    if not supplied or not hmac.compare_digest(supplied, auth.csrf_token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    return auth


def _user_payload(auth: AuthContext) -> dict[str, object]:
    return {
        "authenticated": True,
        "id": auth.user_id,
        "email": auth.email,
        "display_name": auth.display_name,
        "has_avatar": auth.has_avatar,
        "csrf_token": auth.csrf_token,
    }


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_TTL,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
    )


def _rate_buckets(request: Request, email: str | None = None) -> tuple[str, ...]:
    ip = request.client.host if request.client else "unknown"
    values = ["ip:" + ip]
    if email:
        values.append("email:" + email)
    return tuple(
        hmac.new(settings.secret.encode(), value.encode(), hashlib.sha256).hexdigest()
        for value in values
    )


def _reserve_auth_attempt(buckets: tuple[str, ...]) -> None:
    cutoff = _now() - AUTH_WINDOW
    placeholders = ",".join("?" for _ in buckets)
    with connect(settings) as db:
        db.execute("BEGIN IMMEDIATE")
        try:
            rows = db.execute(
                f"SELECT bucket, COUNT(*) AS attempts FROM auth_attempts "
                f"WHERE bucket IN ({placeholders}) AND attempted_at > ? GROUP BY bucket",
                (*buckets, cutoff),
            ).fetchall()
            if any(row["attempts"] >= AUTH_LIMIT for row in rows):
                raise HTTPException(status_code=429, detail="Too many sign-in attempts. Try again later.")
            now = _now()
            db.executemany(
                "INSERT INTO auth_attempts(bucket, attempted_at) VALUES (?, ?)",
                [(bucket, now) for bucket in buckets],
            )
            db.execute("DELETE FROM auth_attempts WHERE attempted_at < ?", (now - 24 * 60 * 60,))
            db.commit()
        except Exception:
            db.rollback()
            raise


def _hash_password(password: str) -> str:
    with argon_slots:
        return password_hasher.hash(password)


def _verify_password(encoded: str, password: str) -> bool:
    with argon_slots:
        return password_hasher.verify(encoded, password)


def _create_session(db: sqlite3.Connection, user_id: int) -> tuple[str, str]:
    raw_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    db.execute(
        "INSERT INTO sessions(token_hash, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)",
        (_token_hash(raw_token), user_id, csrf_token, _now() + SESSION_TTL),
    )
    return raw_token, csrf_token


def _clean_name(name: str | None) -> str:
    raw = (name or "download").replace("\\", "/").split("/")[-1]
    cleaned = "".join(char for char in raw if ord(char) >= 32 and ord(char) != 127).strip().strip(".")
    return (cleaned[:180] or "download")


def _file_path(file_id: str) -> Path:
    return settings.upload_dir / file_id


def _reserve_chat_slot(user_id: int) -> bool:
    now = _now()
    with connect(settings) as db:
        db.execute("BEGIN IMMEDIATE")
        try:
            db.execute("DELETE FROM chat_attempts WHERE attempted_at < ?", (now - 24 * 60 * 60,))
            minute_count = db.execute(
                "SELECT COUNT(*) FROM chat_attempts WHERE user_id = ? AND attempted_at > ?",
                (user_id, now - 60),
            ).fetchone()[0]
            day_count = db.execute(
                "SELECT COUNT(*) FROM chat_attempts WHERE user_id = ? AND attempted_at > ?",
                (user_id, now - 24 * 60 * 60),
            ).fetchone()[0]
            if minute_count >= 10 or day_count >= 100:
                db.commit()
                return False
            db.execute("INSERT INTO chat_attempts(user_id, attempted_at) VALUES (?, ?)", (user_id, now))
            db.commit()
            return True
        except Exception:
            db.rollback()
            raise


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(static_dir / "index.html")


@app.get("/docs", include_in_schema=False)
async def api_docs() -> HTMLResponse:
    return HTMLResponse(
        """<!doctype html><html lang="en"><head><meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Sentinel API Reference</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css" />
        <link rel="stylesheet" href="/static/docs.css" /></head><body>
        <div class="docs-top"><a href="/">← SENTINEL</a><span>SECURE CONTENT ARBITRATION / API REFERENCE</span></div>
        <div id="swagger-ui"></div>
        <script defer src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
        <script defer src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-standalone-preset.js"></script>
        <script defer src="/static/docs-init.js"></script></body></html>"""
    )


@app.get("/api/health", tags=["system"])
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/auth/register", tags=["authentication"])
async def register(body: RegisterBody, request: Request) -> Response:
    if not settings.allow_registration:
        raise HTTPException(status_code=403, detail="Registration is currently closed")
    email = body.email.strip().casefold()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise HTTPException(status_code=422, detail="Enter a valid email address")
    display_name = body.display_name.strip()
    if not display_name or any(ord(char) < 32 for char in display_name):
        raise HTTPException(status_code=422, detail="Enter a valid display name")

    buckets = _rate_buckets(request, email)
    await run_in_threadpool(_reserve_auth_attempt, buckets)
    password_hash = await run_in_threadpool(_hash_password, body.password)
    now = _now()
    with connect(settings) as db:
        db.execute("BEGIN IMMEDIATE")
        try:
            db.execute(
                "INSERT INTO users(email, display_name, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email, display_name, password_hash, now),
            )
            user_id = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()[0]
            raw_token, csrf_token = _create_session(db, user_id)
            db.commit()
        except sqlite3.IntegrityError:
            db.rollback()
            raise HTTPException(status_code=409, detail="Account could not be created") from None
        except Exception:
            db.rollback()
            raise
    auth = _auth_context_from_id(user_id, csrf_token)
    response = JSONResponse(_user_payload(auth), status_code=201)
    _set_session_cookie(response, raw_token)
    return response


def _auth_context_from_id(user_id: int, csrf_token: str) -> AuthContext:
    with connect(settings) as db:
        row = db.execute("SELECT id, email, display_name, avatar FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise RuntimeError("Newly created account was not found")
    return AuthContext(row["id"], row["email"], row["display_name"], csrf_token, row["avatar"] is not None)


@app.post("/api/auth/login", tags=["authentication"])
async def login(body: LoginBody, request: Request) -> Response:
    email = body.email.strip().casefold()
    buckets = _rate_buckets(request, email)
    await run_in_threadpool(_reserve_auth_attempt, buckets)
    with connect(settings) as db:
        row = db.execute(
            "SELECT id, password_hash FROM users WHERE email = ? COLLATE NOCASE", (email,)
        ).fetchone()
    candidate_hash = row["password_hash"] if row else dummy_password_hash
    try:
        verified = await run_in_threadpool(_verify_password, candidate_hash, body.password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        verified = False
    if not row or not verified:
        raise HTTPException(status_code=401, detail="Email or password is incorrect")

    raw_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    with connect(settings) as db:
        db.execute("BEGIN IMMEDIATE")
        try:
            db.execute("DELETE FROM sessions WHERE user_id = ?", (row["id"],))
            db.execute(
                "INSERT INTO sessions(token_hash, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)",
                (_token_hash(raw_token), row["id"], csrf_token, _now() + SESSION_TTL),
            )
            db.execute("DELETE FROM sessions WHERE expires_at < ?", (_now(),))
            db.commit()
        except Exception:
            db.rollback()
            raise
    response = JSONResponse(_user_payload(_auth_context_from_id(row["id"], csrf_token)))
    _set_session_cookie(response, raw_token)
    return response


@app.get("/api/auth/me", tags=["authentication"])
async def me(request: Request) -> dict[str, object]:
    auth = _auth_context(request)
    return _user_payload(auth) if auth else {"authenticated": False}


@app.post("/api/auth/logout", tags=["authentication"])
async def logout(request: Request, auth: AuthContext = Depends(require_csrf)) -> Response:
    token = request.cookies.get(SESSION_COOKIE, "")
    with connect(settings) as db:
        db.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(token),))
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE, path="/", secure=settings.cookie_secure, httponly=True, samesite="strict")
    return response


@app.get("/api/auth/avatar", tags=["authentication"])
async def get_avatar(auth: AuthContext = Depends(require_auth)) -> Response:
    with connect(settings) as db:
        row = db.execute("SELECT avatar FROM users WHERE id = ?", (auth.user_id,)).fetchone()
    if not row or row["avatar"] is None:
        raise HTTPException(status_code=404, detail="No profile picture has been uploaded")
    return Response(row["avatar"], media_type="image/png", headers={"Cache-Control": "private, no-store"})


@app.post("/api/auth/avatar", tags=["authentication"])
async def upload_avatar(
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    file: UploadFile = File(...),
) -> dict[str, bool]:
    raw = await file.read(MAX_AVATAR_BYTES + 1)
    await file.close()
    if not raw or len(raw) > MAX_AVATAR_BYTES:
        raise HTTPException(status_code=413, detail="Profile pictures must be 2 MB or smaller")
    try:
        with Image.open(io.BytesIO(raw)) as image:
            if image.format not in {"PNG", "JPEG", "WEBP", "GIF"}:
                raise HTTPException(status_code=415, detail="Use a PNG, JPEG, WebP, or GIF image")
            if image.width > 4096 or image.height > 4096 or image.width * image.height > 12_000_000:
                raise HTTPException(status_code=413, detail="Image dimensions are too large")
            image.verify()
        with Image.open(io.BytesIO(raw)) as image:
            image.thumbnail((512, 512))
            converted = image.convert("RGBA" if "A" in image.getbands() else "RGB")
            output = io.BytesIO()
            converted.save(output, format="PNG", optimize=True)
            avatar = output.getvalue()
    except HTTPException:
        raise
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError, Image.DecompressionBombWarning):
        raise HTTPException(status_code=415, detail="The uploaded file is not a valid supported image") from None
    with connect(settings) as db:
        db.execute("UPDATE users SET avatar = ?, avatar_type = 'image/png' WHERE id = ?", (avatar, auth.user_id))
    return {"ok": True}


@app.post("/api/chat", tags=["arbitration"])
async def chat(body: ChatBody, request: Request, auth: AuthContext = Depends(require_csrf)) -> Response:
    decision = getattr(request.state, "prompt_guardrail", None)
    if decision is not None and decision.blocked:
        return JSONResponse(fallback_payload(blocked=True, reason=decision.reason))
    if not _reserve_chat_slot(auth.user_id):
        return JSONResponse(fallback_payload(reason="rate_limited"), status_code=429)
    request_id = uuid.uuid4().hex
    try:
        answer = await arbitrate(body.prompt, settings)
        return JSONResponse({"answer": answer, "disclaimer": "", "blocked": False, "request_id": request_id})
    except Exception as exc:
        # Do not log prompt text, provider responses, or credentials.
        logger.warning("Arbitration unavailable (%s), request_id=%s", type(exc).__name__, request_id)
        payload = fallback_payload()
        payload["request_id"] = request_id
        return JSONResponse(payload)


@app.get("/api/files", tags=["documents"])
async def list_files(auth: AuthContext = Depends(require_auth)) -> dict[str, object]:
    with connect(settings) as db:
        rows = db.execute(
            "SELECT id, original_name, byte_size, created_at FROM documents WHERE user_id = ? ORDER BY created_at DESC",
            (auth.user_id,),
        ).fetchall()
    return {
        "files": [
            {"id": row["id"], "name": row["original_name"], "size": row["byte_size"], "created_at": row["created_at"]}
            for row in rows
        ]
    }


@app.post("/api/files", tags=["documents"])
async def upload_file(
    request: Request,
    auth: AuthContext = Depends(require_csrf),
) -> dict[str, object]:
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > MAX_DOCUMENT_BYTES + 1_000_000:
        raise HTTPException(status_code=413, detail="Document is larger than the 25 MB limit")
    async with request.form(max_files=1, max_fields=0) as form:
        file = form.get("file")
        if not isinstance(file, StarletteUploadFile):
            raise HTTPException(status_code=422, detail="Choose a file to upload")
        file_id = uuid.uuid4().hex
        temp_path = settings.upload_dir / ("." + file_id + ".upload")
        final_path = _file_path(file_id)
        byte_size = 0
        try:
            async with await anyio.open_file(temp_path, "wb") as handle:
                while chunk := await file.read(256 * 1024):
                    byte_size += len(chunk)
                    if byte_size > MAX_DOCUMENT_BYTES:
                        raise HTTPException(status_code=413, detail="Document is larger than the 25 MB limit")
                    await handle.write(chunk)
            if byte_size == 0:
                raise HTTPException(status_code=422, detail="The selected file is empty")
            original_name = _clean_name(file.filename)
            with connect(settings) as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    used = db.execute(
                        "SELECT COALESCE(SUM(byte_size), 0) FROM documents WHERE user_id = ?", (auth.user_id,)
                    ).fetchone()[0]
                    hour_uploads = db.execute(
                        "SELECT COUNT(*) FROM documents WHERE user_id = ? AND created_at > ?",
                        (auth.user_id, _now() - 60 * 60),
                    ).fetchone()[0]
                    day_uploads = db.execute(
                        "SELECT COUNT(*) FROM documents WHERE user_id = ? AND created_at > ?",
                        (auth.user_id, _now() - 24 * 60 * 60),
                    ).fetchone()[0]
                    if hour_uploads >= 30 or day_uploads >= 100:
                        raise HTTPException(status_code=429, detail="Document upload limit reached. Try again later.")
                    if used + byte_size > USER_DOCUMENT_QUOTA:
                        raise HTTPException(status_code=413, detail="Your document storage quota is full")
                    os.replace(temp_path, final_path)
                    db.execute(
                        "INSERT INTO documents(id, user_id, original_name, byte_size, created_at) VALUES (?, ?, ?, ?, ?)",
                        (file_id, auth.user_id, original_name, byte_size, _now()),
                    )
                    db.commit()
                except Exception:
                    db.rollback()
                    final_path.unlink(missing_ok=True)
                    raise
            return {"id": file_id, "name": original_name, "size": byte_size}
        finally:
            temp_path.unlink(missing_ok=True)
            await file.close()


@app.get("/api/files/{file_id}", tags=["documents"])
async def download_file(file_id: uuid.UUID, auth: AuthContext = Depends(require_auth)) -> FileResponse:
    key = file_id.hex
    with connect(settings) as db:
        row = db.execute(
            "SELECT original_name FROM documents WHERE id = ? AND user_id = ?", (key, auth.user_id)
        ).fetchone()
    path = _file_path(key)
    if row is None or not path.is_file():
        raise HTTPException(status_code=404, detail="Document not found")
    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename=row["original_name"],
        headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "private, no-store"},
    )


@app.delete("/api/files/{file_id}", tags=["documents"])
async def delete_file(file_id: uuid.UUID, auth: AuthContext = Depends(require_csrf)) -> dict[str, bool]:
    key = file_id.hex
    with connect(settings) as db:
        db.execute("BEGIN IMMEDIATE")
        try:
            row = db.execute(
                "SELECT id FROM documents WHERE id = ? AND user_id = ?", (key, auth.user_id)
            ).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Document not found")
            db.execute("DELETE FROM documents WHERE id = ? AND user_id = ?", (key, auth.user_id))
            db.commit()
        except Exception:
            db.rollback()
            raise
    _file_path(key).unlink(missing_ok=True)
    return {"ok": True}
