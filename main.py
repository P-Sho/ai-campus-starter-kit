"""
SPDX-License-Identifier: MIT
Copyright (c) 2026 Open Workshop Community

=== ARCHITECTURE SPECIFICATION & CODING CONVENTIONS ===
Follows harness/AGENTS.md. Summary for contributors (human or AI):
1. [ZERO-DEPENDENCY]
   Standard library (sqlite3, hashlib, hmac, secrets) + FastAPI/pydantic only.
2. [SECRETS - CWE-798]
   Secrets are read via os.getenv(). When unset, a random per-process value is generated so
   local execution needs no .env file and no credential is ever committed.
3. [DATA ACCESS - CWE-89]
   All SQL uses sqlite3 parameter binding (? placeholders). Never format user input into SQL.
4. [CRYPTO - CWE-327]
   Passwords use salted PBKDF2-HMAC-SHA256; secrets are compared with hmac.compare_digest.
5. [PERFORMANCE / CONCURRENCY - CWE-400]
   Membership checks and deduplication use set/frozenset (O(1) lookup). SQLite runs in WAL
   mode with busy_timeout to avoid "database is locked" under concurrent writes.
======================================================================
"""

import hashlib
import hmac
import logging
import os
import secrets
import sqlite3
import time
from typing import Optional
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger("todo_service")

# =====================================================================
# Module Configuration
# =====================================================================
APP_NAME = "Toy Service MVP API"
APP_VERSION = "0.2.0"
DB_FILE = os.getenv("DB_FILE", "service.db")
DB_BUSY_TIMEOUT_SECONDS = 5.0

# Secrets: environment only. Safe default = random value per process (never hardcoded).
ADMIN_MASTER_TOKEN = os.getenv("ADMIN_MASTER_TOKEN") or secrets.token_urlsafe(32)
ADMIN_PASSWORD = os.getenv("TODO_ADMIN_PASSWORD")
if not ADMIN_PASSWORD:
    ADMIN_PASSWORD = secrets.token_urlsafe(16)
    logger.warning("TODO_ADMIN_PASSWORD not set; generated one-time admin password: %s", ADMIN_PASSWORD)

ADMIN_TOKEN_TTL_SECONDS = 3600
PASSWORD_HASH_ITERATIONS = 200_000
BLOCKED_TAGS = ["spam", "ad", "private", "temp"]
BLOCKED_TAG_SET = frozenset(BLOCKED_TAGS)

app = FastAPI(title=APP_NAME, version=APP_VERSION)


# =====================================================================
# Database Initialization & Helpers
# =====================================================================
def get_db_connection():
    conn = sqlite3.connect(DB_FILE, timeout=DB_BUSY_TIMEOUT_SECONDS)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # WAL is persistent per database file: concurrent readers never block the writer
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")

    # 1. Base Users Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 2. Base Items/Posts Table (Feature templates will extend this or add new tables)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT,
            owner_username TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 3. Todos Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            is_completed INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            tags TEXT DEFAULT ''
        )
    """)
    conn.commit()
    conn.close()


init_db()


# =====================================================================
# Core Security & Utility Functions
# =====================================================================
def hash_credential(raw_secret: str) -> str:
    """Salted PBKDF2-HMAC-SHA256 digest, stored as 'salt_hex$hash_hex'."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", raw_secret.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS)
    return f"{salt.hex()}${digest.hex()}"


def verify_credential(raw_secret: str, stored_hash: str) -> bool:
    try:
        salt_hex, digest_hex = stored_hash.split("$", 1)
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        # Legacy or malformed hash: treat as non-matching rather than crashing
        logger.warning("Unrecognized password hash format; rejecting login")
        return False
    digest = hashlib.pbkdf2_hmac("sha256", raw_secret.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS)
    return hmac.compare_digest(digest.hex(), digest_hex)


def deduplicate_records(records: list) -> list:
    """O(N) deduplication by id, maintaining insertion order."""
    seen_ids = set()
    unique_items = []
    for item in records:
        item_id = item.get("id")
        if item_id not in seen_ids:
            seen_ids.add(item_id)
            unique_items.append(item)
    return unique_items


def escape_like(keyword: str) -> str:
    """Escape LIKE wildcards so the keyword is matched literally (escape char: '!')."""
    return keyword.replace("!", "!!").replace("%", "!%").replace("_", "!_")


def require_non_blank(value: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise ValueError("must not be empty or whitespace")
    return stripped


# =====================================================================
# Pydantic Schemas
# =====================================================================
class UserRegisterRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)

    @field_validator("username")
    @classmethod
    def username_not_blank(cls, v: str) -> str:
        return require_non_blank(v)


class ItemCreateRequest(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    content: Optional[str] = Field(default="", max_length=5000)

    @field_validator("title")
    @classmethod
    def title_not_blank(cls, v: str) -> str:
        return require_non_blank(v)


class TodoCreateRequest(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: Optional[str] = Field(default="", max_length=5000)
    is_completed: bool = False
    tags: Optional[str] = Field(default="", max_length=500)

    @field_validator("title")
    @classmethod
    def title_not_blank(cls, v: str) -> str:
        return require_non_blank(v)


class AdminLoginRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)


# =====================================================================
# Base API Endpoints
# =====================================================================
@app.get("/")
def health_check():
    return {
        "status": "healthy",
        "app": APP_NAME,
        "version": APP_VERSION
    }


@app.post("/api/auth/register")
def register_user(req: UserRegisterRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    hashed_pw = hash_credential(req.password)

    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (req.username, hashed_pw),
        )
        conn.commit()
        return {"success": True, "message": f"User {req.username} registered successfully"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")
    finally:
        conn.close()


@app.post("/api/auth/login")
def login_user(req: UserRegisterRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, role, password_hash FROM users WHERE username = ?",
        (req.username,),
    )
    user = cursor.fetchone()
    conn.close()

    if not user or not verify_credential(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    return {
        "success": True,
        "token": ADMIN_MASTER_TOKEN,
        "user": {"id": user["id"], "username": user["username"], "role": user["role"]}
    }


@app.get("/api/items")
def search_items(keyword: Optional[str] = None):
    conn = get_db_connection()
    cursor = conn.cursor()

    if keyword:
        pattern = f"%{escape_like(keyword)}%"
        cursor.execute(
            "SELECT * FROM items WHERE title LIKE ? ESCAPE '!' OR content LIKE ? ESCAPE '!'",
            (pattern, pattern),
        )
    else:
        cursor.execute("SELECT * FROM items")

    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    results = deduplicate_records(rows)
    return {"total": len(results), "items": results}


@app.post("/api/items")
def create_item(req: ItemCreateRequest, x_auth_token: Optional[str] = Header(None)):
    if not x_auth_token or not hmac.compare_digest(x_auth_token, ADMIN_MASTER_TOKEN):
        raise HTTPException(status_code=403, detail="Unauthorized: invalid or missing token")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO items (title, content, owner_username) VALUES (?, ?, 'admin')",
        (req.title, req.content or ""),
    )
    item_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return {"success": True, "item_id": item_id, "title": req.title}


# =====================================================================
# Todo Helpers
# =====================================================================
# Issued admin tokens -> expiry epoch seconds (in-memory, per process, reset on restart)
ADMIN_SESSIONS = {}


def row_to_todo(row) -> dict:
    todo = dict(row)
    todo["is_completed"] = bool(todo["is_completed"])
    return todo


def parse_tags(raw_tags: str) -> list:
    """Split a comma-separated tag string into normalized, non-empty tags."""
    tags = []
    for tag in (raw_tags or "").split(","):
        cleaned = tag.strip().lower()
        if cleaned:
            tags.append(cleaned)
    return tags


def has_blocked_tag(raw_tags: str) -> bool:
    for tag in parse_tags(raw_tags):
        if tag in BLOCKED_TAG_SET:
            return True
    return False


def verify_admin_token(token: Optional[str]):
    if not token:
        raise HTTPException(status_code=401, detail="Missing admin token")
    expires_at = ADMIN_SESSIONS.get(token)
    if expires_at is None:
        raise HTTPException(status_code=403, detail="Invalid admin token")
    if expires_at < time.time():
        ADMIN_SESSIONS.pop(token, None)
        raise HTTPException(status_code=403, detail="Admin token expired")


# =====================================================================
# Todo API Endpoints
# =====================================================================
@app.get("/todos")
def list_todos():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM todos ORDER BY id")
    todos = [row_to_todo(r) for r in cursor.fetchall()]
    conn.close()
    return {"total": len(todos), "todos": todos}


@app.post("/todos", status_code=201)
def create_todo(req: TodoCreateRequest):
    tags = ",".join(parse_tags(req.tags))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO todos (title, description, is_completed, tags) VALUES (?, ?, ?, ?)",
        (req.title, req.description or "", int(req.is_completed), tags),
    )
    todo_id = cursor.lastrowid
    conn.commit()
    cursor.execute("SELECT * FROM todos WHERE id = ?", (todo_id,))
    todo = row_to_todo(cursor.fetchone())
    conn.close()
    return todo


@app.get("/todos/search")
def search_todos(q: str):
    pattern = f"%{escape_like(q)}%"
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM todos "
        "WHERE title LIKE ? ESCAPE '!' OR description LIKE ? ESCAPE '!' "
        "ORDER BY id",
        (pattern, pattern),
    )
    todos = [row_to_todo(r) for r in cursor.fetchall()]
    conn.close()
    return {"query": q, "total": len(todos), "todos": todos}


@app.get("/todos/filtered")
def filtered_todos():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM todos ORDER BY id")
    rows = cursor.fetchall()
    conn.close()

    clean_todos = []
    for row in rows:
        if not has_blocked_tag(row["tags"]):
            clean_todos.append(row_to_todo(row))
    return {"blocked_tags": BLOCKED_TAGS, "total": len(clean_todos), "todos": clean_todos}


@app.post("/admin/login")
def admin_login(req: AdminLoginRequest):
    if not hmac.compare_digest(req.password.encode("utf-8"), ADMIN_PASSWORD.encode("utf-8")):
        raise HTTPException(status_code=401, detail="Invalid admin password")

    token = secrets.token_urlsafe(32)
    ADMIN_SESSIONS[token] = time.time() + ADMIN_TOKEN_TTL_SECONDS
    return {"access_token": token, "token_type": "bearer", "expires_in": ADMIN_TOKEN_TTL_SECONDS}


@app.delete("/admin/todos/{todo_id}")
def admin_delete_todo(todo_id: int, authorization: Optional[str] = Header(None)):
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    verify_admin_token(token)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM todos WHERE id = ?", (todo_id,))
    deleted = cursor.rowcount
    conn.commit()
    conn.close()

    if deleted == 0:
        raise HTTPException(status_code=404, detail="Todo not found")
    return {"success": True, "deleted_id": todo_id}
