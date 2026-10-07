"""
API & unit tests for the Todo service (main.py).

The API tests boot a real uvicorn server in a subprocess against a throwaway SQLite
file, so they exercise routing, validation, and the DB layer end to end without
needing httpx/TestClient.
"""

import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

import pytest
import requests

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST_ADMIN_SECRET = "pytest-admin-secret"
TEST_MASTER_TOKEN = "pytest-master-token"

# Point main.py at a scratch DB before it is imported by the unit tests below
_UNIT_DB_DIR = tempfile.mkdtemp(prefix="todo_unit_")
os.environ.setdefault("DB_FILE", os.path.join(_UNIT_DB_DIR, "unit.db"))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    db_path = str(tmp_path_factory.mktemp("api_db") / "api.db")
    port = _free_port()
    env = dict(os.environ)
    env.update({
        "DB_FILE": db_path,
        "TODO_ADMIN_PASSWORD": TEST_ADMIN_SECRET,
        "ADMIN_MASTER_TOKEN": TEST_MASTER_TOKEN,
    })
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT_DIR,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    base_url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 20
    while True:
        try:
            if requests.get(base_url + "/", timeout=1).status_code == 200:
                break
        except requests.ConnectionError:
            pass
        if proc.poll() is not None or time.time() > deadline:
            proc.kill()
            stderr = proc.stderr.read().decode("utf-8", errors="ignore")
            pytest.fail(f"uvicorn failed to start:\n{stderr[-2000:]}")
        time.sleep(0.2)

    yield {"url": base_url, "db_path": db_path}

    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


def _admin_token(base_url: str) -> str:
    res = requests.post(base_url + "/admin/login", json={"password": TEST_ADMIN_SECRET})
    assert res.status_code == 200
    return res.json()["access_token"]


def _todo_count(db_path: str) -> int:
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute("SELECT COUNT(*) FROM todos").fetchone()[0]
    finally:
        conn.close()


# =====================================================================
# 1. Basic CRUD
# =====================================================================
def test_create_list_search_and_filter_todos(server):
    url = server["url"]

    res = requests.post(url + "/todos", json={
        "title": "Buy milk", "description": "2L whole milk", "tags": "home, Shopping",
    })
    assert res.status_code == 201
    created = res.json()
    assert created["title"] == "Buy milk"
    assert created["is_completed"] is False
    assert created["tags"] == "home,shopping"
    assert created["id"] > 0 and created["created_at"]

    spam = requests.post(url + "/todos", json={"title": "Win a prize", "tags": "SPAM"}).json()

    listed = requests.get(url + "/todos").json()
    listed_ids = {t["id"] for t in listed["todos"]}
    assert created["id"] in listed_ids and spam["id"] in listed_ids

    found = requests.get(url + "/todos/search", params={"q": "whole"}).json()
    assert [t["id"] for t in found["todos"]] == [created["id"]]

    filtered_ids = {t["id"] for t in requests.get(url + "/todos/filtered").json()["todos"]}
    assert created["id"] in filtered_ids
    assert spam["id"] not in filtered_ids


def test_admin_can_delete_todo(server):
    url = server["url"]
    todo_id = requests.post(url + "/todos", json={"title": "to delete"}).json()["id"]
    headers = {"Authorization": f"Bearer {_admin_token(url)}"}

    res = requests.delete(f"{url}/admin/todos/{todo_id}", headers=headers)
    assert res.status_code == 200
    assert res.json() == {"success": True, "deleted_id": todo_id}

    assert requests.delete(f"{url}/admin/todos/{todo_id}", headers=headers).status_code == 404


# =====================================================================
# 2. SQL Injection defense
# =====================================================================
@pytest.mark.parametrize("payload", [
    "' OR '1'='1",
    "%' OR 1=1 --",
    "'; DROP TABLE todos; --",
])
def test_search_sql_injection_returns_no_rows(server, payload):
    url = server["url"]
    requests.post(url + "/todos", json={"title": "secret plan"})

    res = requests.get(url + "/todos/search", params={"q": payload})
    assert res.status_code == 200
    assert res.json()["total"] == 0
    # Table must still exist and be queryable
    assert _todo_count(server["db_path"]) >= 1


def test_injection_payload_is_stored_literally(server):
    url = server["url"]
    payload = "x'); DROP TABLE todos; --"
    created = requests.post(url + "/todos", json={"title": payload}).json()
    assert created["title"] == payload

    found = requests.get(url + "/todos/search", params={"q": "DROP TABLE"}).json()
    assert [t["title"] for t in found["todos"]] == [payload]
    assert _todo_count(server["db_path"]) >= 1


def test_like_wildcards_are_matched_literally(server):
    url = server["url"]
    requests.post(url + "/todos", json={"title": "100% done"})
    requests.post(url + "/todos", json={"title": "plain title"})

    titles = [t["title"] for t in requests.get(url + "/todos/search", params={"q": "%"}).json()["todos"]]
    assert "100% done" in titles
    assert "plain title" not in titles


def test_login_sql_injection_is_rejected(server):
    url = server["url"]
    requests.post(url + "/api/auth/register", json={"username": "alice", "password": "alice-pw"})

    for username in ["alice' --", "' OR '1'='1' --"]:
        res = requests.post(url + "/api/auth/login", json={"username": username, "password": "x"})
        assert res.status_code == 401


# =====================================================================
# 3. Admin authentication rejection
# =====================================================================
def test_invalid_admin_credentials_are_rejected(server):
    url = server["url"]
    todo_id = requests.post(url + "/todos", json={"title": "protected"}).json()["id"]

    assert requests.post(url + "/admin/login", json={"password": "wrong"}).status_code == 401

    no_token = requests.delete(f"{url}/admin/todos/{todo_id}")
    assert no_token.status_code in (401, 403)

    bad_token = requests.delete(f"{url}/admin/todos/{todo_id}", headers={"Authorization": "Bearer forged-token"})
    assert bad_token.status_code in (401, 403)

    wrong_scheme = requests.delete(f"{url}/admin/todos/{todo_id}", headers={"Authorization": TEST_MASTER_TOKEN})
    assert wrong_scheme.status_code in (401, 403)

    ids = {t["id"] for t in requests.get(url + "/todos").json()["todos"]}
    assert todo_id in ids


def test_item_creation_requires_master_token(server):
    url = server["url"]
    assert requests.post(url + "/api/items", json={"title": "t"}).status_code == 403
    assert requests.post(url + "/api/items", json={"title": "t"}, headers={"x-auth-token": "nope"}).status_code == 403
    ok = requests.post(url + "/api/items", json={"title": "t"}, headers={"x-auth-token": TEST_MASTER_TOKEN})
    assert ok.status_code == 200


# =====================================================================
# 4. Invalid input defense
# =====================================================================
@pytest.mark.parametrize("body", [
    {"title": ""},
    {"title": "   "},
    {"description": "no title"},
    {"title": None},
    {"title": "x" * 201},
])
def test_invalid_todo_input_is_rejected(server, body):
    url = server["url"]
    before = _todo_count(server["db_path"])

    res = requests.post(url + "/todos", json=body)
    assert res.status_code == 422
    assert _todo_count(server["db_path"]) == before


def test_title_is_trimmed(server):
    created = requests.post(server["url"] + "/todos", json={"title": "  padded  "}).json()
    assert created["title"] == "padded"


def test_wal_mode_enabled(server):
    conn = sqlite3.connect(server["db_path"])
    try:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    finally:
        conn.close()


# =====================================================================
# Unit tests: pure helpers
# =====================================================================
def test_password_hash_is_salted_and_verifiable():
    import main

    h1 = main.hash_credential("s3cret")
    h2 = main.hash_credential("s3cret")
    assert h1 != h2  # random salt
    assert main.verify_credential("s3cret", h1)
    assert not main.verify_credential("wrong", h1)
    assert not main.verify_credential("s3cret", "5f4dcc3b5aa765d61d8327deb882cf99")  # legacy md5


def test_deduplicate_records_keeps_first_occurrence_order():
    import main

    records = [{"id": 2, "v": "a"}, {"id": 1}, {"id": 2, "v": "b"}, {"id": 3}, {"id": 1}]
    assert main.deduplicate_records(records) == [{"id": 2, "v": "a"}, {"id": 1}, {"id": 3}]


def test_blocked_tag_detection():
    import main

    assert main.has_blocked_tag("work, AD")
    assert main.has_blocked_tag(" temp ")
    assert not main.has_blocked_tag("work,advertising,home")
    assert not main.has_blocked_tag("")
