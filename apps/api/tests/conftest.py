from __future__ import annotations

import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

os.environ["DATABASE_URL"] = "sqlite:///./test_api.db"
os.environ["SCAN_ALLOW_PRIVATE_TARGETS"] = "1"
os.environ["SMTP_HOST"] = "mailpit.invalid"


def _fresh_db():
    import pathlib
    p = pathlib.Path("test_api.db")
    if p.exists():
        p.unlink()
    import app.models  # noqa: F401  (import registers tables)
    from app.core.db import Base, engine
    Base.metadata.create_all(engine)


_fresh_db()


import pytest


class _Lab(BaseHTTPRequestHandler):
    def log_message(self, *args, **kwargs):
        pass

    def _send(self, code, headers, body=b""):
        self.send_response(code)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        php = os.getenv("LAB_PHP_VERSION", "8.4.26")
        if self.path.startswith("/.well-known/security.txt"):
            self._send(200, {"Content-Type": "text/plain"},
                       b"Contact: mailto:security@labvalid.example\n"
                       b"Policy: https://labvalid.example/security-policy\n")
        elif self.path.startswith("/security.txt"):
            self._send(404, {"Content-Type": "text/plain"}, b"not here")
        elif self.path.startswith("/phpinfo.php"):
            if os.getenv("LAB_PHPINFO", "1") == "1":
                body = (f"<html><title>phpinfo()</title>"
                        f"<h1>PHP Version {php}</h1></html>").encode()
                self._send(200, {"Content-Type": "text/html",
                                 "X-Powered-By": f"PHP/{php}"}, body)
            else:
                self._send(404, {}, b"no")
        elif self.path.startswith("/"):
            headers = {"Content-Type": "text/html"}
            if os.getenv("LAB_EXPOSE_PHP", "1") == "1":
                headers["X-Powered-By"] = f"PHP/{php}"
            if os.getenv("LAB_SERVER", ""):
                headers["Server"] = os.getenv("LAB_SERVER", "")
            body = (b"<html><body><a href='/security'>security</a>"
                    b"<p>hello</p></body></html>")
            self._send(200, headers, body)
        else:
            self._send(404, {}, b"no")




@pytest.fixture(scope="session")
def lab_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Lab)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture()
def patched_lab(monkeypatch):
    def _flip():
        monkeypatch.setenv("LAB_PHP_VERSION", "8.4.27")
    return _flip


class Api:
    def __init__(self, client, cookies, email=""):
        self.client = client
        self.cookies = dict(cookies)
        self.email = email

    def request(self, method, url, **kwargs):
        headers = dict(kwargs.pop("headers", {}))
        headers.pop("cookies", None)
        headers.setdefault("x-csrf-token", self.cookies.get("sentinel_csrf", ""))
        headers.setdefault("Cookie", "; ".join(
            f"{k}={v}" for k, v in self.cookies.items()))
        return self.client.request(method, url, headers=headers, **kwargs)

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, json=None, **kw):
        return self.request("POST", url, json=json, **kw)

    def patch(self, url, json=None, **kw):
        return self.request("PATCH", url, json=json, **kw)

    def delete(self, url, **kw):
        return self.request("DELETE", url, **kw)


@pytest.fixture()
def client(lab_url):
    from app.main import create_app
    from fastapi.testclient import TestClient

    app = create_app()
    app.state.redis = None
    with TestClient(app, base_url="http://testserver") as c:
        c.lab_url = lab_url
        yield c


@pytest.fixture(autouse=True)
def _stub_celery_tasks(client, monkeypatch):
    from app.workers import tasks

    def _noop(_scan_id):
        return None

    def _do_send(disclosure_id):
        from app.core.db import SessionFactory
        from app.services.disclosure_exec import execute_disclosure_send
        db = SessionFactory()
        try:
            execute_disclosure_send(db, disclosure_id)
        finally:
            db.close()

    def _do_test(disclosure_id):
        from app.core.db import SessionFactory
        from app.services.disclosure_exec import execute_test_email
        db = SessionFactory()
        try:
            execute_test_email(db, disclosure_id)
        finally:
            db.close()

    class StubTask:
        def __init__(self, sync_fn):
            self.sync_fn = sync_fn or _noop

        def apply_async(self, args=None, task_id=None, **kw):
            self.sync_fn((args or [None])[0])
            return SimpleNamespace(id=task_id or "stub")

    monkeypatch.setattr(tasks, "scan_asset", StubTask(_noop))
    monkeypatch.setattr(tasks, "discover_contact", StubTask(_noop))
    monkeypatch.setattr(tasks, "send_disclosure", StubTask(_do_send))
    monkeypatch.setattr(tasks, "send_test_email", StubTask(_do_test))


def _pull_cookies(client, registration_response, email):
    cookies = {}
    for k in ("sentinel_session", "sentinel_csrf"):
        val = registration_response.cookies.get(k)
        if val:
            cookies[k] = val
    # remove session crumbs from the shared jar to avoid cross-user conflicts
    for key in ("sentinel_session", "sentinel_csrf"):
        try:
            del client.cookies[key]
        except KeyError:
            pass
    return Api(client, cookies, email=email)


@pytest.fixture()
def registered_user(client):
    import uuid

    email = f"{uuid.uuid4().hex[:10]}@example.com"
    r = client.post("/api/auth/register",
                    json={"email": email, "password": "Sup3rSecret!2026"})
    assert r.status_code == 201, r.text
    return _pull_cookies(client, r, email)


@pytest.fixture()
def api_user_a(client):
    import uuid

    email = f"a-{uuid.uuid4().hex[:10]}@example.com"
    r = client.post("/api/auth/register",
                    json={"email": email, "password": "Sup3rSecret!2026"})
    assert r.status_code == 201, r.text
    return _pull_cookies(client, r, email)


@pytest.fixture()
def api_user_b(client):
    import uuid

    email = f"b-{uuid.uuid4().hex[:10]}@example.com"
    r = client.post("/api/auth/register",
                    json={"email": email, "password": "Sup3rSecret!2026"})
    assert r.status_code == 201, r.text
    return _pull_cookies(client, r, email)


@pytest.fixture()
def asset_a(api_user_a, lab_url):
    r = api_user_a.post("/api/assets", json={
        "name": "lab-vuln", "url": lab_url,
        "description": "authorized local lab",
        "scan_interval_seconds": 86400, "monitoring_enabled": False,
        "authorization_confirmed": True,
    })
    assert r.status_code == 201, r.text
    return r.json()

