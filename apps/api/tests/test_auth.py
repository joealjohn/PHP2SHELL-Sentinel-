from __future__ import annotations

import pytest


@pytest.fixture
def bare_client(client, turn_off_cookies):
    return client


@pytest.fixture
def turn_off_cookies(client):
    saved = dict(client.cookies)
    for key in list(client.cookies):
        del client.cookies[key]
    yield
    for k, v in saved.items():
        client.cookies.set(k, v)


class TestAuth:
    def test_register_login_me(self, client):
        import uuid

        email = f"{uuid.uuid4().hex[:10]}@example.com"
        r = client.post("/api/auth/register",
                        json={"email": email, "password": "Sup3rSecret!2026"})
        assert r.status_code == 201, r.text
        assert "sentinel_session" in r.cookies
        me = client.get("/api/auth/me")
        assert me.status_code == 200
        assert me.json()["email"] == email

    def test_duplicate_email(self, client):
        r1 = client.post("/api/auth/register", json={
            "email": "dup@example.com", "password": "Sup3rSecret!2026"})
        assert r1.status_code == 201
        r2 = client.post("/api/auth/register", json={
            "email": "dup@example.com", "password": "Sup3rSecret!2026"})
        assert r2.status_code == 409

    def test_weak_password_rejected(self, client):
        r = client.post("/api/auth/register", json={
            "email": "weak@example.com", "password": "shortpass1"})
        assert r.status_code == 422

    def test_unauthenticated_401(self, bare_client):
        r = bare_client.get("/api/auth/me")
        assert r.status_code == 401
        body = r.json()
        assert body["error"]["code"] == "UNAUTHENTICATED"

    def test_logout_clears(self, client):
        import uuid

        email = f"{uuid.uuid4().hex[:10]}@example.com"
        client.post("/api/auth/register",
                    json={"email": email, "password": "Sup3rSecret!2026"})
        r = client.post("/api/auth/logout", headers={
            "x-csrf-token": client.cookies.get("sentinel_csrf")})
        assert r.status_code == 200
        saved = dict(client.cookies)
        for key in list(client.cookies):
            del client.cookies[key]
        assert client.get("/api/auth/me").status_code == 401
        for k, v in saved.items():
            client.cookies.set(k, v)


class TestCsrf:
    def test_writes_need_csrf(self, client, lab_url):
        import uuid

        email = f"{uuid.uuid4().hex[:10]}@example.com"
        client.post("/api/auth/register",
                    json={"email": email, "password": "Sup3rSecret!2026"})
        csrf = client.cookies.get("sentinel_csrf")
        r = client.post("/api/assets", json={"name": "x", "url": lab_url})
        assert r.status_code == 403
        r = client.post("/api/assets", json={"name": "x", "url": lab_url},
                        headers={"x-csrf-token": csrf})
        assert r.status_code == 201


class TestAuthorizationGate:
    def test_unconfirmed_asset_cannot_scan(self, api_user_a, lab_url):
        r = api_user_a.post("/api/assets", json={
            "name": "no-auth", "url": lab_url,
            "authorization_confirmed": False})
        assert r.status_code == 201, r.text
        asset = r.json()
        assert asset["authorization_confirmed"] is False
        assert asset["authorization_confirmed_at"] is None
        asset_id = asset["id"]

        s = api_user_a.post(f"/api/assets/{asset_id}/scan")
        assert s.status_code == 409, s.text
        assert s.json()["error"]["code"] == "AUTHORIZATION_REQUIRED"

        p = api_user_a.patch(f"/api/assets/{asset_id}",
                             json={"authorization_confirmed": True})
        assert p.status_code == 200, p.text
        assert p.json()["authorization_confirmed"] is True
        assert p.json()["authorization_confirmed_at"] is not None

    def test_confirmed_asset_scans(self, api_user_a, lab_url):
        r = api_user_a.post("/api/assets", json={
            "name": "with-auth", "url": lab_url,
            "authorization_confirmed": True})
        assert r.status_code == 201, r.text
        asset = r.json()
        assert asset["authorization_confirmed"] is True
        assert asset["authorization_confirmed_at"] is not None
        s = api_user_a.post(f"/api/assets/{asset['id']}/scan")
        assert s.status_code == 202, s.text


class TestSsrfGuards:
    def _public_only(self, monkeypatch):
        from types import SimpleNamespace

        import app.api.routers.assets as assets_mod

        fake = SimpleNamespace(allow_private_targets=False)
        monkeypatch.setattr(assets_mod, "get_settings", lambda: fake)

    def test_rejects_loopback(self, api_user_a, monkeypatch):
        self._public_only(monkeypatch)
        r = api_user_a.post("/api/assets", json={
            "name": "loopback", "url": "http://127.0.0.1:8080/"})
        assert r.status_code == 422
        assert r.json()["error"]["code"] in ("PRIVATE_TARGET", "SUSPICIOUS_HOST")

    def test_rejects_metadata_endpoint(self, api_user_a, monkeypatch):
        self._public_only(monkeypatch)
        r = api_user_a.post("/api/assets", json={
            "name": "metadata", "url": "http://169.254.169.254/latest/meta-data/"})
        assert r.status_code == 422
        assert r.json()["error"]["code"] == "METADATA_ENDPOINT"

    def test_rejects_decimal_host(self, api_user_a, monkeypatch):
        self._public_only(monkeypatch)
        r = api_user_a.post("/api/assets", json={
            "name": "dec", "url": "http://2130706433/"})
        assert r.status_code == 422

    def test_rejects_private_subnet(self, api_user_a, monkeypatch):
        self._public_only(monkeypatch)
        r = api_user_a.post("/api/assets", json={
            "name": "lan", "url": "http://10.1.2.3/"})
        assert r.status_code == 422

    def test_rejects_ipv6_loopback(self, api_user_a, monkeypatch):
        self._public_only(monkeypatch)
        r = api_user_a.post("/api/assets", json={
            "name": "v6", "url": "http://[::1]/"})
        assert r.status_code == 422

    def test_rejects_garbage(self, api_user_a, monkeypatch):
        self._public_only(monkeypatch)
        r = api_user_a.post("/api/assets", json={"name": "x", "url": "not a url"})
        assert r.status_code == 422
