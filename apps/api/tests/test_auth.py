from __future__ import annotations


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
