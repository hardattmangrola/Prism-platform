import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestWebhookValidation:
    def test_rejects_non_http_scheme(self):
        from web.app import _validate_webhook_url
        with pytest.raises(ValueError):
            _validate_webhook_url("ftp://example.com/hook")

    def test_rejects_empty(self):
        from web.app import _validate_webhook_url
        with pytest.raises(ValueError):
            _validate_webhook_url("")

    def test_rejects_loopback(self, monkeypatch):
        from web.app import _validate_webhook_url
        monkeypatch.setattr("socket.gethostbyname", lambda h: "127.0.0.1")
        with pytest.raises(ValueError):
            _validate_webhook_url("http://localhost/hook")

    def test_rejects_private_ip(self, monkeypatch):
        from web.app import _validate_webhook_url
        monkeypatch.setattr("socket.gethostbyname", lambda h: "10.0.0.5")
        with pytest.raises(ValueError):
            _validate_webhook_url("http://internal.example/hook")

    def test_accepts_public_url(self, monkeypatch):
        from web import app as app_mod
        monkeypatch.setattr("socket.gethostbyname", lambda h: "93.184.216.34")
                                                                         
        monkeypatch.setattr(app_mod._requests, "head", lambda *a, **kw: (_ for _ in ()).throw(Exception("nope")))
        result = app_mod._validate_webhook_url("https://hooks.example.com/prism")
        assert result == "https://hooks.example.com/prism"


class TestWebhookDelivery:
    def test_sends_post_with_payload(self, monkeypatch):
        from web import app as app_mod
        captured = {}

        def fake_post(url, json=None, headers=None, timeout=None):
            captured["url"] = url
            captured["json"] = json
            captured["headers"] = headers

        monkeypatch.setattr(app_mod._requests, "post", fake_post)
        monkeypatch.setattr(app_mod, "WEBHOOK_SECRET", "shh")
        payload = {"scan_id": "abc", "status": "completed"}
        app_mod._send_webhook("https://hooks.example.com/prism", payload)

        assert captured["url"] == "https://hooks.example.com/prism"
        assert captured["json"] == payload
        assert captured["headers"]["X-Prism-Secret"] == "shh"
        assert captured["headers"]["Content-Type"] == "application/json"

    def test_swallows_post_errors(self, monkeypatch):
        from web import app as app_mod

        def boom(*a, **kw):
            raise RuntimeError("network down")

        monkeypatch.setattr(app_mod._requests, "post", boom)
                        
        app_mod._send_webhook("https://hooks.example.com/prism", {"x": 1})
