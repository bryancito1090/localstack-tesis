"""Contrato HTTP y eventos que consume el detector, sin AWS ni dependencias."""

import http.client
from http.server import HTTPServer
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]


class PortalTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = Path(self.tmp.name) / "app.log"
        self.secret = Path(self.tmp.name) / "session_secret"
        self.secret.write_bytes(b"local-test-session-value")
        from unittest.mock import patch

        env = patch.dict(
            os.environ,
            {
                "PORTAL_LOG_FILE": str(self.log),
                "PORTAL_SESSION_SECRET_FILE": str(self.secret),
                "PORTAL_ASSET_NAME": "custom-portal-ec2",
            },
        )
        env.start()
        self.addCleanup(env.stop)
        spec = importlib.util.spec_from_file_location(
            "portal_app", ROOT / "ansible/roles/portal_app/files/app.py"
        )
        self.app = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.app)
        self.server = HTTPServer(("127.0.0.1", 0), self.app.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        try:
            conn.request(method, path, body, headers or {})
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            conn.close()

    def test_health_and_private_dashboard(self):
        status, _, data = self.request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["status"], "ok")
        status, headers, _ = self.request("GET", "/dashboard")
        self.assertEqual(status, 302)
        self.assertEqual(headers["Location"], "/login")

    def test_five_failures_lock_account_and_preserve_detector_contract(self):
        password = "incorrect-test-password"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Forwarded-For": "198.51.100.8",
        }
        for _ in range(5):
            self.request(
                "POST",
                "/login",
                urlencode({"username": "admin.demo", "password": password}),
                headers,
            )
        self.request(
            "POST",
            "/login",
            urlencode({"username": "admin.demo", "password": password}),
            headers,
        )
        events = [json.loads(line) for line in self.log.read_text().splitlines()]
        failed = [event for event in events if event["event_type"] == "login_failed"]
        self.assertEqual(len(failed), 5)
        self.assertEqual(failed[-1]["failed_attempts"], 5)
        self.assertEqual(failed[-1]["severity"], "HIGH")
        self.assertEqual(events[-1]["event_type"], "access_blocked")
        for event in events:
            self.assertEqual(event["sourceIPAddress"], "198.51.100.8")
            self.assertEqual(event["asset_name"], "custom-portal-ec2")
            self.assertIn("timestamp_utc", event)
            self.assertNotIn("password", event)
        self.assertNotIn(password, self.log.read_text())

    def test_valid_login_signed_session_and_tamper_rejection(self):
        import base64
        import hashlib

        salt = b"test-salt"
        digest = hashlib.pbkdf2_hmac("sha256", b"correct-test-password", salt, 120000)
        self.app.USERS["test.demo"] = {
            "display": "Test",
            "hash": base64.b64encode(salt).decode()
            + ":"
            + base64.b64encode(digest).decode(),
        }
        status, headers, _ = self.request(
            "POST",
            "/login",
            urlencode({"username": "test.demo", "password": "correct-test-password"}),
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 302)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        self.assertEqual(
            self.request("GET", "/dashboard", headers={"Cookie": cookie})[0], 200
        )
        self.assertEqual(
            self.request("GET", "/dashboard", headers={"Cookie": cookie + "tampered"})[
                0
            ],
            302,
        )
        self.assertEqual(self.secret.read_bytes(), b"local-test-session-value")
        self.assertEqual(
            json.loads(self.log.read_text().splitlines()[0])["event_type"],
            "login_success",
        )

    def test_metrics_and_telemetry_endpoint(self):
        status, headers, data = self.request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertIn("x-response-time", {k.lower(): v for k, v in headers.items()})
        health_json = json.loads(data)
        self.assertEqual(health_json["status"], "ok")
        self.assertIn("uptime_seconds", health_json)
        self.assertIn("version", health_json)

        # /api/metrics sin autenticar desde IP externa devuelve 401
        ext_headers = {"X-Forwarded-For": "203.0.113.50"}
        status, _, _ = self.request("GET", "/api/metrics", headers=ext_headers)
        self.assertEqual(status, 401)

        # /api/metrics desde loopback devuelve 200 con telemetría completa
        status, _, data = self.request("GET", "/api/metrics")
        self.assertEqual(status, 200)
        metrics = json.loads(data)
        self.assertIn("latency", metrics)
        self.assertIn("requests", metrics)
        self.assertIn("uptime", metrics)
        self.assertIn("system", metrics)
        self.assertIn("audit", metrics)

    def test_light_mode_and_zero_emojis_in_rendered_html(self):
        import re

        status, _, data = self.request("GET", "/login")
        self.assertEqual(status, 200)
        html_login = data.decode("utf-8")
        self.assertIn("data-theme", html_login)
        self.assertIn("btn-theme", html_login)
        self.assertIn("<svg", html_login)

        # Verificar ausencia total de emojis en login
        login_emojis = re.findall(
            r"[\U00010000-\U0010ffff\u2600-\u27bf\u2300-\u23ff]", html_login
        )
        self.assertEqual(login_emojis, [])

        # Verificar dashboard renderizado y ausencia total de emojis
        cookie = self.app.sign_value(f"admin.demo:{self.app.epoch_now()}")
        headers = {"Cookie": f"portal_session={cookie}"}
        status, _, data = self.request("GET", "/dashboard", headers=headers)
        self.assertEqual(status, 200)
        html_dash = data.decode("utf-8")
        self.assertIn("btn-theme", html_dash)
        self.assertIn("data-theme", html_dash)
        self.assertIn("<svg", html_dash)
        dash_emojis = re.findall(
            r"[\U00010000-\U0010ffff\u2600-\u27bf\u2300-\u23ff]", html_dash
        )
        self.assertEqual(dash_emojis, [])
