import io
import json
import unittest
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import sso_to_auth_json as s2a


class ExtractNextActionTests(unittest.TestCase):
    def test_sso_to_token_honors_pre_cancel_without_network(self):
        with patch.object(
            s2a.requests,
            "Session",
            side_effect=AssertionError("cancelled conversion must not start a session"),
        ):
            self.assertIsNone(
                s2a.sso_to_token(
                    "valid-sso",
                    log=lambda message: None,
                    should_stop=lambda: True,
                )
            )

    def test_action_discovery_stops_between_chunks(self):
        class FakeResponse:
            text = 'createServerReference("4001401a617b1234567890123456789012345678", callServer)'

        class FakeSession:
            def __init__(self):
                self.urls = []

            def get(self, url, **kwargs):
                self.urls.append(url)
                return FakeResponse()

        session = FakeSession()
        html = "".join(
            f'<script src="/_next/static/chunks/{index}.js"></script>'
            for index in range(5)
        )
        s2a._discover_action_ids_from_js(
            session,
            html,
            should_stop=lambda: len(session.urls) >= 1,
        )
        self.assertEqual(len(session.urls), 1)

    def test_parse_sso_line_keeps_email_prefix(self):
        self.assertEqual(
            s2a.parse_sso_line("user@example.com----password----sso-value"),
            ("user@example.com", "sso-value"),
        )
        self.assertEqual(
            s2a.parse_sso_line("user@example.com----sso-value"),
            ("user@example.com", "sso-value"),
        )
        self.assertEqual(s2a.parse_sso_line("sso-value"), ("", "sso-value"))

    def test_collect_existing_auth_emails_ignores_invalid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "valid.json").write_text(
                '{"type":"xai","email":"user@example.com","access_token":"token"}',
                encoding="utf-8",
            )
            (root / "invalid.json").write_text("not json", encoding="utf-8")
            (root / "partial.json").write_text(
                '{"email":"retry@example.com"}', encoding="utf-8"
            )
            (root / "xai-legacy@example.com.json").write_text(
                '{"type":"xai","access_token":"token"}', encoding="utf-8"
            )

            self.assertEqual(
                s2a.collect_existing_auth_emails(out_dir=directory),
                {"user@example.com", "legacy@example.com"},
            )

    def test_batch_main_skips_existing_email_before_token_exchange(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "sso.txt"
            source.write_text(
                "user@example.com----password----sso-value\n", encoding="utf-8"
            )
            cpa_dir = root / "auths"
            cpa_dir.mkdir()
            (cpa_dir / "xai-user@example.com.json").write_text(
                '{"type":"xai","email":"user@example.com","access_token":"token"}',
                encoding="utf-8",
            )

            argv = [
                "sso_to_auth_json.py",
                "--sso",
                str(source),
                "--cpa-auth-dir",
                str(cpa_dir),
            ]
            with patch.object(sys, "argv", argv), patch.object(
                s2a,
                "sso_to_token",
                side_effect=AssertionError("existing account must be skipped"),
            ), patch.object(sys, "stdout", io.StringIO()):
                self.assertEqual(s2a.main(), 0)

    def test_auto_scan_uses_safe_files_and_keeps_latest_email(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "accounts_20260701_000000.txt").write_text(
                "user@example.com----old-password----old-sso\n", encoding="utf-8"
            )
            (root / "accounts_20260702_000000.txt").write_text(
                "user@example.com----new-password----new-sso\n", encoding="utf-8"
            )
            (root / "sso_pending.txt").write_text(
                "pending@example.com----pending-sso\n", encoding="utf-8"
            )
            (root / "requirements.txt").write_text("not-an-sso\n", encoding="utf-8")

            entries, files = s2a.scan_sso_entries(root)

            self.assertEqual(len(files), 3)
            self.assertEqual(
                dict(entries),
                {
                    "user@example.com": "new-sso",
                    "pending@example.com": "pending-sso",
                },
            )

    def test_auto_scan_main_loads_config_and_skips_existing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "accounts_20260701_000000.txt").write_text(
                "user@example.com----password----sso-value\n", encoding="utf-8"
            )
            cpa_dir = root / "auths"
            cpa_dir.mkdir()
            (cpa_dir / "xai-user@example.com.json").write_text(
                '{"type":"xai","email":"user@example.com","access_token":"token"}',
                encoding="utf-8",
            )
            (root / "config.json").write_text(
                json.dumps({"cpa_auth_dir": str(cpa_dir)}), encoding="utf-8"
            )

            argv = ["sso_to_auth_json.py", "--scan-dir", str(root)]
            with patch.object(sys, "argv", argv), patch.object(
                s2a,
                "sso_to_token",
                side_effect=AssertionError("existing account must be skipped"),
            ), patch.object(sys, "stdout", io.StringIO()):
                self.assertEqual(s2a.main(), 0)

    def test_collect_remote_auth_emails_supports_email_and_filename(self):
        response = MagicMock()
        response.json.return_value = {
            "files": [
                {"type": "xai", "email": "User@Example.com", "name": "record.json"},
                {"provider": "xai", "email": "", "name": "xai-legacy@example.com.json"},
                {"type": "openai", "email": "ignore@example.com", "name": "other.json"},
            ]
        }
        with patch("requests.get", return_value=response) as get:
            self.assertEqual(
                s2a.collect_remote_auth_emails("http://127.0.0.1:8317", "key"),
                {"user@example.com", "legacy@example.com"},
            )
        get.assert_called_once()
        response.raise_for_status.assert_called_once()

    def test_remote_cpa_is_authoritative_for_existing_email(self):
        logs = []
        with patch.object(
            s2a,
            "collect_existing_auth_emails",
            return_value=set(),
        ), patch.object(
            s2a,
            "collect_remote_auth_emails",
            return_value={"user@example.com"},
        ), patch.object(
            s2a,
            "sso_to_token",
            side_effect=AssertionError("remote existing account must be skipped"),
        ):
            result = s2a.convert_sso_entries(
                [("user@example.com", "sso-value")],
                cpa_auth_dir="local-auths",
                cpa_remote_url="http://127.0.0.1:8317",
                cpa_management_key="key",
                log=logs.append,
            )

        self.assertEqual(result["skipped"], 1)
        self.assertEqual(result["ok"], 0)

    def test_local_json_does_not_hide_remote_missing_email(self):
        token = {"access_token": "token", "expires_in": 21600}
        entry = {"user_id": "user-id", "email": "user@example.com", "key": "token"}
        with patch.object(
            s2a,
            "collect_existing_auth_emails",
            return_value={"user@example.com"},
        ), patch.object(
            s2a,
            "collect_remote_auth_emails",
            return_value=set(),
        ), patch.object(
            s2a,
            "sso_to_token",
            return_value=token,
        ) as exchange, patch.object(
            s2a,
            "token_to_auth_entry",
            return_value=("auth-key", entry),
        ), patch.object(
            s2a,
            "token_to_cpa_record",
            return_value={"email": "user@example.com", "access_token": "token"},
        ), patch.object(
            s2a,
            "write_cpa_auth",
            return_value=Path("xai-user@example.com.json"),
        ), patch.object(
            s2a,
            "upload_cpa_auth_remote",
            return_value="xai-user@example.com.json",
        ):
            result = s2a.convert_sso_entries(
                [("user@example.com", "sso-value")],
                cpa_auth_dir="local-auths",
                cpa_remote_url="http://127.0.0.1:8317",
                cpa_management_key="key",
                log=lambda message: None,
            )

        exchange.assert_called_once()
        self.assertEqual(result["ok"], 1)
        self.assertEqual(result["skipped"], 0)

    def test_extract_create_server_reference(self):
        html = 'createServerReference("401b73e22a5e68737d0037e1aa449fef82cd1b35fb", callServer)'
        ids = s2a._extract_next_action_ids(html)
        self.assertTrue(any(x.startswith("401b73e2") for x in ids))

    def test_fallback_includes_hardcoded(self):
        ids = s2a._extract_next_action_ids("")
        self.assertIn(s2a.NEXT_ACTION_ID.lower(), [x.lower() for x in ids])

    def test_parse_consent_code(self):
        body = (
            '0:{"a":"$@1"}\n'
            '1:{"success":true,"action":"allow","code":"abcXYZ123"}\n'
        )
        self.assertEqual(s2a._parse_consent_code(body), "abcXYZ123")

    def test_sso_to_token_uses_fast_action_without_scanning_chunks(self):
        class FakeCookies:
            def set(self, *args, **kwargs):
                return None

        class FakeResponse:
            def __init__(self, url, text="", status_code=200, payload=None):
                self.url = url
                self.text = text
                self.status_code = status_code
                self._payload = payload or {}

            def json(self):
                return self._payload

        class FakeSession:
            def __init__(self):
                self.cookies = FakeCookies()
                self.proxies = None
                self.posts = []

            def get(self, url, **kwargs):
                if url == "https://accounts.x.ai/":
                    return FakeResponse(url)
                return FakeResponse("https://accounts.x.ai/oauth2/consent?request=1")

            def post(self, url, **kwargs):
                self.posts.append((url, kwargs))
                if "/oauth2/token" in url:
                    return FakeResponse(
                        url,
                        payload={"access_token": "not-a-jwt", "expires_in": 21600},
                    )
                return FakeResponse(
                    url,
                    text='1:{"success":true,"code":"fast-code"}',
                )

        session = FakeSession()
        original_action = s2a._working_next_action_id
        s2a._working_next_action_id = s2a.NEXT_ACTION_ID
        try:
            with patch.object(s2a.requests, "Session", return_value=session), patch.object(
                s2a, "_discover_action_ids_from_js", side_effect=AssertionError("should not scan")
            ):
                token = s2a.sso_to_token("valid-sso", log=lambda message: None)
        finally:
            s2a._working_next_action_id = original_action

        self.assertIsNotNone(token)
        consent_headers = session.posts[0][1]["headers"]
        self.assertEqual(consent_headers["Next-Action"], s2a.NEXT_ACTION_ID)

    def test_upload_cpa_auth_remote_uses_proxy_for_public_host(self):
        captured = {}

        class FakeResp:
            status_code = 200
            text = "ok"
            reason = "OK"

        def fake_post(url, **kwargs):
            captured.update(kwargs)
            return FakeResp()

        with patch("requests.post", side_effect=fake_post):
            name = s2a.upload_cpa_auth_remote(
                "https://2api.example.com",
                "mgmt-key",
                {"email": "a@b.com", "access_token": "t"},
                proxy="http://127.0.0.1:10808",
            )
        self.assertTrue(name.endswith(".json"))
        self.assertEqual(
            captured.get("proxies"),
            {
                "http": "http://127.0.0.1:10808",
                "https": "http://127.0.0.1:10808",
            },
        )

    def test_upload_cpa_auth_remote_forces_direct_for_localhost(self):
        captured = {}

        class FakeResp:
            status_code = 200
            text = "ok"
            reason = "OK"

        def fake_post(url, **kwargs):
            captured.update(kwargs)
            return FakeResp()

        with patch("requests.post", side_effect=fake_post):
            s2a.upload_cpa_auth_remote(
                "http://127.0.0.1:8317",
                "mgmt-key",
                {"email": "a@b.com", "access_token": "t"},
                proxy="http://127.0.0.1:10808",
            )
        self.assertEqual(captured.get("proxies"), {})


if __name__ == "__main__":
    unittest.main()
