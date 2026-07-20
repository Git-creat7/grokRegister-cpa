import unittest
import unittest.mock

import connectivity


class DummyResp:
    def __init__(self, status_code=200, text="ok"):
        self.status_code = status_code
        self.text = text


class ConnectivityTests(unittest.TestCase):
    def test_proxy_empty_is_ok(self):
        name, ok, detail = connectivity.check_proxy("", lambda *a, **k: DummyResp())
        self.assertTrue(ok)
        self.assertIn("未配置", detail)

    def test_cpa_disabled_skips(self):
        name, ok, detail = connectivity.check_cpa(
            {"cpa_auto_add": False}, lambda *a, **k: DummyResp()
        )
        self.assertTrue(ok)
        self.assertIn("未开启", detail)

    def test_cpa_enabled_needs_target(self):
        name, ok, detail = connectivity.check_cpa(
            {"cpa_auto_add": True, "cpa_auth_dir": "", "cpa_remote_url": ""},
            lambda *a, **k: DummyResp(),
        )
        self.assertFalse(ok)

    def test_email_cloudflare_missing_base(self):
        name, ok, detail = connectivity.check_email_api(
            "cloudflare",
            {},
            lambda *a, **k: DummyResp(),
            lambda *a, **k: DummyResp(),
        )
        self.assertFalse(ok)

    def test_email_cloudflare_ok(self):
        name, ok, detail = connectivity.check_email_api(
            "cloudflare",
            {"cloudflare_api_base": "https://mail.example.com"},
            lambda *a, **k: DummyResp(200),
            lambda *a, **k: DummyResp(),
        )
        self.assertTrue(ok)
        self.assertIn("200", detail)

    def test_email_cloudflare_unauthorized_is_failure(self):
        def fake_get(url, **kwargs):
            return DummyResp(401)

        name, ok, detail = connectivity.check_email_api(
            "cloudflare",
            {
                "cloudflare_api_base": "https://mail.example.com",
                "cloudflare_api_key": "bad-secret",
                "cloudflare_auth_mode": "x-api-key",
                "cloudflare_path_accounts": "/admin/new_address",
            },
            fake_get,
            lambda *a, **k: DummyResp(),
        )
        self.assertFalse(ok)
        self.assertIn("401", detail)
        self.assertIn("open_api/settings", detail)

    def test_email_cloudflare_domains_401_but_open_api_ok(self):
        def fake_get(url, **kwargs):
            if url.endswith("/open_api/settings"):
                return DummyResp(200)
            return DummyResp(401)

        name, ok, detail = connectivity.check_email_api(
            "cloudflare",
            {
                "cloudflare_api_base": "https://mail.example.com",
                "cloudflare_custom_auth": "global-pass",
                "cloudflare_auth_mode": "x-admin-auth",
                "cloudflare_api_key": "admin",
                "cloudflare_path_accounts": "/admin/new_address",
            },
            fake_get,
            lambda *a, **k: DummyResp(),
        )
        self.assertTrue(ok)
        self.assertIn("open_api/settings", detail)

    def test_email_cloudflare_direct_create_with_custom_auth_does_not_need_domains(
        self,
    ):
        name, ok, detail = connectivity.check_email_api(
            "cloudflare",
            {
                "cloudflare_api_base": "https://mail.example.com",
                "cloudflare_auth_mode": "none",
                "cloudflare_custom_auth": "global-secret",
                "cloudflare_path_accounts": "/api/new_address",
            },
            lambda *a, **k: DummyResp(401),
            lambda *a, **k: DummyResp(),
        )
        self.assertTrue(ok)
        self.assertIn("直建模式", detail)

    def test_email_cloudflare_uses_configured_auth(self):
        captured = {}

        def fake_get(url, **kwargs):
            captured.update(kwargs)
            return DummyResp(200)

        _, ok, _ = connectivity.check_email_api(
            "cloudflare",
            {
                "cloudflare_api_base": "https://mail.example.com",
                "cloudflare_api_key": "secret",
                "cloudflare_auth_mode": "x-api-key",
                "cloudflare_custom_auth": "global-secret",
            },
            fake_get,
            lambda *a, **k: DummyResp(),
        )
        self.assertTrue(ok)
        self.assertEqual(captured["headers"]["X-API-Key"], "secret")
        self.assertEqual(captured["headers"]["x-custom-auth"], "global-secret")

    def test_cpa_remote_uses_proxy_when_configured(self):
        captured = {}

        def fake_get(url, **kwargs):
            captured.update(kwargs)
            return DummyResp(200, '{"files":[]}')

        name, ok, detail = connectivity.check_cpa(
            {
                "cpa_auto_add": True,
                "cpa_remote_url": "https://2api.example.com",
                "cpa_management_key": "secret",
                "proxy": "http://127.0.0.1:10808",
            },
            fake_get,
        )
        self.assertTrue(ok)
        self.assertEqual(
            captured.get("proxies"),
            {"http": "http://127.0.0.1:10808", "https": "http://127.0.0.1:10808"},
        )
        self.assertIn("via proxy", detail)

    def test_cpa_local_remote_ignores_proxy(self):
        captured = {}

        def fake_get(url, **kwargs):
            captured.update(kwargs)
            return DummyResp(200, '{"files":[]}')

        with unittest.mock.patch.object(connectivity, "_tcp_open", return_value=True):
            name, ok, detail = connectivity.check_cpa(
                {
                    "cpa_auto_add": True,
                    "cpa_remote_url": "http://127.0.0.1:8317",
                    "cpa_management_key": "secret",
                    "proxy": "http://127.0.0.1:10808",
                },
                fake_get,
            )
        self.assertTrue(ok)
        self.assertEqual(captured.get("proxies"), {})
        self.assertIn("direct", detail)

    def test_proxies_for_cpa_host_policy(self):
        proxy = "http://127.0.0.1:10808"
        self.assertEqual(
            connectivity.proxies_for_cpa_host("2api.example.com", proxy),
            {"http": proxy, "https": proxy},
        )
        self.assertEqual(connectivity.proxies_for_cpa_host("127.0.0.1", proxy), {})
        self.assertEqual(connectivity.proxies_for_cpa_host("192.168.1.10", proxy), {})
        self.assertEqual(connectivity.proxies_for_cpa_host("10.0.0.5", proxy), {})
        self.assertEqual(connectivity.proxies_for_cpa_host("172.16.0.1", proxy), {})
        self.assertEqual(
            connectivity.proxies_for_cpa_host("172.32.0.1", proxy),
            {"http": proxy, "https": proxy},
        )

    def test_format_results(self):
        text = connectivity.format_check_results(
            [("代理", True, "ok"), ("CPA", False, "bad")]
        )
        self.assertIn("[OK] 代理", text)
        self.assertIn("[FAIL] CPA", text)


if __name__ == "__main__":
    unittest.main()
