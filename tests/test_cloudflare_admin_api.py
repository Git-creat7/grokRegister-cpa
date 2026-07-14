import tkinter as tk
import unittest
from unittest.mock import patch

import cf_mail_debug
import grok_register_ttk as app


class DummyResponse:
    def __init__(self, payload):
        self._payload = payload
        self.text = ""

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class CloudflareAdminCreateTests(unittest.TestCase):
    original_config = app.DEFAULT_CONFIG.copy()
    original_cf_domain_index = 0

    def setUp(self):
        self.original_config = app.config.copy()
        self.original_cf_domain_index = app._cf_domain_index
        app._cf_domain_index = 0

    def tearDown(self):
        app.config = self.original_config
        app._cf_domain_index = self.original_cf_domain_index

    def test_default_config_keeps_cloudflare_temp_email_new_address(self):
        app.config = app.DEFAULT_CONFIG.copy()
        captured = {}

        def fake_post(url, **kwargs):
            captured["url"] = url
            captured.update(kwargs)
            return DummyResponse({"address": "anon@example.com", "jwt": "default-jwt"})

        with patch.object(app, "http_post", side_effect=fake_post):
            address, jwt = app.cloudflare_create_temp_address("https://temp-mail.example.com")

        self.assertEqual(address, "anon@example.com")
        self.assertEqual(jwt, "default-jwt")
        self.assertEqual(captured["url"], "https://temp-mail.example.com/api/new_address")
        self.assertEqual(captured["json"], {})
        self.assertEqual(captured["headers"], {"Content-Type": "application/json"})

    def test_app_uses_admin_new_address_with_x_admin_auth(self):
        app.config.update({
            "cloudflare_api_key": "admin-secret",
            "cloudflare_auth_mode": "x-admin-auth",
            "cloudflare_path_accounts": "/admin/new_address",
            "defaultDomains": "vitassk.com",
        })
        captured = {}

        def fake_post(url, **kwargs):
            captured["url"] = url
            captured.update(kwargs)
            return DummyResponse({"address": "adminuser@vitassk.com", "jwt": "address-jwt"})

        with patch.object(app, "generate_username", return_value="adminuser"), \
                patch.object(app, "http_post", side_effect=fake_post):
            address, jwt = app.cloudflare_create_temp_address("https://temp-mail.ikun.day")

        self.assertEqual(address, "adminuser@vitassk.com")
        self.assertEqual(jwt, "address-jwt")
        self.assertEqual(captured["url"], "https://temp-mail.ikun.day/admin/new_address")
        self.assertEqual(captured["json"], {
            "name": "adminuser",
            "domain": "vitassk.com",
            "enablePrefix": True,
        })
        self.assertEqual(captured["headers"]["Content-Type"], "application/json")
        self.assertEqual(captured["headers"]["x-admin-auth"], "admin-secret")

    def test_app_keeps_anonymous_new_address_with_none_auth(self):
        app.config.update({
            "cloudflare_api_key": "",
            "cloudflare_auth_mode": "none",
            "cloudflare_custom_auth": "",
            "cloudflare_path_accounts": "/api/new_address",
            "defaultDomains": "vitassk.com",
        })
        captured = {}

        def fake_post(url, **kwargs):
            captured["url"] = url
            captured.update(kwargs)
            return DummyResponse({"address": "anon@vitassk.com", "jwt": "anon-jwt"})

        with patch.object(app, "http_post", side_effect=fake_post):
            address, jwt = app.cloudflare_create_temp_address("https://temp-mail.ikun.day")

        self.assertEqual(address, "anon@vitassk.com")
        self.assertEqual(jwt, "anon-jwt")
        self.assertEqual(captured["url"], "https://temp-mail.ikun.day/api/new_address")
        self.assertEqual(captured["json"], {"domain": "vitassk.com"})
        self.assertEqual(captured["headers"], {"Content-Type": "application/json"})

    def test_app_injects_custom_auth_on_anonymous_new_address(self):
        app.config.update({
            "cloudflare_api_key": "",
            "cloudflare_auth_mode": "none",
            "cloudflare_custom_auth": "global-pass",
            "cloudflare_path_accounts": "/api/new_address",
            "defaultDomains": "vitassk.com",
        })
        captured = {}

        def fake_post(url, **kwargs):
            captured["url"] = url
            captured.update(kwargs)
            return DummyResponse({"address": "anon@vitassk.com", "jwt": "anon-jwt"})

        with patch.object(app, "http_post", side_effect=fake_post):
            app.cloudflare_create_temp_address("https://temp-mail.ikun.day")

        self.assertEqual(captured["headers"], {
            "Content-Type": "application/json",
            "x-custom-auth": "global-pass",
        })

    def test_debug_tool_can_create_address_through_admin_api(self):
        captured = {}

        def fake_post(url, **kwargs):
            captured["url"] = url
            captured.update(kwargs)
            return DummyResponse({"address": "debuguser@vitassk.com", "jwt": "debug-jwt"})

        with patch.object(cf_mail_debug.requests, "post", side_effect=fake_post):
            address, jwt = cf_mail_debug.create_address(
                "https://temp-mail.ikun.day",
                auth_mode="x-admin-auth",
                api_key="admin-secret",
                create_path="/admin/new_address",
                domain="vitassk.com",
                name="debuguser",
            )

        self.assertEqual(address, "debuguser@vitassk.com")
        self.assertEqual(jwt, "debug-jwt")
        self.assertEqual(captured["url"], "https://temp-mail.ikun.day/admin/new_address")
        self.assertEqual(captured["json"], {
            "name": "debuguser",
            "domain": "vitassk.com",
            "enablePrefix": True,
        })
        self.assertEqual(captured["headers"]["Content-Type"], "application/json")
        self.assertEqual(captured["headers"]["x-admin-auth"], "admin-secret")

    def test_gui_loads_cloudflare_default_domain_from_config(self):
        app.config["defaultDomains"] = "mail.example.com"
        try:
            root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(f"Tk display unavailable: {exc}")
        root.withdraw()
        try:
            with patch.object(app, "load_config", return_value=app.config):
                gui = app.GrokRegisterGUI(root)

            self.assertEqual(gui.default_domains_var.get(), "mail.example.com")
        finally:
            root.destroy()

    def test_yyds_uses_configured_default_domain(self):
        app.config.update({
            "yyds_api_key": "api-key",
            "yyds_jwt": "",
            "yyds_default_domain": "mail.example.com",
        })
        captured = {}

        def fake_post(url, **kwargs):
            captured["url"] = url
            captured.update(kwargs)
            return DummyResponse({
                "success": True,
                "data": {"address": "abc123@mail.example.com", "token": "temp-token"},
            })

        with patch.object(app, "yyds_generate_username", return_value="abc123"), \
                patch.object(app, "http_post", side_effect=fake_post), \
                patch.object(app, "yyds_pick_domain") as pick_domain:
            address, token = app.yyds_get_email_and_token()

        self.assertEqual(address, "abc123@mail.example.com")
        self.assertEqual(token, "temp-token")
        self.assertEqual(captured["url"], "https://maliapi.215.im/v1/accounts")
        self.assertEqual(captured["json"], {
            "localPart": "abc123",
            "domain": "mail.example.com",
        })
        pick_domain.assert_not_called()

    def test_yyds_empty_default_domain_keeps_auto_pick(self):
        app.config.update({
            "yyds_api_key": "api-key",
            "yyds_jwt": "",
            "yyds_default_domain": "",
        })
        captured = {}

        def fake_post(url, **kwargs):
            captured.update(kwargs)
            return DummyResponse({
                "success": True,
                "data": {"address": "abc123@auto.example.com", "token": "temp-token"},
            })

        with patch.object(app, "yyds_generate_username", return_value="abc123"), \
                patch.object(app, "yyds_pick_domain", return_value="auto.example.com"), \
                patch.object(app, "http_post", side_effect=fake_post):
            address, token = app.yyds_get_email_and_token()

        self.assertEqual(address, "abc123@auto.example.com")
        self.assertEqual(token, "temp-token")
        self.assertEqual(captured["json"], {
            "localPart": "abc123",
            "domain": "auto.example.com",
        })

    def test_gui_loads_yyds_default_domain_from_config(self):
        app.config["yyds_default_domain"] = "mail.example.com"
        try:
            root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(f"Tk display unavailable: {exc}")
        root.withdraw()
        try:
            with patch.object(app, "load_config", return_value=app.config):
                gui = app.GrokRegisterGUI(root)

            self.assertEqual(gui.yyds_default_domain_var.get(), "mail.example.com")
        finally:
            root.destroy()


if __name__ == "__main__":
    unittest.main()
