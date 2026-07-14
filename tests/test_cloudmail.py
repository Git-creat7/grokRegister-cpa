import os
import unittest
from unittest.mock import call, patch

import grok_register_ttk as app


class DummyResponse:
    def __init__(self, payload, text=""):
        self._payload = payload
        self.text = text

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class CloudMailTests(unittest.TestCase):
    def setUp(self):
        self.original_config = app.config.copy()
        self.original_domain_index = app._cf_domain_index
        self.original_public_token = app._cloudmail_public_token
        self.original_public_token_config = app._cloudmail_public_token_config
        self.original_account_ids = app._cloudmail_account_ids.copy()
        self.env_patch = patch.dict(
            os.environ,
            {
                "CLOUDMAIL_URL": "",
                "CLOUDMAIL_ADMIN_EMAIL": "",
                "CLOUDMAIL_PASSWORD": "",
            },
        )
        self.env_patch.start()
        app.config = app.DEFAULT_CONFIG.copy()
        app._cf_domain_index = 0
        app._cloudmail_public_token = None
        app._cloudmail_public_token_config = None
        app._cloudmail_account_ids.clear()

    def tearDown(self):
        self.env_patch.stop()
        app.config = self.original_config
        app._cf_domain_index = self.original_domain_index
        app._cloudmail_public_token = self.original_public_token
        app._cloudmail_public_token_config = self.original_public_token_config
        app._cloudmail_account_ids.clear()
        app._cloudmail_account_ids.update(self.original_account_ids)

    def configure_cloudmail(self):
        app.config.update(
            {
                "email_provider": "cloudmail",
                "cloudmail_url": "https://mail.example.com/",
                "cloudmail_admin_email": "admin@example.com",
                "cloudmail_password": "admin-password",
                "defaultDomains": "first.example, second.example",
            }
        )

    def test_add_address_uses_raw_cloudmail_authorization_token(self):
        responses = [
            DummyResponse({"code": 200, "data": {"token": "admin-jwt"}}),
            DummyResponse({"code": 200, "data": {"accountId": 42}}),
        ]

        with patch.object(app, "http_post", side_effect=responses) as post:
            result = app.cloudmail_add_address(
                "https://mail.example.com",
                "admin@example.com",
                "admin-password",
                "new@first.example",
            )

        self.assertEqual(result, {"accountId": 42})
        self.assertEqual(
            post.call_args_list,
            [
                call(
                    "https://mail.example.com/api/login",
                    json={
                        "email": "admin@example.com",
                        "password": "admin-password",
                    },
                    headers={"Content-Type": "application/json"},
                ),
                call(
                    "https://mail.example.com/api/account/add",
                    json={"email": "new@first.example", "token": ""},
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": "admin-jwt",
                    },
                ),
            ],
        )

    def test_get_email_creates_address_and_tracks_account_id(self):
        self.configure_cloudmail()

        with patch.object(app, "generate_username", return_value="randomuser"), patch.object(
            app,
            "cloudmail_add_address",
            return_value={"accountId": 91},
        ) as add_address:
            address, token = app.get_email_and_token()

        self.assertEqual(address, "randomuser@first.example")
        self.assertEqual(token, "cloudmail_catch_all")
        self.assertEqual(app._cloudmail_account_ids[address], 91)
        add_address.assert_called_once_with(
            "https://mail.example.com",
            "admin@example.com",
            "admin-password",
            address,
        )

    def test_public_email_list_filters_by_full_address(self):
        captured = {}

        def fake_post(url, **kwargs):
            captured["url"] = url
            captured.update(kwargs)
            return DummyResponse(
                {"code": 200, "data": {"rows": [{"emailId": "mail-1"}]}}
            )

        with patch.object(app, "http_post", side_effect=fake_post):
            messages = app.cloudmail_public_email_list(
                "https://mail.example.com", "public-token", "user@first.example"
            )

        self.assertEqual(messages, [{"emailId": "mail-1"}])
        self.assertEqual(captured["url"], "https://mail.example.com/api/public/emailList")
        self.assertEqual(
            captured["json"], {"size": 20, "toEmail": "user@first.example"}
        )
        self.assertEqual(captured["headers"]["Authorization"], "public-token")

    def test_public_token_is_cached_until_cloudmail_config_changes(self):
        self.configure_cloudmail()
        with patch.object(
            app,
            "cloudmail_gen_public_token",
            side_effect=["first-token", "second-token"],
        ) as generate:
            self.assertEqual(app._cloudmail_get_shared_token(), "first-token")
            self.assertEqual(app._cloudmail_get_shared_token(), "first-token")
            app.config["cloudmail_password"] = "changed-password"
            self.assertEqual(app._cloudmail_get_shared_token(), "second-token")

        self.assertEqual(generate.call_count, 2)
        self.assertEqual(
            generate.call_args_list[1],
            call(
                "https://mail.example.com",
                "admin@example.com",
                "changed-password",
            ),
        )

    def test_code_polling_parses_html_and_cleans_up_address(self):
        self.configure_cloudmail()
        email = "randomuser@first.example"
        app._cloudmail_account_ids[email] = 91
        messages = [
            {
                "emailId": "mail-1",
                "subject": "Your xAI verification code",
                "content": "<p>Verification code: <strong>123456</strong></p>",
            }
        ]

        with patch.object(
            app, "_cloudmail_get_shared_token", return_value="public-token"
        ), patch.object(
            app, "cloudmail_public_email_list", return_value=messages
        ) as email_list, patch.object(
            app, "cloudmail_delete_address"
        ) as delete_address:
            code = app.cloudmail_get_oai_code(
                "ignored", email, timeout=1, poll_interval=0
            )

        self.assertEqual(code, "123456")
        email_list.assert_called_once_with(
            "https://mail.example.com", "public-token", to_email=email, size=20
        )
        delete_address.assert_called_once_with(
            "https://mail.example.com",
            "admin@example.com",
            "admin-password",
            91,
        )
        self.assertNotIn(email, app._cloudmail_account_ids)

    def test_dispatches_verification_lookup_to_cloudmail(self):
        app.config["email_provider"] = "cloudmail"
        with patch.object(app, "cloudmail_get_oai_code", return_value="ABC-123") as get_code:
            result = app.get_oai_code(
                "address-token",
                "user@example.com",
                timeout=10,
                poll_interval=1,
            )

        self.assertEqual(result, "ABC-123")
        get_code.assert_called_once_with(
            "address-token",
            "user@example.com",
            timeout=10,
            poll_interval=1,
            log_callback=None,
            cancel_callback=None,
            resend_callback=None,
        )


if __name__ == "__main__":
    unittest.main()
