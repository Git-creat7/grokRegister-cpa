import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import grok_register_ttk as app


class NsfwFlowTests(unittest.TestCase):
    def test_pre_cancel_skips_nsfw_network(self):
        with patch.object(
            app.requests,
            "Session",
            side_effect=AssertionError("cancelled NSFW must not start a session"),
        ):
            ok, message = app.enable_nsfw_for_token(
                "sso-token",
                cancel_callback=lambda: True,
            )
        self.assertFalse(ok)
        self.assertEqual(message, "用户已停止")

    def _session_context(self):
        session = MagicMock()
        session.headers = {}
        context = MagicMock()
        context.__enter__.return_value = session
        context.__exit__.return_value = False
        return context

    def test_http_success_skips_browser_and_clearance_scan(self):
        with patch.object(app.requests, "Session", return_value=self._session_context()), patch.object(
            app, "set_tos_accepted", return_value=(True, "ok")
        ), patch.object(app, "set_birth_date", return_value=(True, "ok")), patch.object(
            app, "update_nsfw_settings", return_value=(True, "ok")
        ), patch.object(app, "enable_nsfw_via_browser") as browser_fallback, patch.object(
            app, "extract_cf_clearance_and_ua"
        ) as clearance_scan:
            ok, message = app.enable_nsfw_for_token("sso-token")

        self.assertTrue(ok)
        self.assertIn("HTTP 快速路径", message)
        browser_fallback.assert_not_called()
        clearance_scan.assert_not_called()

    def test_cloudflare_failure_falls_back_to_browser(self):
        with patch.object(app.requests, "Session", return_value=self._session_context()), patch.object(
            app, "set_tos_accepted", return_value=(True, "ok")
        ), patch.object(
            app,
            "set_birth_date",
            return_value=(False, "set_birth_date 被 Cloudflare 拦截，HTTP 403"),
        ), patch.object(app, "_active_page", return_value=object()), patch.object(
            app,
            "enable_nsfw_via_browser",
            return_value=(True, "成功开启 NSFW（浏览器内）"),
        ) as browser_fallback, patch.object(app, "extract_cf_clearance_and_ua") as clearance_scan:
            ok, message = app.enable_nsfw_for_token("sso-token")

        self.assertTrue(ok)
        self.assertIn("浏览器内", message)
        browser_fallback.assert_called_once_with(
            token="sso-token",
            log_callback=None,
            cancel_callback=None,
        )
        clearance_scan.assert_not_called()

    def test_fast_only_failure_does_not_open_browser(self):
        with patch.object(app.requests, "Session", return_value=self._session_context()), patch.object(
            app,
            "set_tos_accepted",
            return_value=(False, "HTTP 403"),
        ) as set_tos, patch.object(app, "enable_nsfw_via_browser") as browser_fallback:
            ok, message = app.enable_nsfw_for_token(
                "sso-token",
                allow_browser_fallback=False,
                http_budget=8,
            )

        self.assertFalse(ok)
        self.assertEqual(message, "HTTP 403")
        self.assertLessEqual(set_tos.call_args.kwargs["timeout"], 8)
        browser_fallback.assert_not_called()

    def test_tos_only_skips_birth_and_settings_requests(self):
        with patch.object(app.requests, "Session", return_value=self._session_context()), patch.object(
            app, "set_tos_accepted", return_value=(True, "ok")
        ), patch.object(app, "set_birth_date") as set_birth, patch.object(
            app, "update_nsfw_settings"
        ) as update_nsfw:
            ok, message = app.enable_nsfw_for_token(
                "sso-token",
                allow_browser_fallback=False,
                tos_only=True,
            )

        self.assertTrue(ok)
        self.assertEqual(message, "TOS 已确认")
        set_birth.assert_not_called()
        update_nsfw.assert_not_called()

    def test_reused_browser_retries_cloudflare_failure(self):
        page = SimpleNamespace(url="about:blank")
        with patch.object(app, "_active_page", return_value=page), patch.object(
            app,
            "enable_nsfw_via_browser",
            side_effect=[(False, "CF HTTP 403"), (True, "ok")],
        ) as browser_enable:
            ok, message = app.enable_nsfw_with_reused_browser(
                "sso-token",
                log_callback=lambda _: None,
                attempts=2,
                retry_delay=0,
            )

        self.assertTrue(ok)
        self.assertEqual(message, "ok")
        self.assertEqual(browser_enable.call_count, 2)
        self.assertTrue(browser_enable.call_args_list[0].kwargs["navigate"])
        self.assertTrue(browser_enable.call_args_list[1].kwargs["navigate"])

    def test_reused_browser_skips_navigation_for_warm_grok_page(self):
        page = SimpleNamespace(url="https://grok.com/")
        with patch.object(app, "_active_page", return_value=page), patch.object(
            app,
            "enable_nsfw_via_browser",
            return_value=(True, "ok"),
        ) as browser_enable, patch.object(app, "start_browser") as start_browser:
            ok, message = app.enable_nsfw_with_reused_browser(
                "sso-token",
                log_callback=lambda _: None,
            )

        self.assertTrue(ok)
        self.assertEqual(message, "ok")
        self.assertFalse(browser_enable.call_args.kwargs["navigate"])
        start_browser.assert_not_called()

    def test_worker_http_only_by_default(self):
        """注册批内 worker 对齐初版：纯 HTTP，失败不冷启浏览器。"""
        with patch.object(
            app,
            "enable_nsfw_for_token",
            return_value=(False, "set_birth_date 被 Cloudflare 拦截，HTTP 403"),
        ) as http_enable, patch.object(
            app,
            "enable_nsfw_with_reused_browser",
        ) as browser_enable:
            worker = app.create_nsfw_retry_worker(log_callback=lambda _: None)
            ok, message = worker.retry_callback(
                "user@example.com",
                "sso-token",
                lambda: False,
            )

        self.assertFalse(ok)
        self.assertIn("Cloudflare", message)
        self.assertFalse(http_enable.call_args.kwargs["tos_only"])
        self.assertFalse(http_enable.call_args.kwargs["allow_browser_fallback"])
        browser_enable.assert_not_called()

    def test_worker_http_success_returns_ok(self):
        with patch.object(
            app,
            "enable_nsfw_for_token",
            return_value=(True, "成功开启 NSFW（HTTP 快速路径）"),
        ) as http_enable, patch.object(
            app,
            "enable_nsfw_with_reused_browser",
        ) as browser_enable:
            worker = app.create_nsfw_retry_worker(log_callback=lambda _: None)
            ok, message = worker.retry_callback(
                "user@example.com",
                "sso-token",
                lambda: False,
            )

        self.assertTrue(ok)
        self.assertIn("HTTP", message)
        browser_enable.assert_not_called()
        http_enable.assert_called_once()

    def test_worker_allow_browser_falls_back(self):
        with patch.object(
            app,
            "enable_nsfw_for_token",
            return_value=(False, "HTTP 403"),
        ), patch.object(
            app,
            "enable_nsfw_with_reused_browser",
            return_value=(True, "ok"),
        ) as browser_enable:
            worker = app.create_nsfw_retry_worker(
                log_callback=lambda _: None, allow_browser=True
            )
            ok, message = worker.retry_callback(
                "user@example.com",
                "sso-token",
                lambda: False,
            )

        self.assertTrue(ok)
        self.assertEqual(message, "ok")
        browser_enable.assert_called_once()


if __name__ == "__main__":
    unittest.main()
