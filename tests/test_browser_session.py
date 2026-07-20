import os
import tempfile
import unittest
from unittest.mock import ANY, MagicMock, patch

import browser_session as bs


class BrowserSessionTests(unittest.TestCase):
    def setUp(self):
        bs.configure(
            get_proxies=lambda: {},
            extension_path="",
            keep_windows_background=False,
        )
        bs.set_browser_session(None, None)

    def test_create_options_unique_profile(self):
        opts = bs.create_browser_options(unique_profile=True)
        self.assertIsNotNone(opts)
        profile = getattr(bs._tls, "profile_dir", "")
        self.assertTrue(profile)
        self.assertTrue(os.path.isdir(profile))
        self.assertIn("grok-register-chrome", profile.replace("\\", "/"))
        # set_user_data_path 不能搭配 auto_port；必须有 host:port 形式 address
        self.assertIn(":", str(getattr(opts, "address", "") or ""))

    def test_create_options_applies_configured_proxy(self):
        proxy = "http://127.0.0.1:9999"
        bs.configure(
            get_proxies=lambda: {"http": proxy, "https": proxy},
            extension_path="",
        )
        opts = bs.create_browser_options(unique_profile=False)
        self.assertEqual(getattr(opts, "proxy", ""), proxy)

    def test_session_proxy_bool(self):
        self.assertFalse(bool(bs.browser))
        self.assertFalse(bool(bs.page))
        fake_b, fake_p = object(), object()
        bs.set_browser_session(fake_b, fake_p)
        self.assertTrue(bool(bs.browser))
        self.assertTrue(bool(bs.page))
        bs.set_browser_session(None, None)
        self.assertFalse(bool(bs.browser))

    def test_start_fail_streak(self):
        before = bs.get_start_fail_streak()
        with patch.object(bs, "Chromium", side_effect=RuntimeError("boom")):
            with self.assertRaises(Exception):
                bs.start_browser(log_callback=None)
        self.assertGreaterEqual(bs.get_start_fail_streak(), before + 1)

    def test_start_browser_honors_pre_cancel(self):
        with patch.object(bs, "Chromium") as chromium:
            with self.assertRaisesRegex(RuntimeError, "用户已停止"):
                bs.start_browser(cancel_callback=lambda: True)
        chromium.assert_not_called()

    def test_start_browser_stops_retrying_after_cancel(self):
        cancelled = False

        def fail_once(options):
            nonlocal cancelled
            cancelled = True
            raise RuntimeError("boom")

        with patch.object(bs, "Chromium", side_effect=fail_once) as chromium:
            with self.assertRaisesRegex(RuntimeError, "用户已停止"):
                bs.start_browser(cancel_callback=lambda: cancelled)

        chromium.assert_called_once()

    def test_stop_browser_always_quits(self):
        mock_browser = MagicMock()
        bs.set_browser_session(mock_browser, object())
        bs.stop_browser()
        mock_browser.quit.assert_called_once()

    def test_start_browser_backgrounds_window_when_enabled(self):
        bs.configure(
            get_proxies=lambda: {},
            extension_path="",
            keep_windows_background=True,
        )
        mock_browser = MagicMock()
        mock_page = object()
        mock_browser.get_tabs.return_value = [mock_page]
        with patch.object(bs, "Chromium", return_value=mock_browser), patch.object(
            bs, "_start_background_guard"
        ) as start_guard:
            browser, page = bs.start_browser()

        self.assertIs(browser, mock_browser)
        self.assertIs(page, mock_page)
        start_guard.assert_called_once_with(
            mock_browser,
            previous_foreground=ANY,
            log_callback=None,
        )
        bs.stop_browser()


if __name__ == "__main__":
    unittest.main()
