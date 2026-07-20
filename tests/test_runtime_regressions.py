import os
import queue
import signal
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, mock_open, patch

import grok_register_ttk as app


class RuntimeRegressionTests(unittest.TestCase):
    def test_gui_runtime_wiring_keeps_browser_in_background(self):
        with patch.object(app._bs, "configure") as configure_browser, patch.object(
            app._rf, "configure"
        ):
            app._wire_runtime_modules(gui_mode=True)
            gui_kwargs = configure_browser.call_args.kwargs
            app._wire_runtime_modules()
            cli_kwargs = configure_browser.call_args.kwargs

        self.assertTrue(gui_kwargs["keep_windows_background"])
        self.assertFalse(cli_kwargs["keep_windows_background"])

    def setUp(self):
        self.original_config = app.config.copy()

    def tearDown(self):
        app.config = self.original_config

    def test_empty_proxy_does_not_invent_local_cpa_proxy(self):
        app.config["proxy"] = ""
        empty_proxy_env = {
            "http_proxy": "",
            "HTTP_PROXY": "",
            "https_proxy": "",
            "HTTPS_PROXY": "",
        }
        with patch.dict(os.environ, empty_proxy_env, clear=False):
            self.assertEqual(app._resolve_cpa_proxy(), "")

    def test_gui_stop_first_click_sets_state_and_disables_button(self):
        gui = object.__new__(app.GrokRegisterGUI)
        gui.is_running = True
        gui.sso_convert_running = False
        gui.stop_requested = False
        gui.stop_btn = MagicMock()
        gui.status_var = MagicMock()
        gui.status_label = MagicMock()
        gui.close_browser_on_stop_var = MagicMock()
        gui.close_browser_on_stop_var.get.return_value = True
        logs = []
        gui.log = logs.append

        gui.stop_registration()
        gui.stop_registration()

        self.assertTrue(gui.stop_requested)
        gui.stop_btn.config.assert_called_once_with(state=app.tk.DISABLED)
        gui.status_var.set.assert_called_once_with("正在停止...")
        self.assertEqual(len(logs), 1)

    def test_gui_close_cancels_nsfw_and_forces_browser_cleanup(self):
        gui = object.__new__(app.GrokRegisterGUI)
        gui._closing = False
        gui.stop_requested = False
        gui.nsfw_retry_worker = MagicMock()
        gui.root = MagicMock()
        app.config["close_browser_on_stop"] = False

        gui._on_close()

        self.assertTrue(gui._closing)
        self.assertTrue(gui.stop_requested)
        self.assertTrue(app.config["close_browser_on_stop"])
        gui.nsfw_retry_worker.cancel.assert_called_once_with(wait=True, timeout=5.0)
        gui.root.destroy.assert_called_once_with()

    def test_gui_closing_drops_new_ui_queue_calls(self):
        gui = object.__new__(app.GrokRegisterGUI)
        gui._closing = True
        gui._ui_thread_id = threading.get_ident() + 1
        gui.ui_queue = queue.Queue()

        self.assertTrue(gui._queue_ui_call(lambda: None))
        self.assertTrue(gui.ui_queue.empty())

    def test_cancelled_cpa_conversion_does_not_start_or_append_pending(self):
        app.config["cpa_auto_add"] = True
        app.config["cpa_auth_dir"] = "auths"
        with patch.object(
            app._s2cpa,
            "sso_to_token",
            side_effect=AssertionError("cancelled CPA must not exchange tokens"),
        ), patch.object(app, "_append_sso_pending") as append_pending:
            self.assertFalse(
                app.add_sso_to_cpa(
                    "sso-token",
                    email="user@example.com",
                    should_stop=lambda: True,
                )
            )
        append_pending.assert_not_called()

    def test_parallel_browser_start_failure_counts_all_tasks(self):
        app.config["register_workers"] = 2
        app.config["enable_nsfw"] = False
        logs = []
        previous_handler = signal.getsignal(signal.SIGINT)
        try:
            with patch.object(app, "start_browser", side_effect=RuntimeError("boot failed")), patch.object(
                app, "cli_log", side_effect=logs.append
            ), patch.object(app, "maybe_stop_browser", return_value=None):
                app.run_registration_cli(2)
        finally:
            signal.signal(signal.SIGINT, previous_handler)

        self.assertTrue(any("成功 0 | 失败 2" in line for line in logs), logs)

    def test_gui_worker_log_is_drained_on_ui_thread(self):
        gui = object.__new__(app.GrokRegisterGUI)
        gui._ui_thread_id = threading.get_ident()
        gui.ui_queue = queue.Queue()
        gui.root = MagicMock()
        gui.log_text = MagicMock()

        worker = threading.Thread(target=gui.log, args=("worker message",))
        worker.start()
        worker.join()

        gui.log_text.insert.assert_not_called()
        gui._drain_ui_queue()
        gui.log_text.insert.assert_called_once()

    def test_account_write_failure_is_not_counted_as_success(self):
        gui = object.__new__(app.GrokRegisterGUI)
        gui.is_running = True
        gui.stop_requested = False
        gui.success_count = 0
        gui.fail_count = 0
        gui.fail_stats = app.empty_fail_stats()
        gui.results = []
        gui.accounts_output_file = "unwritable.txt"
        gui._stats_lock = threading.Lock()
        gui._accounts_lock = threading.Lock()
        gui.log = lambda message: None
        gui.update_stats = lambda: None

        with patch.object(app, "start_browser", return_value=(object(), object())), patch.object(
            app, "open_signup_page", return_value=None
        ), patch.object(app, "fill_email_and_submit", return_value=("a@example.com", "mail-token")), patch.object(
            app, "fill_code_and_submit", return_value="ABC-123"
        ), patch.object(
            app,
            "fill_profile_and_submit",
            return_value={"given_name": "A", "family_name": "B", "password": "secret"},
        ), patch.object(app, "wait_for_sso_cookie", return_value="sso-token"), patch.object(
            app, "maybe_stop_browser", return_value=None
        ), patch.object(app, "stop_browser", return_value=None), patch.object(
            app, "add_sso_to_cpa"
        ) as add_to_cpa, patch.object(app, "_append_sso_pending") as append_pending, patch(
            "builtins.open", side_effect=OSError("disk full")
        ):
            app.config["enable_nsfw"] = False
            gui.run_registration(1)

        self.assertEqual(gui.success_count, 0)
        self.assertEqual(gui.fail_count, 1)
        self.assertEqual(gui.results, [])
        add_to_cpa.assert_not_called()
        append_pending.assert_called_once()
        self.assertEqual(append_pending.call_args.args, ("a@example.com", "sso-token"))

    def test_gui_nsfw_queue_error_does_not_block_success_or_cpa(self):
        gui = object.__new__(app.GrokRegisterGUI)
        gui.is_running = True
        gui.stop_requested = False
        gui.success_count = 0
        gui.fail_count = 0
        gui.fail_stats = app.empty_fail_stats()
        gui.results = []
        gui._stats_lock = threading.Lock()
        gui._accounts_lock = threading.Lock()
        gui.nsfw_retry_worker = MagicMock()
        gui.nsfw_retry_worker.submit.side_effect = OSError("pending busy")
        gui.log = lambda message: None
        gui.update_stats = lambda: None

        with tempfile.TemporaryDirectory() as tmp:
            gui.accounts_output_file = os.path.join(tmp, "accounts.txt")
            with patch.object(app, "start_browser", return_value=(object(), object())), patch.object(
                app, "open_signup_page", return_value=None
            ), patch.object(app, "fill_email_and_submit", return_value=("a@example.com", "mail-token")), patch.object(
                app, "fill_code_and_submit", return_value="ABC-123"
            ), patch.object(
                app,
                "fill_profile_and_submit",
                return_value={"given_name": "A", "family_name": "B", "password": "secret"},
            ), patch.object(app, "wait_for_sso_cookie", return_value="sso-token"), patch.object(
                app, "maybe_stop_browser", return_value=None
            ), patch.object(app, "add_sso_to_cpa", return_value=True) as add_to_cpa, patch.object(
                app,
                "enable_nsfw_for_token",
                side_effect=AssertionError("registration worker must not enable NSFW synchronously"),
            ):
                app.config["enable_nsfw"] = True
                gui.run_registration(1)

        self.assertEqual(gui.success_count, 1)
        self.assertEqual(gui.fail_count, 0)
        gui.nsfw_retry_worker.submit.assert_called_once_with("a@example.com", "sso-token")
        add_to_cpa.assert_called_once()

    def test_gui_marks_batch_done_only_after_nsfw_finish(self):
        gui = object.__new__(app.GrokRegisterGUI)
        gui.stop_requested = False
        gui.success_count = 1
        gui.fail_count = 0
        gui.fail_stats = app.empty_fail_stats()
        gui.nsfw_retry_worker = MagicMock()
        gui.nsfw_retry_worker.pending_tasks.return_value = 1
        gui.nsfw_retry_worker.finish.return_value = {
            "submitted": 1,
            "attempted": 1,
            "succeeded": 1,
            "failed": 0,
            "cancelled": 0,
            "completed": True,
        }
        order = []
        gui.log = lambda message: order.append("log")
        gui.run_registration = lambda count, worker_id=0, workers=1: order.append("registration")
        gui._set_running_ui = lambda running: order.append(f"ui:{running}")
        gui.nsfw_retry_worker.finish.side_effect = lambda: (
            order.append("nsfw"),
            {
                "submitted": 1,
                "attempted": 1,
                "succeeded": 1,
                "failed": 0,
                "cancelled": 0,
                "completed": True,
            },
        )[1]

        gui._run_registration_entry(1, 1)

        self.assertLess(order.index("registration"), order.index("nsfw"))
        self.assertLess(order.index("nsfw"), order.index("ui:False"))

    def test_cli_single_registration_uses_batch_nsfw_worker(self):
        worker = MagicMock()
        worker.submit.return_value = True
        worker.pending_tasks.return_value = 1
        worker.finish.return_value = {
            "submitted": 1,
            "attempted": 1,
            "succeeded": 1,
            "failed": 0,
            "cancelled": 0,
            "completed": True,
        }
        app.config["register_workers"] = 1
        app.config["enable_nsfw"] = True
        previous_handler = signal.getsignal(signal.SIGINT)
        try:
            with patch.object(app, "create_nsfw_retry_worker", return_value=worker) as create_worker, patch.object(
                app, "start_browser", return_value=(object(), object())
            ), patch.object(app, "open_signup_page"), patch.object(
                app, "fill_email_and_submit", return_value=("a@example.com", "mail-token")
            ), patch.object(app, "fill_code_and_submit", return_value="ABC-123"), patch.object(
                app,
                "fill_profile_and_submit",
                return_value={"given_name": "A", "family_name": "B", "password": "secret"},
            ), patch.object(app, "wait_for_sso_cookie", return_value="sso-token"), patch.object(
                app, "add_sso_to_cpa", return_value=True
            ), patch.object(app, "maybe_stop_browser"), patch.object(
                app, "cleanup_runtime_memory"
            ), patch.object(app, "enable_nsfw_for_token", side_effect=AssertionError("sync NSFW")), patch(
                "builtins.open", mock_open()
            ):
                app.run_registration_cli(1)
        finally:
            signal.signal(signal.SIGINT, previous_handler)

        create_worker.assert_called_once()
        worker.submit.assert_called_once_with("a@example.com", "sso-token")
        worker.finish.assert_called_once_with()

    def test_cli_sigint_handler_only_sets_stop_until_main_flow_logs(self):
        app.config["register_workers"] = 1
        app.config["enable_nsfw"] = False
        logs = []
        registered = {}
        previous_handler = signal.getsignal(signal.SIGINT)

        def fake_signal(sig, handler):
            if sig == signal.SIGINT and callable(handler) and "handler" not in registered:
                registered["handler"] = handler
            return previous_handler

        def cancel_during_start(*args, **kwargs):
            before = len(logs)
            registered["handler"](signal.SIGINT, None)
            self.assertEqual(len(logs), before)
            self.assertTrue(kwargs["cancel_callback"]())
            raise RuntimeError("用户已停止")

        with patch.object(app.signal, "signal", side_effect=fake_signal), patch.object(
            app, "start_browser", side_effect=cancel_during_start
        ), patch.object(app, "cli_log", side_effect=logs.append), patch.object(
            app, "cleanup_runtime_memory"
        ):
            app.run_registration_cli(1)

        self.assertTrue(any("收到 Ctrl+C" in line for line in logs), logs)

    def test_cli_parallel_registration_shares_one_nsfw_worker(self):
        worker = MagicMock()
        worker.submit.return_value = True
        worker.pending_tasks.return_value = 2
        worker.finish.return_value = {
            "submitted": 2,
            "attempted": 2,
            "succeeded": 2,
            "failed": 0,
            "cancelled": 0,
            "completed": True,
        }
        app.config["register_workers"] = 2
        app.config["enable_nsfw"] = True
        previous_handler = signal.getsignal(signal.SIGINT)
        try:
            with patch.object(app, "create_nsfw_retry_worker", return_value=worker) as create_worker, patch.object(
                app, "start_browser", return_value=(object(), object())
            ), patch.object(app, "open_signup_page"), patch.object(
                app, "fill_email_and_submit", return_value=("a@example.com", "mail-token")
            ), patch.object(app, "fill_code_and_submit", return_value="ABC-123"), patch.object(
                app,
                "fill_profile_and_submit",
                return_value={"given_name": "A", "family_name": "B", "password": "secret"},
            ), patch.object(app, "wait_for_sso_cookie", return_value="sso-token"), patch.object(
                app, "add_sso_to_cpa", return_value=True
            ), patch.object(app, "maybe_stop_browser"), patch.object(
                app, "stop_browser"
            ), patch.object(app, "enable_nsfw_for_token", side_effect=AssertionError("sync NSFW")), patch(
                "builtins.open", mock_open()
            ):
                app.run_registration_cli(2)
        finally:
            signal.signal(signal.SIGINT, previous_handler)

        create_worker.assert_called_once()
        self.assertEqual(worker.submit.call_count, 2)
        worker.finish.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
