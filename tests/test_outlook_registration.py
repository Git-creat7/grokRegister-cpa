import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import ANY, MagicMock, patch

import grok_register_ttk as app


class OutlookRegistrationTests(unittest.TestCase):
    def setUp(self):
        self.original_config = app.config.copy()
        app._clear_outlook_batch_runtime()

    def tearDown(self):
        app._clear_outlook_batch_runtime()
        app.config = self.original_config

    def _accounts_file(self, directory, count=1):
        path = Path(directory) / "accounts.json"
        path.write_text(
            json.dumps(
                [
                    {
                        "email": f"user-{index}@outlook.com",
                        "client_id": f"client-{index}",
                        "refresh_token": f"refresh-{index}",
                    }
                    for index in range(count)
                ]
            ),
            encoding="utf-8",
        )
        return path

    def _configure(self, path):
        app.config = app.DEFAULT_CONFIG.copy()
        app.config.update(
            {
                "email_provider": "outlook",
                "outlook_accounts_file": str(path),
                "proxy": "",
                "enable_nsfw": False,
                "cpa_auto_add": False,
            }
        )

    def test_registration_bridge_uses_same_outlook_account_for_graph_code(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self._accounts_file(temp_dir)
            self._configure(path)
            runtime = app._initialize_outlook_batch_runtime(count=1)
            email, lease_id = app.get_email_and_token()

            with patch.object(
                app.outlook_provider,
                "wait_for_code_graph",
                return_value="ABC-123",
            ) as wait_graph:
                code = app.get_oai_code(lease_id, email, timeout=5, poll_interval=1)

        self.assertEqual(code, "ABC-123")
        self.assertEqual(wait_graph.call_args.args[0].email, email)
        self.assertIsNotNone(wait_graph.call_args.kwargs["not_before"])
        self.assertNotIn(email, lease_id)
        self.assertNotIn("refresh-0", lease_id)
        self.assertTrue(runtime.succeed_current())

    def test_protocol_failure_carries_exact_outlook_lease(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self._accounts_file(temp_dir)
            self._configure(path)
            runtime = app._initialize_outlook_batch_runtime(count=1)
            captured = {}

            def fail_after_acquire(**kwargs):
                email, lease_id = kwargs["get_email_and_token"]()
                captured.update(email=email, lease_id=lease_id)
                raise RuntimeError("signup failed")

            with patch.object(app, "use_protocol_register", return_value=True), patch.object(
                app._protocol, "register_one", side_effect=fail_after_acquire
            ):
                with self.assertRaises(RuntimeError) as raised:
                    app.register_account_once()

        self.assertEqual(raised.exception.outlook_lease_id, captured["lease_id"])
        self.assertTrue(runtime.fail(raised.exception.outlook_lease_id))
        self.assertEqual(runtime.failed_count, 1)

    def test_pool_rejects_count_above_available_accounts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self._accounts_file(temp_dir)
            self._configure(path)
            with self.assertRaises(app.outlook_provider.OutlookConfigError):
                app._initialize_outlook_batch_runtime(count=2)

        self.assertIsNone(app._get_outlook_batch_runtime())

    def test_success_calls_existing_cpa_import_without_logging_secrets(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self._accounts_file(temp_dir)
            output = Path(temp_dir) / "registered.txt"
            self._configure(path)
            runtime = app._initialize_outlook_batch_runtime(count=1)
            gui = object.__new__(app.GrokRegisterGUI)
            gui.is_running = True
            gui.stop_requested = False
            gui.success_count = 0
            gui.fail_count = 0
            gui.fail_stats = app.empty_fail_stats()
            gui.results = []
            gui.accounts_output_file = str(output)
            gui._stats_lock = threading.Lock()
            gui._accounts_lock = threading.Lock()
            logs = []
            gui.log = logs.append
            gui.update_stats = lambda: None
            real_open = open

            def guarded_open(file, *args, **kwargs):
                if str(file).endswith("mail_credentials.txt"):
                    raise AssertionError("Outlook lease must not be persisted as mail credentials")
                return real_open(file, *args, **kwargs)

            def fake_register_account_once(**_kwargs):
                email, lease_id = app.get_email_and_token()
                return (
                    email,
                    "PASSWORD_SECRET",
                    "SSO_SECRET",
                    {
                        "given_name": "A",
                        "family_name": "B",
                        "password": "PASSWORD_SECRET",
                        "_outlook_lease_id": lease_id,
                    },
                )

            with patch.object(
                app,
                "register_account_once",
                side_effect=fake_register_account_once,
            ), patch.object(
                app, "add_sso_to_cpa", return_value=True
            ) as add_to_cpa, patch.object(app, "maybe_stop_browser", return_value=None), patch(
                "builtins.open", side_effect=guarded_open
            ):
                gui.run_registration(1)

        self.assertEqual(gui.success_count, 1)
        self.assertEqual(runtime.succeeded_count, 1)
        add_to_cpa.assert_called_once_with(
            "SSO_SECRET",
            email="user-0@outlook.com",
            log_callback=ANY,
            should_stop=gui.should_stop,
        )
        combined = "\n".join(logs)
        for secret in ("PASSWORD_SECRET", "SSO_SECRET", "refresh-0"):
            self.assertNotIn(secret, combined)

    def test_outlook_disables_protocol_pipeline(self):
        app.config.update({"email_provider": "outlook", "register_mode": "protocol"})
        self.assertFalse(app.use_protocol_pipeline(5, workers=1))

    def test_cli_outlook_keeps_configured_workers_settles_and_clears_pool(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self._accounts_file(temp_dir, count=2)
            self._configure(path)
            app.config["register_workers"] = 8
            logs = []
            acquired = []
            acquired_lock = threading.Lock()
            real_settle = app._settle_outlook_lease
            real_clear = app._clear_outlook_batch_runtime

            def fake_register_account_once(**_kwargs):
                email, lease_id = app.get_email_and_token()
                with acquired_lock:
                    acquired.append((email, lease_id))
                return email, "PASSWORD_SECRET", "SSO_SECRET", {
                    "password": "PASSWORD_SECRET",
                    "_outlook_lease_id": lease_id,
                }

            with patch.object(app, "cli_log", side_effect=logs.append), patch.object(
                app, "use_protocol_register", return_value=True
            ), patch.object(
                app, "register_account_once", side_effect=fake_register_account_once
            ), patch.object(
                app, "add_sso_to_cpa", return_value=True
            ), patch.object(
                app, "cleanup_runtime_memory"
            ), patch.object(
                app, "_settle_outlook_lease", wraps=real_settle
            ) as settle, patch.object(
                app, "_clear_outlook_batch_runtime", wraps=real_clear
            ) as clear, patch(
                "builtins.open", MagicMock()
            ):
                app.run_registration_cli(2)

        self.assertEqual(
            {email for email, _lease_id in acquired},
            {"user-0@outlook.com", "user-1@outlook.com"},
        )
        self.assertEqual(
            {(args[0], args[1]) for args, _kwargs in settle.call_args_list},
            {(lease_id, True) for _email, lease_id in acquired},
        )
        clear.assert_called_once_with()
        self.assertIsNone(app._get_outlook_batch_runtime())
        self.assertTrue(any("并发: 2" in line for line in logs))
        self.assertTrue(any("任务结束。成功 2 | 失败 0" in line for line in logs))

    def test_cli_outlook_rejects_count_above_pool_before_registration(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self._accounts_file(temp_dir)
            self._configure(path)
            logs = []
            with patch.object(app, "cli_log", side_effect=logs.append), patch.object(
                app, "register_account_once"
            ) as register_once:
                app.run_registration_cli(2)

        register_once.assert_not_called()
        self.assertIsNone(app._get_outlook_batch_runtime())
        self.assertTrue(any("Outlook 账号池初始化失败" in line for line in logs))

    def test_gui_start_keeps_configured_workers(self):
        gui = object.__new__(app.GrokRegisterGUI)
        gui.is_running = False
        gui.sso_convert_running = False
        gui.outlook_test_running = False
        gui.email_provider_var = MagicMock(get=lambda: "outlook")

        def variable(value):
            item = MagicMock()
            item.get.return_value = value
            return item

        gui.email_provider_var = variable("outlook")
        gui.nsfw_var = variable(False)
        gui.close_browser_on_stop_var = variable(False)
        gui.log_level_var = variable("info")
        gui.proxy_var = variable("")
        gui.api_key_var = variable("")
        gui.duckmail_api_base_var = variable(app.DUCKMAIL_API_BASE_DEFAULT)
        gui.cloudflare_api_base_var = variable("")
        gui.cloudflare_api_key_var = variable("")
        gui.cloudflare_auth_mode_var = variable("none")
        gui.default_domains_var = variable("")
        gui.cloudflare_custom_auth_var = variable("")
        gui.cloudflare_random_subdomain_var = variable(False)
        gui.yyds_api_key_var = variable("")
        gui.yyds_jwt_var = variable("")
        gui.mailnest_api_key_var = variable("")
        gui.mailnest_project_code_var = variable(app.MAILNEST_DEFAULT_PROJECT_CODE)
        gui.yyds_default_domain_var = variable("")
        gui.cloudmail_url_var = variable("")
        gui.cloudmail_admin_email_var = variable("")
        gui.cloudmail_password_var = variable("")
        gui.outlook_accounts_file_var = variable("accounts.json")
        gui.cpa_auto_add_var = variable(False)
        gui.cpa_auth_dir_var = variable("")
        gui.cpa_remote_url_var = variable("")
        gui.cpa_management_key_var = variable("")
        gui.cloudflare_paths_var = variable("/domains,/accounts,/token,/mails")
        gui.count_var = variable("2")
        gui.workers_var = variable("8")
        gui.outlook_count_var = MagicMock()
        gui.progress_var = MagicMock()
        gui.eta_var = MagicMock()
        gui.update_stats = lambda: None
        gui._set_running_ui = lambda _running: None
        logs = []
        gui.log = logs.append

        runtime = MagicMock(available_count=2)
        started = {}

        class CapturedThread:
            def __init__(self, target, args=(), **_kwargs):
                started["target"] = target
                started["args"] = args

            def start(self):
                return None

        with patch.object(app, "save_config"), patch.object(
            app, "_initialize_outlook_batch_runtime", return_value=runtime
        ), patch.object(app._conn, "run_connectivity_checks", return_value=[]), patch.object(
            app.threading, "Thread", CapturedThread
        ):
            gui.start_registration()

        gui.workers_var.set.assert_not_called()
        self.assertEqual(app.config["register_workers"], 2)
        self.assertEqual(started["args"], (2, 2))


if __name__ == "__main__":
    unittest.main()
