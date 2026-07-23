import json
import queue
import tempfile
import tkinter as tk
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import grok_register_ttk as app


class OutlookGuiTests(unittest.TestCase):
    def setUp(self):
        self.original_config = app.config.copy()

    def tearDown(self):
        app.config = self.original_config

    def test_gui_exposes_outlook_actions(self):
        app.config = app.DEFAULT_CONFIG.copy()
        try:
            root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(f"Tk display unavailable: {exc}")
        root.withdraw()
        try:
            with patch.object(app, "load_config", return_value=app.config):
                gui = app.GrokRegisterGUI(root)
            self.assertIn("outlook", gui._provider_widget_groups)
            self.assertEqual(gui.outlook_browse_btn.cget("text"), "选择 TXT/JSON")
            self.assertEqual(gui.outlook_import_btn.cget("text"), "粘贴账号")
            self.assertEqual(gui.outlook_test_btn.cget("text"), "测试 Outlook 连接")
        finally:
            root.destroy()

    def test_paste_import_writes_password_free_json_and_updates_count(self):
        gui = object.__new__(app.GrokRegisterGUI)
        gui.outlook_accounts_file_var = MagicMock()
        gui.outlook_accounts_file_var.get.return_value = "outlook_accounts.txt"
        gui.outlook_count_var = MagicMock()
        gui.count_var = MagicMock()
        pasted = (
            "first@outlook.com----password-one----client-one----refresh-one\n"
            "second@outlook.com----password-two----client-two----refresh-two\n"
        )

        with tempfile.TemporaryDirectory() as temp_dir, patch.object(app, "APP_DIR", temp_dir):
            result = gui._import_outlook_accounts_text(pasted)
            payload = json.loads(Path(result["path"]).read_text(encoding="utf-8"))

        self.assertEqual(result["count"], 2)
        self.assertTrue(all("password" not in item for item in payload))
        gui.count_var.set.assert_called_once_with("2")
        gui.outlook_count_var.set.assert_called_once_with("有效账号：2")
        self.assertNotIn("password-one", json.dumps(result))
        self.assertNotIn("refresh-one", json.dumps(result))

    def test_file_selection_loads_txt_or_json_and_displays_count(self):
        gui = object.__new__(app.GrokRegisterGUI)
        gui.root = MagicMock()
        gui.outlook_accounts_file_var = MagicMock()
        gui.outlook_count_var = MagicMock()
        gui.count_var = MagicMock()
        logs = []
        gui.log = logs.append

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "accounts.txt"
            path.write_text(
                "first@outlook.com----pw----client-one----refresh-one\n"
                "second@outlook.com----pw----client-two----refresh-two\n",
                encoding="utf-8",
            )
            with patch.object(app.filedialog, "askopenfilename", return_value=str(path)):
                gui.select_outlook_accounts_file()

        gui.outlook_accounts_file_var.set.assert_called_once_with(str(path))
        gui.count_var.set.assert_called_once_with("2")
        self.assertTrue(any("有效账号 2 个" in line for line in logs))

    def test_connection_test_uses_graph_without_logging_secrets(self):
        gui = object.__new__(app.GrokRegisterGUI)
        gui.root = MagicMock()
        gui.is_running = False
        gui.sso_convert_running = False
        gui.outlook_test_running = False
        gui.outlook_accounts_file_var = MagicMock()
        gui.proxy_var = MagicMock()
        gui.proxy_var.get.return_value = ""
        gui.outlook_count_var = MagicMock()
        gui.count_var = MagicMock()
        gui.outlook_test_btn = MagicMock()
        gui.outlook_browse_btn = MagicMock()
        gui.outlook_import_btn = MagicMock()
        gui.start_btn = MagicMock()
        gui.ui_queue = queue.Queue()
        logs = []
        gui.log = logs.append

        class ImmediateThread:
            def __init__(self, target, **_kwargs):
                self.target = target

            def start(self):
                self.target()

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "accounts.txt"
            path.write_text(
                "user@outlook.com----PASSWORD_SECRET----client-id----REFRESH_SECRET\n",
                encoding="utf-8",
            )
            gui.outlook_accounts_file_var.get.return_value = str(path)
            with patch.object(
                app.outlook_provider,
                "check_account",
                return_value={"message_count": 3},
            ) as check_account, patch.object(app.threading, "Thread", ImmediateThread):
                gui.test_outlook_connection()

        callback, args = gui.ui_queue.get_nowait()
        callback(*args)
        check_account.assert_called_once()
        combined = "\n".join(logs)
        self.assertNotIn("PASSWORD_SECRET", combined)
        self.assertNotIn("REFRESH_SECRET", combined)
        self.assertNotIn("sso", combined.lower())


if __name__ == "__main__":
    unittest.main()
