import json
import stat
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from email_providers import outlook


class OutlookProviderTests(unittest.TestCase):
    def test_legacy_input_discards_password_and_deduplicates_email(self):
        accounts = outlook.parse_accounts_text(
            "User@outlook.com----secret-one----client-one----refresh-one\n"
            "user@OUTLOOK.com----secret-two----client-two----refresh-two\n"
        )

        self.assertEqual(len(accounts), 1)
        self.assertEqual(accounts[0].email, "User@outlook.com")
        self.assertEqual(accounts[0].client_id, "client-one")
        self.assertEqual(accounts[0].refresh_token, "refresh-one")
        self.assertFalse(hasattr(accounts[0], "password"))
        self.assertNotIn("refresh-one", repr(accounts[0]))

    def test_loads_json_accounts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "accounts.json"
            path.write_text(
                json.dumps(
                    [
                        {
                            "email": "user@outlook.com",
                            "client_id": "client-id",
                            "refresh_token": "refresh-token",
                            "tenant": "common",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            accounts = outlook.load_accounts_file(str(path))

        self.assertEqual(len(accounts), 1)
        self.assertEqual(accounts[0].tenant, "common")

    def test_write_accounts_json_omits_password(self):
        account = outlook.OutlookAccount("user@outlook.com", "client-id", "refresh-token")
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "accounts.json"
            outlook.write_accounts_json(str(path), [account])
            payload = json.loads(path.read_text(encoding="utf-8"))
            mode = stat.S_IMODE(path.stat().st_mode)

        self.assertNotIn("password", payload[0])
        self.assertEqual(payload[0]["email"], "user@outlook.com")
        self.assertEqual(mode, 0o600)

    def test_refresh_access_token_uses_graph_scope(self):
        account = outlook.OutlookAccount("user@outlook.com", "client-id", "refresh-token")
        captured = {}

        def fake_http(url, **kwargs):
            captured["url"] = url
            captured.update(kwargs)
            return {"access_token": "access-token"}

        with patch.object(outlook, "_http_json", side_effect=fake_http):
            access_token, rotated = outlook.refresh_access_token(account)

        self.assertEqual(access_token, "access-token")
        self.assertIsNone(rotated)
        self.assertEqual(captured["form"]["scope"], outlook.GRAPH_SCOPE)
        self.assertNotIn("refresh-token", repr(account))

    def test_oauth_error_does_not_echo_refresh_token(self):
        account = outlook.OutlookAccount("user@outlook.com", "client-id", "REFRESH_SECRET")
        with patch.object(
            outlook,
            "_http_json",
            side_effect=outlook.OutlookHTTPError(
                400,
                '{"refresh_token":"REFRESH_SECRET","password":"PASSWORD_SECRET"}',
            ),
        ):
            with self.assertRaises(outlook.OutlookAuthError) as raised:
                outlook.refresh_access_token(account)

        self.assertNotIn("REFRESH_SECRET", str(raised.exception))
        self.assertNotIn("PASSWORD_SECRET", str(raised.exception))

    def test_refresh_retries_common_aadsts70011_scope_error(self):
        account = outlook.OutlookAccount("user@outlook.com", "client-id", "refresh-token")
        calls = []

        def fake_http(_url, **kwargs):
            calls.append(kwargs["form"])
            if len(calls) == 1:
                raise outlook.OutlookHTTPError(400, "invalid_scope: AADSTS70011")
            return {"access_token": "access-token"}

        with patch.object(outlook, "_http_json", side_effect=fake_http):
            access_token, _rotated = outlook.refresh_access_token(account)

        self.assertEqual(access_token, "access-token")
        self.assertEqual(calls[0]["scope"], outlook.GRAPH_SCOPE)
        self.assertEqual(calls[1]["scope"], outlook.GRAPH_DELEGATED_SCOPE)

    def test_check_account_performs_graph_probe(self):
        account = outlook.OutlookAccount("user@outlook.com", "client-id", "refresh-token")
        with patch.object(
            outlook,
            "refresh_access_token",
            return_value=("access-token", None),
        ), patch.object(
            outlook,
            "graph_list_messages",
            return_value=[{"id": "one"}, {"id": "two"}],
        ) as list_messages:
            result = outlook.check_account(account, proxy="http://proxy", top=5)

        self.assertEqual(result["protocol"], "graph")
        self.assertEqual(result["message_count"], 2)
        list_messages.assert_called_once_with("access-token", top=5, proxy="http://proxy")

    def test_wait_for_code_ignores_mail_before_lease(self):
        account = outlook.OutlookAccount("user@outlook.com", "client-id", "refresh-token")
        not_before = datetime.now(timezone.utc)
        messages = [
            {
                "id": "old",
                "receivedDateTime": (not_before - timedelta(minutes=1)).isoformat(),
            },
            {
                "id": "new",
                "receivedDateTime": (not_before + timedelta(seconds=1)).isoformat(),
            },
        ]
        with patch.object(
            outlook,
            "refresh_access_token",
            return_value=("access-token", None),
        ), patch.object(
            outlook,
            "graph_list_messages",
            return_value=messages,
        ), patch.object(
            outlook,
            "graph_get_message",
            return_value={"subject": "Your verification code is ABC-123", "bodyPreview": ""},
        ) as get_message:
            code = outlook.wait_for_code_graph(account, not_before=not_before, timeout=1)

        self.assertEqual(code, "ABC-123")
        get_message.assert_called_once_with("access-token", "new", proxy="")

    def test_batch_runtime_never_reuses_an_account(self):
        runtime = outlook.OutlookBatchRuntime(
            [
                outlook.OutlookAccount("User@outlook.com", "client-one", "refresh-one"),
                outlook.OutlookAccount("user@OUTLOOK.com", "client-two", "refresh-two"),
            ]
        )

        email, lease_id = runtime.acquire()
        self.assertEqual(email, "User@outlook.com")
        self.assertNotIn(email, lease_id)
        self.assertNotIn("refresh-one", lease_id)
        self.assertTrue(runtime.fail(lease_id))
        with self.assertRaises(outlook.OutlookPoolExhausted):
            runtime.acquire()

    def test_batch_runtime_can_settle_mail_worker_lease_from_outer_thread(self):
        runtime = outlook.OutlookBatchRuntime(
            [
                outlook.OutlookAccount("first@outlook.com", "client-one", "refresh-one"),
                outlook.OutlookAccount("second@outlook.com", "client-two", "refresh-two"),
            ]
        )
        acquired = []

        worker = threading.Thread(target=lambda: acquired.append(runtime.acquire()))
        worker.start()
        worker.join()

        self.assertEqual(acquired[0][0], "first@outlook.com")
        self.assertTrue(runtime.succeed(acquired[0][1]))
        second_email, _lease = runtime.acquire()
        self.assertEqual(second_email, "second@outlook.com")

    def test_batch_runtime_supports_parallel_leases_and_exact_settlement(self):
        runtime = outlook.OutlookBatchRuntime(
            [
                outlook.OutlookAccount("first@outlook.com", "client-one", "refresh-one"),
                outlook.OutlookAccount("second@outlook.com", "client-two", "refresh-two"),
            ]
        )

        first_email, first_lease = runtime.acquire()
        second_email, second_lease = runtime.acquire()

        self.assertNotEqual(first_lease, second_lease)
        self.assertEqual(runtime.resolve(first_lease).email, first_email)
        self.assertEqual(runtime.resolve(second_lease).email, second_email)
        self.assertTrue(runtime.succeed(second_lease))
        self.assertTrue(runtime.fail(first_lease))
        self.assertEqual(runtime.succeeded_count, 1)
        self.assertEqual(runtime.failed_count, 1)


if __name__ == "__main__":
    unittest.main()
