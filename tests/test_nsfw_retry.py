import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import nsfw_retry
from nsfw_retry import NsfwRetryWorker, load_pending_entries


class NsfwRetryWorkerTests(unittest.TestCase):
    def test_success_removes_pending_and_failure_keeps_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nsfw_pending.txt"

            def retry(email, sso, should_stop):
                return (email.startswith("ok"), "done" if email.startswith("ok") else "blocked")

            worker = NsfwRetryWorker(path, retry, log=lambda _: None, idle_timeout=0.1)
            worker.submit("ok@example.com", "sso-ok")
            worker.submit("bad@example.com", "sso-bad")
            summary = worker.finish(timeout=2)

            self.assertTrue(summary["completed"])
            self.assertEqual(summary["succeeded"], 1)
            self.assertEqual(summary["failed"], 1)
            self.assertEqual(load_pending_entries(path), [("bad@example.com", "sso-bad")])

    def test_same_email_updates_pending_sso(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nsfw_pending.txt"
            worker = NsfwRetryWorker(
                path,
                lambda email, sso, should_stop: (False, "keep"),
                log=lambda _: None,
                idle_timeout=0.1,
            )
            worker._persist("user@example.com", "old-sso")
            worker._persist("user@example.com", "new-sso")

            self.assertEqual(load_pending_entries(path), [("user@example.com", "new-sso")])

    def test_old_sso_failure_does_not_restore_it_after_new_sso_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nsfw_pending.txt"

            def retry(email, sso, should_stop):
                return sso == "new-sso", "done"

            worker = NsfwRetryWorker(path, retry, log=lambda _: None, idle_timeout=0.1)
            worker.submit("user@example.com", "old-sso")
            worker.submit("user@example.com", "new-sso")
            summary = worker.finish(timeout=2)

            self.assertEqual(summary["failed"], 1)
            self.assertEqual(summary["succeeded"], 1)
            self.assertEqual(load_pending_entries(path), [])

    def test_new_batch_does_not_process_historical_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nsfw_pending.txt"
            path.write_text("old@example.com----old-sso\n", encoding="utf-8")
            processed = []

            def retry(email, sso, should_stop):
                processed.append((email, sso))
                return True, "done"

            worker = NsfwRetryWorker(path, retry, log=lambda _: None, idle_timeout=0.1)
            worker.submit("new@example.com", "new-sso")
            worker.finish(timeout=2)

            self.assertEqual(processed, [("new@example.com", "new-sso")])
            self.assertEqual(load_pending_entries(path), [("old@example.com", "old-sso")])

    def test_finish_waits_until_inflight_task_has_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nsfw_pending.txt"
            started = threading.Event()
            release = threading.Event()

            def retry(email, sso, should_stop):
                started.set()
                release.wait(2)
                return True, "done"

            worker = NsfwRetryWorker(path, retry, log=lambda _: None, idle_timeout=0.1)
            worker.submit("user@example.com", "sso-token")
            self.assertTrue(started.wait(1))
            result = {}
            finisher = threading.Thread(
                target=lambda: result.setdefault("summary", worker.finish(timeout=2))
            )
            finisher.start()
            time.sleep(0.05)
            self.assertTrue(finisher.is_alive())
            release.set()
            finisher.join(2)

            self.assertFalse(finisher.is_alive())
            self.assertTrue(result["summary"]["completed"])
            self.assertEqual(result["summary"]["attempted"], 1)

    def test_finish_timeout_is_total_budget_not_double_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nsfw_pending.txt"
            started = threading.Event()
            release = threading.Event()

            def retry(email, sso, should_stop):
                started.set()
                release.wait(2)
                return False, "stopped"

            worker = NsfwRetryWorker(path, retry, log=lambda _: None, idle_timeout=0.1)
            worker.submit("user@example.com", "sso-token")
            self.assertTrue(started.wait(1))
            started_at = time.monotonic()
            summary = worker.finish(timeout=0.1)
            elapsed = time.monotonic() - started_at
            release.set()
            worker.cancel(wait=True, timeout=2)

            self.assertFalse(summary["completed"])
            self.assertLess(elapsed, 0.18)

    def test_concurrent_duplicate_submit_runs_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nsfw_pending.txt"
            release = threading.Event()
            callback_count = 0
            callback_lock = threading.Lock()

            def retry(email, sso, should_stop):
                nonlocal callback_count
                with callback_lock:
                    callback_count += 1
                release.wait(2)
                return True, "done"

            worker = NsfwRetryWorker(path, retry, log=lambda _: None, idle_timeout=0.1)
            barrier = threading.Barrier(20)
            results = []

            def submit():
                barrier.wait()
                results.append(worker.submit("user@example.com", "sso-token"))

            threads = [threading.Thread(target=submit) for _ in range(20)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(2)
            release.set()
            summary = worker.finish(timeout=2)

            self.assertEqual(sum(bool(result) for result in results), 1)
            self.assertEqual(callback_count, 1)
            self.assertEqual(summary["submitted"], 1)

    def test_cancel_waits_for_in_progress_thread_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nsfw_pending.txt"
            publication_started = threading.Event()
            release_publication = threading.Event()
            cleanup_done = threading.Event()
            worker = NsfwRetryWorker(
                path,
                lambda email, sso, should_stop: (False, "stopped"),
                cleanup_callback=cleanup_done.set,
                log=lambda _: None,
                idle_timeout=0.1,
            )

            def delayed_ensure_thread():
                with worker._thread_lock:
                    if worker._stop_event.is_set():
                        return
                    publication_started.set()
                    release_publication.wait(2)
                    worker._thread = threading.Thread(target=worker._run, daemon=True)
                    worker._thread.start()

            worker._ensure_thread = delayed_ensure_thread
            submitter = threading.Thread(
                target=worker.submit,
                args=("user@example.com", "sso-token"),
            )
            submitter.start()
            self.assertTrue(publication_started.wait(1))
            result = {}
            canceller = threading.Thread(
                target=lambda: result.setdefault(
                    "summary",
                    worker.cancel(wait=True, timeout=2),
                )
            )
            canceller.start()
            time.sleep(0.05)
            self.assertTrue(canceller.is_alive())
            release_publication.set()
            submitter.join(2)
            canceller.join(2)

            self.assertFalse(canceller.is_alive())
            self.assertTrue(cleanup_done.is_set())
            self.assertTrue(result["summary"]["worker_stopped"])

    def test_cancel_keeps_queued_items_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nsfw_pending.txt"
            started = threading.Event()

            def retry(email, sso, should_stop):
                started.set()
                while not should_stop():
                    time.sleep(0.01)
                return False, "stopped"

            worker = NsfwRetryWorker(path, retry, log=lambda _: None, idle_timeout=0.1)
            worker.submit("first@example.com", "sso-first")
            worker.submit("second@example.com", "sso-second")
            self.assertTrue(started.wait(1))
            summary = worker.cancel(wait=True, timeout=2)

            self.assertEqual(summary["submitted"], 2)
            self.assertEqual(summary["attempted"], 1)
            self.assertEqual(summary["cancelled"], 1)
            self.assertTrue(summary["worker_stopped"])
            self.assertEqual(worker.pending_tasks(), 0)
            self.assertEqual(
                load_pending_entries(path),
                [
                    ("first@example.com", "sso-first"),
                    ("second@example.com", "sso-second"),
                ],
            )

    def test_pending_write_failure_does_not_block_attempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nsfw_pending.txt"
            worker = NsfwRetryWorker(
                path,
                lambda email, sso, should_stop: (True, "done"),
                log=lambda _: None,
                idle_timeout=0.1,
            )
            with patch.object(nsfw_retry, "_append_pending_entry", side_effect=OSError("busy")):
                self.assertTrue(worker.submit("user@example.com", "sso-token"))
                summary = worker.finish(timeout=2)

            self.assertEqual(summary["succeeded"], 1)

    def test_log_callback_failure_does_not_change_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nsfw_pending.txt"

            def broken_log(message):
                raise RuntimeError("closed")

            worker = NsfwRetryWorker(
                path,
                lambda email, sso, should_stop: (True, "done"),
                log=broken_log,
                idle_timeout=0.1,
            )
            worker.submit("user@example.com", "sso-token")
            summary = worker.finish(timeout=2)

            self.assertEqual(summary["attempted"], 1)
            self.assertEqual(summary["succeeded"], 1)
            self.assertEqual(summary["failed"], 0)

    def test_cancel_between_enqueue_and_thread_start_drains_queue(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nsfw_pending.txt"
            worker = NsfwRetryWorker(
                path,
                lambda email, sso, should_stop: (True, "done"),
                log=lambda _: None,
            )
            worker._ensure_thread = lambda: worker.cancel(wait=False)

            self.assertTrue(worker.submit("user@example.com", "sso-token"))

            self.assertEqual(worker.pending_tasks(), 0)
            self.assertEqual(worker.summary()["cancelled"], 1)
            self.assertEqual(load_pending_entries(path), [("user@example.com", "sso-token")])

    def test_cancel_retries_pending_write_for_unstarted_item(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nsfw_pending.txt"
            worker = NsfwRetryWorker(
                path,
                lambda email, sso, should_stop: (True, "done"),
                log=lambda _: None,
            )
            worker._ensure_thread = lambda: None
            real_append = nsfw_retry._append_pending_entry
            calls = 0

            def flaky_append(*args):
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise OSError("busy")
                return real_append(*args)

            with patch.object(nsfw_retry, "_append_pending_entry", side_effect=flaky_append):
                self.assertTrue(worker.submit("user@example.com", "sso-token"))
                worker.cancel(wait=True, timeout=1)

            self.assertEqual(load_pending_entries(path), [("user@example.com", "sso-token")])

    def test_read_error_is_not_treated_as_empty_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nsfw_pending.txt"
            path.write_text("user@example.com----sso-token\n", encoding="utf-8")
            with patch.object(Path, "read_text", side_effect=OSError("busy")):
                with self.assertRaises(OSError):
                    load_pending_entries(path)


if __name__ == "__main__":
    unittest.main()
