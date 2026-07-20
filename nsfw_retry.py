"""持久化 NSFW 补开队列。"""
from __future__ import annotations

import os
import queue
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Optional

RetryCallback = Callable[[str, str, Callable[[], bool]], tuple[bool, str]]

_pending_locks_guard = threading.Lock()
_pending_locks: dict[str, threading.Lock] = {}


def _parse_line(raw_line: str) -> tuple[str, str]:
    line = str(raw_line or "").strip()
    if not line or line.startswith("#"):
        return "", ""
    if "----" not in line:
        return "", line
    parts = line.split("----")
    email = parts[0].strip() if "@" in parts[0] else ""
    return email, parts[-1].strip()


def _entry_key(email: str, sso: str) -> str:
    email_key = str(email or "").strip().casefold()
    return f"email:{email_key}" if email_key else f"sso:{sso}"


def _thread_lock_for(path: Path) -> threading.Lock:
    key = os.path.abspath(os.fspath(path))
    if os.name == "nt":
        key = key.casefold()
    with _pending_locks_guard:
        lock = _pending_locks.get(key)
        if lock is None:
            lock = threading.Lock()
            _pending_locks[key] = lock
        return lock


@contextmanager
def _pending_transaction(path: Path):
    """串行化同进程线程及不同进程的 pending 读改写。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    thread_lock = _thread_lock_for(path)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with thread_lock, lock_path.open("a+b") as lock_file:
        if os.fstat(lock_file.fileno()).st_size == 0:
            lock_file.write(b"\0")
            lock_file.flush()
        lock_file.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _load_pending_entries_unlocked(path: Path) -> list[tuple[str, str]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []
    unique: dict[str, tuple[str, str]] = {}
    for raw_line in lines:
        email, sso = _parse_line(raw_line)
        if sso:
            unique[_entry_key(email, sso)] = (email, sso)
    return list(unique.values())


def load_pending_entries(path: str | Path) -> list[tuple[str, str]]:
    pending_path = Path(path)
    with _pending_transaction(pending_path):
        return _load_pending_entries_unlocked(pending_path)


def _write_pending_entries(path: Path, entries: list[tuple[str, str]]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    text = "".join(f"{email}----{sso}\n" if email else f"{sso}\n" for email, sso in entries)
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def _append_pending_entry(path: Path, email: str, sso: str) -> None:
    line = f"{email}----{sso}\n" if email else f"{sso}\n"
    with _pending_transaction(path):
        with path.open("a", encoding="utf-8") as pending_file:
            pending_file.write(line)


class NsfwRetryWorker:
    """单批次串行处理 NSFW；成功删除 pending，失败保留。"""

    def __init__(
        self,
        pending_path: str | Path,
        retry_callback: RetryCallback,
        *,
        cleanup_callback: Optional[Callable[[], None]] = None,
        log: Callable[[str], None] = print,
        idle_timeout: float = 90.0,
    ):
        self.pending_path = Path(pending_path)
        self.retry_callback = retry_callback
        self.cleanup_callback = cleanup_callback
        self.log = log
        self.idle_timeout = max(float(idle_timeout), 0.1)
        self._queue: queue.Queue[Optional[tuple[str, str, bool]]] = queue.Queue()
        self._state_lock = threading.Lock()
        self._thread_lock = threading.Lock()
        self._scheduled: set[tuple[str, str]] = set()
        self._latest_sso: dict[str, str] = {}
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._accepting = True
        self._exit_queued = False
        self._submitted = 0
        self._attempted = 0
        self._succeeded = 0
        self._failed = 0

    def _safe_log(self, message: str) -> None:
        try:
            self.log(message)
        except Exception:
            pass

    def _persist(self, email: str, sso: str) -> None:
        _append_pending_entry(self.pending_path, email, sso)

    def _remove(self, email: str, sso: str) -> None:
        with _pending_transaction(self.pending_path):
            entries = _load_pending_entries_unlocked(self.pending_path)
            kept = [
                (item_email, item_sso)
                for item_email, item_sso in entries
                if not (
                    item_sso == sso
                    and str(item_email or "").casefold() == str(email or "").casefold()
                )
            ]
            _write_pending_entries(self.pending_path, kept)

    def _enqueue(self, email: str, sso: str, persisted: bool) -> bool:
        item = (str(email or "").strip(), str(sso or "").strip())
        if not item[1]:
            return False
        with self._state_lock:
            if not self._accepting or item in self._scheduled:
                return False
            self._scheduled.add(item)
            self._latest_sso[_entry_key(*item)] = item[1]
            self._submitted += 1
            self._queue.put((item[0], item[1], bool(persisted)))
        self._ensure_thread()
        return True

    def submit(self, email: str, sso: str) -> bool:
        email = str(email or "").strip()
        sso = str(sso or "").strip()
        if not sso:
            return False
        persisted = True
        try:
            self._persist(email, sso)
        except Exception as exc:
            persisted = False
            self._safe_log(f"[NSFW] [!] 保存 pending 失败，仍尝试本次补开: {exc}")
        return self._enqueue(email, sso, persisted)

    def start_existing(self) -> int:
        try:
            entries = load_pending_entries(self.pending_path)
        except Exception as exc:
            self._safe_log(f"[NSFW] [!] 读取 pending 失败: {exc}")
            return 0
        queued = 0
        for email, sso in entries:
            if self._enqueue(email, sso, True):
                queued += 1
        return queued

    def _ensure_thread(self) -> None:
        with self._thread_lock:
            if self._thread is not None and self._thread.is_alive():
                return
            if self._stop_event.is_set():
                return
            self._thread = threading.Thread(
                target=self._run,
                name="nsfw-retry-worker",
                daemon=True,
            )
            self._thread.start()

    def _record_result(self, ok: bool) -> None:
        with self._state_lock:
            self._attempted += 1
            if ok:
                self._succeeded += 1
            else:
                self._failed += 1

    def _discard_scheduled(self, item: tuple[str, str]) -> None:
        with self._state_lock:
            self._scheduled.discard(item)

    def _is_latest(self, email: str, sso: str) -> bool:
        with self._state_lock:
            return self._latest_sso.get(_entry_key(email, sso)) == sso

    def _preserve_failed_item(self, email: str, sso: str, persisted: bool) -> str:
        if persisted:
            return "已保留 pending"
        if not self._is_latest(email, sso):
            return "旧 SSO 已由更新项替代"
        try:
            self._persist(email, sso)
            return "已保留 pending"
        except Exception as exc:
            self._safe_log(f"[NSFW] [!] 保存 pending 失败: {email or '未知邮箱'} ({exc})")
            return "pending 保存失败"

    def _drain_cancelled_items(self) -> None:
        while True:
            try:
                queued = self._queue.get_nowait()
            except queue.Empty:
                return
            if queued is not None:
                email, sso, persisted = queued
                if not persisted and self._is_latest(email, sso):
                    try:
                        self._persist(email, sso)
                    except Exception as exc:
                        self._safe_log(f"[NSFW] [!] 取消时保存 pending 失败: {email or '未知邮箱'} ({exc})")
                self._discard_scheduled((email, sso))
            self._queue.task_done()

    def _run(self) -> None:
        try:
            while not self._stop_event.is_set():
                try:
                    item = self._queue.get(timeout=self.idle_timeout)
                except queue.Empty:
                    continue
                if item is None:
                    self._queue.task_done()
                    return
                email, sso, persisted = item
                try:
                    ok, message = self.retry_callback(
                        email,
                        sso,
                        self._stop_event.is_set,
                    )
                    ok = bool(ok)
                    self._record_result(ok)
                    if ok:
                        try:
                            self._remove(email, sso)
                        except Exception as exc:
                            self._safe_log(f"[NSFW] [!] 补开成功但清理 pending 失败: {email or '未知邮箱'} ({exc})")
                        self._safe_log(f"[NSFW] [+] 补开成功: {email or '未知邮箱'} ({message})")
                    else:
                        pending_status = self._preserve_failed_item(email, sso, persisted)
                        self._safe_log(f"[NSFW] [!] 补开失败，{pending_status}: {email or '未知邮箱'} ({message})")
                except Exception as exc:
                    self._record_result(False)
                    pending_status = self._preserve_failed_item(email, sso, persisted)
                    self._safe_log(f"[NSFW] [!] 补开异常，{pending_status}: {email or '未知邮箱'} ({exc})")
                finally:
                    self._discard_scheduled((email, sso))
                    self._queue.task_done()
        finally:
            if self._stop_event.is_set():
                self._drain_cancelled_items()
            if self.cleanup_callback:
                try:
                    self.cleanup_callback()
                except Exception:
                    pass
            with self._thread_lock:
                if self._thread is threading.current_thread():
                    self._thread = None

    def pending_tasks(self) -> int:
        with self._queue.all_tasks_done:
            return int(self._queue.unfinished_tasks)

    def summary(self) -> dict[str, int | bool]:
        with self._state_lock:
            submitted = self._submitted
            attempted = self._attempted
            succeeded = self._succeeded
            failed = self._failed
        thread = self._thread
        return {
            "submitted": submitted,
            "attempted": attempted,
            "succeeded": succeeded,
            "failed": failed,
            "cancelled": max(submitted - attempted, 0),
            "completed": attempted == submitted and not self._stop_event.is_set(),
            "worker_stopped": thread is None or not thread.is_alive(),
        }

    def wait_for_tasks(self, timeout: float | None = None) -> bool:
        deadline = None if timeout is None else time.monotonic() + max(timeout, 0)
        while self.pending_tasks():
            thread = self._thread
            if thread is None or not thread.is_alive():
                return False
            if deadline is not None and time.monotonic() >= deadline:
                return False
            time.sleep(0.05)
        return True

    def _queue_exit(self) -> None:
        with self._thread_lock:
            with self._state_lock:
                if self._exit_queued:
                    return
                self._exit_queued = True
                thread = self._thread
                if thread is not None and thread.is_alive():
                    self._queue.put(None)

    def _join(self, timeout: float | None) -> bool:
        thread = self._thread
        if thread is None or not thread.is_alive():
            return True
        thread.join(timeout=None if timeout is None else max(timeout, 0))
        return not thread.is_alive()

    def finish(self, timeout: float | None = None) -> dict[str, int | bool]:
        """停止接收新任务，等待本批任务全部得到明确成功或失败结果。"""
        with self._state_lock:
            self._accepting = False
        started_at = time.monotonic()
        drained = self.wait_for_tasks(timeout=timeout)
        if not drained:
            remaining = None
            if timeout is not None:
                remaining = max(timeout - (time.monotonic() - started_at), 0)
            self.cancel(wait=True, timeout=remaining)
            result = self.summary()
            result["completed"] = False
            return result
        self._queue_exit()
        remaining = None
        if timeout is not None:
            remaining = max(timeout - (time.monotonic() - started_at), 0)
        joined = self._join(remaining)
        result = self.summary()
        result["completed"] = bool(result["completed"] and joined)
        return result

    def cancel(self, wait: bool = False, timeout: float | None = 5.0) -> dict[str, int | bool]:
        """取消本批；未尝试项目继续保留在 pending。"""
        with self._state_lock:
            self._accepting = False
        self._queue_exit()
        self._stop_event.set()
        thread = self._thread
        if thread is None or not thread.is_alive():
            self._drain_cancelled_items()
        if wait:
            self._join(timeout)
        return self.summary()

    def stop(self, wait: bool = False, timeout: float = 5.0) -> None:
        """兼容旧调用；新代码应使用 finish() 或 cancel()。"""
        self.cancel(wait=wait, timeout=timeout)
