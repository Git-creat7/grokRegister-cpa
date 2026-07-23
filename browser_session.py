# -*- coding: utf-8 -*-
"""浏览器会话管理（线程本地 browser/page）。"""
from __future__ import annotations

import gc
import os
import socket
import tempfile
import threading
import time
import uuid
from typing import Callable, Optional, Tuple

import psutil
from DrissionPage import Chromium, ChromiumOptions

if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    _user32 = ctypes.windll.user32
    _window_enum_callback = ctypes.WINFUNCTYPE(
        wintypes.BOOL, wintypes.HWND, wintypes.LPARAM
    )
    _user32.EnumWindows.argtypes = [_window_enum_callback, wintypes.LPARAM]
    _user32.EnumWindows.restype = wintypes.BOOL
    _user32.GetWindowThreadProcessId.argtypes = [
        wintypes.HWND,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    _user32.IsWindowVisible.argtypes = [wintypes.HWND]
    _user32.IsWindowVisible.restype = wintypes.BOOL
    _user32.SetWindowPos.argtypes = [
        wintypes.HWND,
        wintypes.HWND,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.UINT,
    ]
    _user32.SetWindowPos.restype = wintypes.BOOL
    _user32.IsWindow.argtypes = [wintypes.HWND]
    _user32.IsWindow.restype = wintypes.BOOL
    _user32.SetForegroundWindow.argtypes = [wintypes.HWND]
    _user32.SetForegroundWindow.restype = wintypes.BOOL
    _user32.GetForegroundWindow.argtypes = []
    _user32.GetForegroundWindow.restype = wintypes.HWND

_tls = threading.local()
_get_proxy: Optional[Callable[[], dict]] = None
_extension_path: str = ""
_keep_windows_background: bool = False
_headless: bool = False
_start_fail_lock = threading.Lock()
_start_fail_streak = 0
_start_fail_threshold = 3


def configure(
    get_proxies=None,
    extension_path="",
    keep_windows_background=False,
    headless=False,
):
    global _get_proxy, _extension_path, _keep_windows_background, _headless
    _get_proxy = get_proxies
    _extension_path = extension_path or ""
    _keep_windows_background = bool(keep_windows_background)
    _headless = bool(headless)


def get_start_fail_streak() -> int:
    with _start_fail_lock:
        return _start_fail_streak


def _note_start_success():
    global _start_fail_streak
    with _start_fail_lock:
        _start_fail_streak = 0


def _note_start_failure():
    global _start_fail_streak
    with _start_fail_lock:
        _start_fail_streak += 1
        return _start_fail_streak


def _proxies() -> dict:
    if _get_proxy:
        return _get_proxy() or {}
    return {}


def active_browser():
    return getattr(_tls, "browser", None)


def active_page():
    return getattr(_tls, "page", None)


def set_browser_session(browser_obj=None, page_obj=None):
    _tls.browser = browser_obj
    _tls.page = page_obj


def _windows_process_tree(root_pid: int) -> set[int]:
    """返回 root_pid 及其所有后代进程。"""
    if os.name != "nt" or root_pid <= 0:
        return {root_pid} if root_pid > 0 else set()
    try:
        root = psutil.Process(root_pid)
        return {root_pid, *(child.pid for child in root.children(recursive=True))}
    except (psutil.Error, OSError):
        return {root_pid}


def _set_idle_priority(process_ids: set[int]) -> set[int]:
    if os.name != "nt":
        return set()

    changed = set()
    for pid in process_ids:
        try:
            psutil.Process(pid).nice(psutil.IDLE_PRIORITY_CLASS)
            changed.add(pid)
        except (psutil.Error, OSError):
            pass
    return changed


def _get_foreground_window() -> int:
    if os.name != "nt":
        return 0

    return int(_user32.GetForegroundWindow() or 0)


def _send_windows_to_back(process_ids: set[int], last_external_hwnd=0) -> tuple[int, int]:
    """将指定进程的可见顶层窗口置底/移出屏幕/最小化，并返回最新非浏览器前台窗口。"""
    if os.name != "nt":
        return int(last_external_hwnd or 0), 0

    current_foreground = _get_foreground_window()
    browser_windows = []

    def _collect(hwnd, _):
        pid = wintypes.DWORD()
        _user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        # 含最小化窗口（仍可能闪任务栏），一并处理
        if int(pid.value) in process_ids:
            browser_windows.append(int(hwnd))
        return True

    _user32.EnumWindows(_window_enum_callback(_collect), 0)
    browser_handles = set(browser_windows)
    if current_foreground and current_foreground not in browser_handles:
        last_external_hwnd = current_foreground

    # SWP_NOSIZE=0x0001 SWP_NOMOVE=0x0002 SWP_NOACTIVATE=0x0010 SWP_ASYNCWINDOWPOS=0x4000
    # SWP_HIDEWINDOW=0x0080 SWP_SHOWWINDOW=0x0040
    flags_bottom = 0x0001 | 0x0002 | 0x0010 | 0x4000
    # 移到屏外：不激活
    flags_move = 0x0010 | 0x4000
    SW_MINIMIZE = 6
    SW_HIDE = 0
    moved = 0
    for hwnd in browser_windows:
        try:
            # 先最小化，再移出屏幕，再置底
            _user32.ShowWindow(hwnd, SW_MINIMIZE)
            _user32.SetWindowPos(
                hwnd, wintypes.HWND(1), -32000, -32000, 1, 1, flags_move
            )
            if _user32.SetWindowPos(
                hwnd, wintypes.HWND(1), 0, 0, 0, 0, flags_bottom
            ):  # HWND_BOTTOM
                moved += 1
            # 彻底隐藏（仍保持进程，CF 路径可用有界面内核）
            _user32.ShowWindow(hwnd, SW_HIDE)
        except Exception:
            pass

    if (
        current_foreground in browser_handles
        and last_external_hwnd
        and int(last_external_hwnd) not in browser_handles
        and _user32.IsWindow(int(last_external_hwnd))
    ):
        _user32.SetForegroundWindow(int(last_external_hwnd))
    return int(last_external_hwnd or 0), moved


def _windows_process_running(pid: int) -> bool:
    if os.name != "nt" or pid <= 0:
        return False

    try:
        return psutil.Process(pid).is_running()
    except (psutil.Error, OSError):
        return False


def _stop_background_guard():
    stop_event = getattr(_tls, "background_guard_stop", None)
    if stop_event is not None:
        stop_event.set()
    _tls.background_guard_stop = None
    _tls.background_guard_thread = None


def _start_background_guard(browser_obj, previous_foreground=0, log_callback=None):
    _stop_background_guard()
    if os.name != "nt":
        return
    try:
        root_pid = int(getattr(browser_obj, "process_id", 0) or 0)
    except Exception:
        root_pid = 0
    if root_pid <= 0:
        if log_callback:
            log_callback("[Debug] 无法取得浏览器 PID，未设置窗口/进程优先级")
        return

    stop_event = threading.Event()
    _tls.background_guard_stop = stop_event
    known_process_ids: set[int] = set()

    def _apply(last_external):
        process_ids = _windows_process_tree(root_pid)
        new_process_ids = process_ids - known_process_ids
        changed_process_ids = _set_idle_priority(new_process_ids)
        known_process_ids.update(changed_process_ids)
        last_external, windows = _send_windows_to_back(process_ids, last_external)
        return last_external, len(changed_process_ids), windows

    try:
        last_external, changed, windows = _apply(previous_foreground)
        if log_callback:
            log_callback(
                f"[Debug] GUI 浏览器已降至最低优先级并置底（进程={changed}，窗口={windows}）"
            )
    except Exception as exc:
        last_external = previous_foreground
        if log_callback:
            log_callback(f"[Debug] 设置浏览器窗口/进程优先级失败: {exc}")

    def _guard():
        nonlocal last_external
        while not stop_event.wait(2.0):
            if not _windows_process_running(root_pid):
                break
            try:
                last_external, _, _ = _apply(last_external)
            except Exception:
                pass

    guard_thread = threading.Thread(
        target=_guard,
        name=f"browser-background-{root_pid}",
        daemon=True,
    )
    _tls.background_guard_thread = guard_thread
    guard_thread.start()


class _SessionProxy:
    __slots__ = ("_key",)

    def __init__(self, key):
        self._key = key

    def _obj(self):
        return getattr(_tls, self._key, None)

    def __bool__(self):
        return self._obj() is not None

    def __eq__(self, other):
        return self._obj() is other

    def __ne__(self, other):
        return self._obj() is not other

    def __getattr__(self, name):
        obj = self._obj()
        if obj is None:
            raise AttributeError(f"{self._key} is not started")
        return getattr(obj, name)


browser = _SessionProxy("browser")
page = _SessionProxy("page")


def _free_local_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        try:
            sock.close()
        except Exception:
            pass


def create_browser_options(unique_profile=True):
    """创建 ChromiumOptions。

    注意：DrissionPage 下 set_user_data_path 会破坏 auto_port() 的 address
    （触发 not enough values to unpack）。并发隔离应使用：
    set_local_port(空闲端口) + set_user_data_path(独立目录)。
    """
    options = ChromiumOptions()
    options.set_timeouts(base=1)
    proxies = _proxies()
    proxy = str(proxies.get("https") or proxies.get("http") or "").strip()
    if proxy:
        options.set_proxy(proxy)
    if unique_profile:
        profile_dir = os.path.join(
            tempfile.gettempdir(),
            "grok-register-chrome",
            f"{os.getpid()}-{threading.get_ident()}-{uuid.uuid4().hex[:8]}",
        )
        os.makedirs(profile_dir, exist_ok=True)
        port = _free_local_port()
        options.set_local_port(port)
        options.set_user_data_path(profile_dir)
        _tls.profile_dir = profile_dir
        _tls.debug_port = port
    else:
        options.auto_port()
    if _extension_path and os.path.exists(_extension_path):
        options.add_extension(_extension_path)
    if _headless:
        try:
            options.headless(True)
        except Exception:
            options.set_argument("--headless=new")
        options.set_argument("--disable-gpu")
        options.set_argument("--window-size=1280,900")
        options.set_argument("--no-sandbox")
        options.set_argument("--disable-dev-shm-usage")
        options.set_argument("--disable-blink-features=AutomationControlled")
    elif _keep_windows_background:
        # 有界面内核过 CF，但启动即屏外+最小化，尽量不闪窗
        options.set_argument("--window-position=-32000,-32000")
        options.set_argument("--window-size=800,600")
        options.set_argument("--start-minimized")
        options.set_argument("--disable-blink-features=AutomationControlled")
    return options


def start_browser(log_callback=None, cancel_callback=None) -> Tuple[object, object]:
    def cancelled():
        return bool(cancel_callback and cancel_callback())

    last_exc = None
    for attempt in range(1, 5):
        if cancelled():
            raise RuntimeError("用户已停止")
        browser_obj = None
        try:
            previous_foreground = 0
            if _keep_windows_background and os.name == "nt":
                previous_foreground = _get_foreground_window()
            browser_obj = Chromium(create_browser_options(unique_profile=True))
            if cancelled():
                raise RuntimeError("用户已停止")
            tabs = browser_obj.get_tabs()
            page_obj = tabs[-1] if tabs else browser_obj.new_tab()
            set_browser_session(browser_obj, page_obj)
            if _keep_windows_background:
                _start_background_guard(
                    browser_obj,
                    previous_foreground=previous_foreground,
                    log_callback=log_callback,
                )
            _note_start_success()
            profile = getattr(_tls, "profile_dir", None) or getattr(browser_obj, "user_data_path", None)
            if log_callback and profile:
                log_callback(f"[Debug] 当前浏览器资料目录: {profile}")
            if log_callback and attempt > 1:
                log_callback(f"[*] 浏览器第 {attempt} 次启动成功")
            return browser_obj, page_obj
        except Exception as exc:
            last_exc = exc
            streak = _note_start_failure()
            _stop_background_guard()
            if log_callback:
                log_callback(f"[Debug] 浏览器启动失败(第{attempt}/4次, 连续失败{streak}): {exc}")
            try:
                cur = active_browser()
                if cur is None:
                    cur = browser_obj
                if cur is not None:
                    cur.quit(del_data=True)
            except Exception:
                pass
            set_browser_session(None, None)
            if cancelled():
                raise RuntimeError("用户已停止") from exc
            deadline = time.monotonic() + min(1.5 * attempt, 4)
            while time.monotonic() < deadline:
                if cancelled():
                    raise RuntimeError("用户已停止") from exc
                time.sleep(min(0.1, max(deadline - time.monotonic(), 0)))
    raise Exception(f"浏览器启动失败，已重试4次: {last_exc}")


def stop_browser():
    _stop_background_guard()
    current = active_browser()
    set_browser_session(None, None)
    if current is None:
        return
    try:
        current.quit(del_data=True)
    except BaseException:
        pass


def restart_browser(log_callback=None, cancel_callback=None):
    stop_browser()
    return start_browser(
        log_callback=log_callback,
        cancel_callback=cancel_callback,
    )


def cleanup_runtime_memory(log_callback=None, reason="定期清理"):
    try:
        if log_callback:
            log_callback(f"[*] {reason}: 关闭浏览器并清理内存")
        stop_browser()
        collected = gc.collect()
        if log_callback:
            log_callback(f"[*] Python GC 已回收对象数: {collected}")
    except BaseException:
        try:
            stop_browser()
        except BaseException:
            pass


def refresh_active_page():
    if active_browser() is None:
        restart_browser()
    try:
        browser_obj = active_browser()
        tabs = browser_obj.get_tabs()
        page_obj = tabs[-1] if tabs else browser_obj.new_tab()
        set_browser_session(browser_obj, page_obj)
    except Exception:
        restart_browser()
    return page


def extract_cf_clearance_and_ua(log_callback=None, ensure_grok=True):
    """提取 grok.com 域 cf_clearance + UA。"""
    cf_clearance = ""
    user_agent = ""
    try:
        active = refresh_active_page()
        if active is None:
            return "", ""

        def _read_cf_and_ua(page_obj, grok_only=False):
            clearance = ""
            ua_text = ""
            cookies = page_obj.cookies(all_domains=True, all_info=True) or []
            for item in cookies:
                if isinstance(item, dict):
                    name = str(item.get("name", "")).strip()
                    value = str(item.get("value", "")).strip()
                    domain = str(item.get("domain", "")).strip().lower()
                else:
                    name = str(getattr(item, "name", "")).strip()
                    value = str(getattr(item, "value", "")).strip()
                    domain = str(getattr(item, "domain", "")).strip().lower()
                if name != "cf_clearance" or not value:
                    continue
                if grok_only and "grok.com" not in domain:
                    continue
                if "grok.com" in domain:
                    clearance = value
                    break
                if not clearance and not grok_only:
                    clearance = value
            try:
                ua = page_obj.run_js("return navigator.userAgent;")
                if ua:
                    ua_text = str(ua).strip()
            except Exception:
                pass
            return clearance, ua_text

        def _page_passed_cf(page_obj):
            try:
                title = str(page_obj.run_js("return document.title || '';") or "").lower()
                body = str(
                    page_obj.run_js(
                        "return (document.body && (document.body.innerText||'')) || '';"
                    )
                    or ""
                ).lower()
                if "just a moment" in title or "just a moment" in body[:200]:
                    return False
                if "checking your browser" in body[:300]:
                    return False
                return True
            except Exception:
                return False

        cf_clearance, user_agent = _read_cf_and_ua(active, grok_only=True)
        if ensure_grok and not cf_clearance:
            if log_callback:
                log_callback("[*] 未找到 grok.com 的 cf_clearance，打开 grok.com 过盾...")
            try:
                active.get("https://grok.com/")
                try:
                    active.wait.doc_loaded()
                except Exception:
                    pass
                time.sleep(2)
                for _ in range(20):
                    if _page_passed_cf(active):
                        cf_clearance, user_agent = _read_cf_and_ua(active, grok_only=True)
                        if cf_clearance:
                            break
                    time.sleep(1.0)
                if log_callback:
                    if cf_clearance:
                        log_callback("[*] 已取得 grok.com 的 cf_clearance")
                    else:
                        log_callback(
                            "[!] 打开 grok.com 后仍无有效 cf_clearance（页面可能仍卡在 Just a moment）"
                        )
            except Exception as nav_exc:
                if log_callback:
                    log_callback(f"[Debug] 打开 grok.com 取 cf_clearance 失败: {nav_exc}")
                cf_clearance, user_agent = _read_cf_and_ua(active, grok_only=True)
    except Exception as exc:
        if log_callback:
            log_callback(f"[Debug] 提取 cf_clearance 失败: {exc}")
    return cf_clearance, user_agent
