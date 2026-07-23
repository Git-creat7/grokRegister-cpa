# -*- coding: utf-8 -*-
"""协议注册 S/P/C/O 流水线（对齐 grok-register-new pipeline）。

S: 预 mint Turnstile token
P: 建邮 + CreateEmailCode + 等码 → Q
C: 取 token + Q → Verify + Signup → SSO
O: Device Flow / CPA（可选，由 on_sso 回调处理）
"""
from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple

import protocol_signup as ps

LogFn = Optional[Callable[[str], None]]
StopFn = Optional[Callable[[], bool]]
EmailFactory = Callable[[], Tuple[str, str]]
CodePoller = Callable[..., str]
OnSSO = Callable[[str, str, str, Dict[str, Any]], None]  # email, password, sso, profile


def _log(fn: LogFn, msg: str) -> None:
    if fn:
        fn(msg)


def _stopped(cb: StopFn) -> bool:
    if not cb:
        return False
    try:
        return bool(cb())
    except Exception:
        return False


@dataclass
class QItem:
    email: str
    password: str
    code: str
    given: str
    family: str
    ready_at: float = field(default_factory=time.time)


@dataclass
class SSOJob:
    email: str
    password: str
    sso: str
    profile: Dict[str, Any]


@dataclass
class PipelineStats:
    sso_ok: int = 0
    done: int = 0  # O 阶段完成（CPA/回调）
    fail: int = 0
    mint_ok: int = 0
    q_ok: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def add_sso(self) -> int:
        with self.lock:
            self.sso_ok += 1
            return self.sso_ok

    def add_done(self) -> int:
        with self.lock:
            self.done += 1
            return self.done

    def add_fail(self) -> None:
        with self.lock:
            self.fail += 1

    def add_mint(self) -> None:
        with self.lock:
            self.mint_ok += 1

    def add_q(self) -> None:
        with self.lock:
            self.q_ok += 1


def derive_workers(
    target: int, register_workers: int = 1
) -> Tuple[int, int, int, int, int]:
    """返回 (s, p, c, o, phys_mint)。Turnstile 浏览器默认 phys=1。"""
    target = max(1, int(target or 1))
    rw = max(1, min(int(register_workers or 1), 8))
    s = 1
    phys = 1
    p = min(4, max(1, min(target, rw + 1)))
    c = min(2, max(1, target // 2 or 1))
    o = min(2, max(1, min(target, rw)))
    if target == 1:
        p, c, o = 1, 1, 1
    return s, p, c, o, phys


class ProtocolPipeline:
    def __init__(
        self,
        *,
        target: int,
        proxy: str = "",
        get_email_and_token: EmailFactory,
        get_oai_code: CodePoller,
        on_sso: OnSSO,
        log: LogFn = None,
        should_stop: StopFn = None,
        register_workers: int = 1,
        token_ttl: float = 240.0,
        q_ttl: float = 120.0,
    ):
        self.target = max(1, int(target))
        self.proxy = (proxy or "").strip()
        self.get_email_and_token = get_email_and_token
        self.get_oai_code = get_oai_code
        self.on_sso = on_sso
        self.log = log
        self.should_stop = should_stop
        self.token_ttl = max(60.0, float(token_ttl))
        self.q_ttl = max(30.0, float(q_ttl))
        self.s_n, self.p_n, self.c_n, self.o_n, self.phys = derive_workers(
            self.target, register_workers
        )
        self.stats = PipelineStats()
        self._t_q: queue.Queue = queue.Queue(maxsize=max(2, min(6, self.target)))
        self._q_q: queue.Queue = queue.Queue(maxsize=max(2, min(6, self.target)))
        self._oauth_q: queue.Queue = queue.Queue(maxsize=max(8, self.target * 2))
        self._mint_sem = threading.Semaphore(self.phys)
        self._q_pending = threading.Semaphore(max(2, min(6, self.target)))
        self._cfg: Dict[str, str] = {}
        self._threads: list[threading.Thread] = []
        self._oauth_threads: list[threading.Thread] = []
        self._done_event = threading.Event()
        self._reg_done = threading.Event()

    def _alive(self) -> bool:
        if _stopped(self.should_stop):
            return False
        if self.stats.sso_ok >= self.target:
            return False
        return not self._done_event.is_set()

    def run(self) -> PipelineStats:
        self._cfg = ps.get_cached_config(
            proxy=self.proxy,
            should_stop=self.should_stop,
            log=self.log,
        )
        _log(
            self.log,
            f"[pipeline] S={self.s_n} P={self.p_n} C={self.c_n} O={self.o_n} "
            f"phys={self.phys} target={self.target}",
        )
        for i in range(self.s_n):
            t = threading.Thread(target=self._s_worker, args=(i,), daemon=True)
            t.start()
            self._threads.append(t)
        for i in range(self.p_n):
            t = threading.Thread(target=self._p_worker, args=(i,), daemon=True)
            t.start()
            self._threads.append(t)
        for i in range(self.c_n):
            t = threading.Thread(target=self._c_worker, args=(i,), daemon=True)
            t.start()
            self._threads.append(t)
        for i in range(self.o_n):
            t = threading.Thread(target=self._o_worker, args=(i,), daemon=True)
            t.start()
            self._oauth_threads.append(t)

        try:
            while self._alive():
                time.sleep(0.25)
                if self.stats.sso_ok >= self.target:
                    break
                if _stopped(self.should_stop):
                    break
        finally:
            self._done_event.set()
            self._reg_done.set()
            for _ in range(self.s_n + self.p_n + self.c_n + 2):
                try:
                    self._t_q.put_nowait(None)
                except Exception:
                    pass
                try:
                    self._q_q.put_nowait(None)
                except Exception:
                    pass
            deadline = time.time() + 20
            for t in self._threads:
                remain = max(0.05, deadline - time.time())
                t.join(timeout=remain)
            # 关闭 O 队列并等 CPA 收尾
            for _ in range(self.o_n + 1):
                try:
                    self._oauth_q.put_nowait(None)
                except Exception:
                    pass
            deadline = time.time() + 120
            for t in self._oauth_threads:
                remain = max(0.05, deadline - time.time())
                t.join(timeout=remain)
        _log(
            self.log,
            f"[pipeline] 结束 sso={self.stats.sso_ok} done={self.stats.done} "
            f"fail={self.stats.fail} mint={self.stats.mint_ok} q={self.stats.q_ok}",
        )
        return self.stats

    def _s_worker(self, wid: int) -> None:
        site_key = self._cfg.get("site_key") or ""
        while self._alive():
            # 控制 token 池深度，避免过期浪费
            if self._t_q.qsize() >= max(1, min(3, self.target - self.stats.sso_ok)):
                time.sleep(0.4)
                continue
            if not self._mint_sem.acquire(timeout=0.5):
                continue
            try:
                if not self._alive():
                    return
                tok = ps.mint_turnstile(
                    site_key,
                    page_url=ps.SIGNUP_PAGE_URL,
                    proxy=self.proxy,
                    log=lambda m: _log(self.log, f"[S{wid+1}] {m}"),
                    should_stop=self.should_stop,
                    retries=2,
                )
                self.stats.add_mint()
                item = (tok, time.time())
                while self._alive():
                    try:
                        self._t_q.put(item, timeout=0.5)
                        break
                    except queue.Full:
                        continue
            except Exception as exc:
                _log(self.log, f"[S{wid+1}] turnstile: {exc}")
                time.sleep(1.5)
            finally:
                self._mint_sem.release()

    def _p_worker(self, wid: int) -> None:
        while self._alive():
            remaining = self.target - self.stats.sso_ok
            if remaining <= 0:
                return
            # 控制 Q 深度
            qcap = min(4, max(1, remaining))
            if self._q_q.qsize() >= qcap:
                time.sleep(0.5)
                continue
            if not self._q_pending.acquire(timeout=0.5):
                continue
            mail_cli = ps.ProtocolClient(proxy=self.proxy)
            try:
                if not self._alive():
                    return
                email, dev_token = self.get_email_and_token()
                if not email:
                    raise RuntimeError("获取邮箱失败")
                password = ps.generate_password()
                given = __import__("random").choice(ps._GIVEN)
                family = __import__("random").choice(ps._FAMILY)
                _log(self.log, f"[P{wid+1}] 邮箱 {email}")
                mail_cli.create_email_code(email)
                code = self.get_oai_code(
                    dev_token,
                    email,
                    log_callback=lambda m: _log(self.log, f"[P{wid+1}] {m}"),
                    cancel_callback=self.should_stop,
                )
                if not code:
                    raise RuntimeError("获取验证码失败")
                clean = str(code).replace("-", "").strip()
                item = QItem(
                    email=email,
                    password=password,
                    code=clean,
                    given=given,
                    family=family,
                )
                while self._alive():
                    try:
                        self._q_q.put(item, timeout=0.5)
                        self.stats.add_q()
                        break
                    except queue.Full:
                        continue
            except Exception as exc:
                _log(self.log, f"[P{wid+1}] {exc}")
                self.stats.add_fail()
                time.sleep(0.8)
            finally:
                self._q_pending.release()

    def _claim_pair(self) -> Optional[Tuple[str, QItem]]:
        """取一对未过期的 (token, Q)。"""
        token = None
        qitem = None
        while self._alive() and token is None:
            try:
                raw = self._t_q.get(timeout=0.5)
            except queue.Empty:
                return None
            if raw is None:
                return None
            tok, ts = raw
            if time.time() - ts > self.token_ttl:
                continue
            token = tok
        while self._alive() and qitem is None:
            try:
                raw = self._q_q.get(timeout=0.5)
            except queue.Empty:
                # 退还 token
                if token:
                    try:
                        self._t_q.put_nowait((token, time.time()))
                    except Exception:
                        pass
                return None
            if raw is None:
                if token:
                    try:
                        self._t_q.put_nowait((token, time.time()))
                    except Exception:
                        pass
                return None
            if time.time() - raw.ready_at > self.q_ttl:
                continue
            qitem = raw
        if token and qitem:
            return token, qitem
        return None

    def _c_worker(self, wid: int) -> None:
        while self._alive():
            pair = self._claim_pair()
            if not pair:
                time.sleep(0.2)
                continue
            token, q = pair
            _log(self.log, f"[C{wid+1}] 注册 {q.email}")
            cli = ps.ProtocolClient(proxy=self.proxy)
            try:
                cli.clear_auth_cookies()
                cli.verify_email_code(q.email, q.code)
                body = ps.build_signup_body(q.email, q.password, q.code, token)
                body_obj = __import__("json").loads(body.decode("utf-8"))
                body_obj[0]["createUserAndSessionRequest"]["givenName"] = q.given
                body_obj[0]["createUserAndSessionRequest"]["familyName"] = q.family
                body = __import__("json").dumps(body_obj, separators=(",", ":")).encode(
                    "utf-8"
                )
                text, sso = cli.signup_server_action(
                    body, self._cfg["action_id"], self._cfg["state_tree"]
                )
                if not sso:
                    sso = ps.extract_sso_from_text(text)
                if not sso:
                    raise RuntimeError(f"signup 无 SSO: {(text or '')[:160]}")
                n = self.stats.add_sso()
                profile = {
                    "given_name": q.given,
                    "family_name": q.family,
                    "password": q.password,
                }
                _log(self.log, f"[C{wid+1}] [+] SSO #{n} {q.email}")
                job = SSOJob(
                    email=q.email, password=q.password, sso=sso, profile=profile
                )
                while True:
                    if _stopped(self.should_stop) and self.stats.sso_ok >= self.target:
                        break
                    try:
                        self._oauth_q.put(job, timeout=0.5)
                        break
                    except queue.Full:
                        if self._done_event.is_set():
                            break
                        continue
            except Exception as exc:
                _log(self.log, f"[C{wid+1}] signup fail {q.email}: {exc}")
                self.stats.add_fail()

    def _o_worker(self, wid: int) -> None:
        while True:
            try:
                job = self._oauth_q.get(timeout=0.5)
            except queue.Empty:
                if self._reg_done.is_set() and self._oauth_q.empty():
                    return
                if _stopped(self.should_stop) and self._oauth_q.empty():
                    return
                continue
            if job is None:
                return
            try:
                self.on_sso(job.email, job.password, job.sso, job.profile)
                d = self.stats.add_done()
                _log(self.log, f"[O{wid+1}] 完成 #{d} {job.email}")
            except Exception as exc:
                _log(self.log, f"[O{wid+1}] {job.email}: {exc}")
                self.stats.add_fail()
