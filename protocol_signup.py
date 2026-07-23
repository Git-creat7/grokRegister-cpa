# -*- coding: utf-8 -*-
"""纯 HTTP 协议注册（对齐 grok-register-new/internal/protocol/xai.go）。

路径：FetchConfig → Turnstile mint → CreateEmailCode → 收码 →
VerifyEmailCode → SignupServerAction → 跟随 set-cookie hop 拿 SSO。

不启动 DrissionPage 注册页，避免 UI 路径打上 bot_flag_source=1。
Turnstile 仅用 Playwright 短生命周期 headless Chrome（mint 脚本）。
"""
from __future__ import annotations

import base64
import json
import os
import random
import re
import secrets
import struct
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import unquote, urljoin, urlparse

from curl_cffi import requests

# 进程内 signup config 缓存（site_key / action_id / state_tree）
_CFG_LOCK = threading.Lock()
_CFG_CACHE: Optional[Dict[str, str]] = None
_CFG_CACHE_AT = 0.0
_CFG_TTL_SEC = float(os.environ.get("GROK_SIGNUP_CFG_TTL", "1200") or "1200")

SITE_URL = "https://accounts.x.ai"
CONNECT_CREATE = f"{SITE_URL}/auth_mgmt.AuthManagement/CreateEmailValidationCode"
CONNECT_VERIFY = f"{SITE_URL}/auth_mgmt.AuthManagement/VerifyEmailValidationCode"
SIGNUP_URL = f"{SITE_URL}/sign-up?redirect=grok-com"
SIGNUP_PAGE_URL = f"{SITE_URL}/sign-up"
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)

_SITE_KEY_RE = re.compile(r"0x4AAAAAAA[a-zA-Z0-9_-]+")
_JS_SRC_RE = re.compile(r'src="(/_next/static/[^"]+\.js)"')
_HEX40_RE = re.compile(r"[a-fA-F0-9]{40,50}")
_FLIGHT_RE = re.compile(r'self\.__next_f\.push\(\[1,"(.*?)"\]\)')
_SET_COOKIE_URL_RE = re.compile(
    r"https?://[^\s\"'<>\\]+set-cookie/?\?q=eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"
)
_SET_COOKIE_REL_RE = re.compile(
    r"(/[A-Za-z0-9_./-]*set-cookie/?\?q=eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)"
)
_JWT_RE = re.compile(r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+")
_SSO_NAMED_RE = re.compile(
    r"(?i)(?:^|[;,\s'\"\\])sso=(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)"
)
_SSO_NEAR_RE = re.compile(
    r"(?i)(?:sso|session)[^e]{0,40}(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)"
)

_GIVEN = [
    "James", "John", "Robert", "Michael", "William", "David", "Richard",
    "Joseph", "Thomas", "Charles", "Neo", "Ethan", "Liam", "Noah", "Lucas",
]
_FAMILY = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Rodriguez", "Martinez", "Lin", "Wang", "Zhao", "Liu", "Chen",
]


def _log(fn: Optional[Callable], msg: str) -> None:
    if fn:
        fn(msg)


def _cancelled(cb: Optional[Callable[[], bool]]) -> bool:
    return bool(cb and cb())


def _pb_str(field: int, s: str) -> bytes:
    data = s.encode("utf-8")
    tag = bytes([((field << 3) | 2) & 0xFF])
    return tag + _pb_varint(len(data)) + data


def _pb_varint(n: int) -> bytes:
    parts = bytearray()
    while n > 0x7F:
        parts.append((n & 0x7F) | 0x80)
        n >>= 7
    parts.append(n & 0x7F)
    return bytes(parts)


def _grpc_web_frame(inner: bytes) -> bytes:
    return b"\x00" + struct.pack(">I", len(inner)) + inner


def _b64url_json(payload: str) -> Optional[dict]:
    pad = "=" * (-len(payload) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload + pad)
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None


def jwt_payload_map(token: str) -> Optional[dict]:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    return _b64url_json(parts[1])


def is_session_sso(tok: str) -> bool:
    if not tok or not tok.startswith("eyJ") or tok.count(".") != 2:
        return False
    payload = jwt_payload_map(tok)
    if payload is None:
        return len(tok) > 80
    cfg = payload.get("config")
    if isinstance(cfg, dict):
        if "success_url" in cfg or "token" in cfg:
            return False
    if "success_url" in payload:
        return False
    return len(tok) > 40


def normalize_rsc(text: str) -> str:
    t = text or ""
    t = t.replace("\\u0026", "&").replace("\\u003d", "=").replace("\\u002F", "/")
    t = t.replace("\\/", "/")
    return t


def extract_sso_from_text(text: str) -> str:
    body = normalize_rsc(text)
    m = _SSO_NAMED_RE.search(body)
    if m and is_session_sso(m.group(1)):
        return m.group(1)
    m = _SSO_NEAR_RE.search(body)
    if m and is_session_sso(m.group(1)):
        return m.group(1)
    for j in _JWT_RE.findall(body):
        if is_session_sso(j):
            return j
    return ""


def scrape_state_tree(html: str) -> str:
    for ch in _FLIGHT_RE.findall(html or ""):
        decoded = ch.replace(r"\"", '"')
        if "sign-up" not in decoded:
            continue
        idx = decoded.find('"f":[[[')
        if idx < 0:
            continue
        f_start = idx + 5
        end = decoded.find('"$undefined"', f_start)
        if end < 0:
            continue
        raw = decoded[f_start:end]
        raw = raw.replace(r'\\"', '"').replace("\\", "")
        from urllib.parse import quote

        return quote(raw, safe="")
    return ""


def build_signup_body(email: str, password: str, code: str, turnstile_token: str) -> bytes:
    given = random.choice(_GIVEN)
    family = random.choice(_FAMILY)
    payload = [
        {
            "emailValidationCode": code,
            "createUserAndSessionRequest": {
                "email": email,
                "givenName": given,
                "familyName": family,
                "clearTextPassword": password,
                "tosAcceptedVersion": "$undefined",
            },
            "turnstileToken": turnstile_token,
            "conversionId": str(uuid.uuid4()),
            "castleRequestToken": "",
        },
        {
            "client": "$T",
            "meta": "$undefined",
            "mutationKey": "$undefined",
        },
    ]
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def generate_password() -> str:
    return "N" + secrets.token_hex(4) + "!a7#" + secrets.token_urlsafe(6)


def extract_all_set_cookie_urls(text: str) -> List[str]:
    body = normalize_rsc(text)
    found: List[str] = []
    seen = set()

    def add(u: str) -> None:
        u = (u or "").strip()
        if not u or u in seen:
            return
        seen.add(u)
        found.append(u)

    for m in _SET_COOKIE_URL_RE.findall(body):
        add(m)
    for m in _SET_COOKIE_REL_RE.findall(body):
        add(SITE_URL + m)
    if not found:
        low = body.lower()
        idx = low.find("set-cookie")
        if idx >= 0:
            window = body[idx : idx + 400]
            j = _JWT_RE.search(window)
            if j:
                add("https://auth.grokusercontent.com/set-cookie?q=" + j.group(0))
    return found


def jwt_from_set_cookie_url(u: str) -> str:
    raw = unquote(u or "")
    i = raw.find("q=")
    if i >= 0:
        rest = raw[i + 2 :]
        for sep in ("&", '"', "'", " "):
            j = rest.find(sep)
            if j >= 0:
                rest = rest[:j]
        if rest.startswith("eyJ"):
            return rest
    m = _JWT_RE.search(raw)
    return m.group(0) if m else ""


def expand_sso_hop_urls(urls: List[str]) -> List[str]:
    out: List[str] = []
    seen = set()

    def add(u: str) -> None:
        if not u or u in seen:
            return
        seen.add(u)
        out.append(u)

    for u in urls:
        add(u)
        jwt = jwt_from_set_cookie_url(u)
        if not jwt:
            continue
        payload = jwt_payload_map(jwt)
        if payload:
            cfg = payload.get("config")
            if isinstance(cfg, dict):
                s = cfg.get("success_url")
                if isinstance(s, str) and s.startswith("https://"):
                    add(s)
                    if "set-cookie" in s and "q=" not in s:
                        add(s.rstrip("/") + "?q=" + jwt)
            s2 = payload.get("success_url")
            if isinstance(s2, str) and s2.startswith("https://"):
                add(s2)
        add("https://auth.grokusercontent.com/set-cookie?q=" + jwt)
    return out


def _find_mint_script() -> str:
    env = (os.environ.get("GROK_TURNSTILE_SCRIPT") or "").strip()
    if env and os.path.isfile(env):
        return env
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "scripts", "turnstile_mint.py"),
        os.path.join(here, "..", "grok-register-new", "scripts", "turnstile_mint.py"),
    ]
    for p in candidates:
        if os.path.isfile(p):
            return os.path.abspath(p)
    return ""


def _find_chrome() -> str:
    env = (os.environ.get("CHROME_PATH") or "").strip()
    if env and os.path.isfile(env):
        return env
    localapp = os.environ.get("LOCALAPPDATA") or ""
    pf = os.environ.get("PROGRAMFILES") or r"C:\Program Files"
    pf86 = os.environ.get("PROGRAMFILES(X86)") or r"C:\Program Files (x86)"
    for p in (
        os.path.join(pf, "Google", "Chrome", "Application", "chrome.exe"),
        os.path.join(pf86, "Google", "Chrome", "Application", "chrome.exe"),
        os.path.join(localapp, "Google", "Chrome", "Application", "chrome.exe") if localapp else "",
        os.path.join(pf, "Microsoft", "Edge", "Application", "msedge.exe"),
    ):
        if p and os.path.isfile(p):
            return p
    return ""


def get_cached_config(
    proxy: str = "",
    should_stop: Optional[Callable[[], bool]] = None,
    log: Optional[Callable] = None,
    force: bool = False,
    client: Optional["ProtocolClient"] = None,
) -> Dict[str, str]:
    """进程内复用 signup config，默认 TTL 20 分钟。"""
    global _CFG_CACHE, _CFG_CACHE_AT
    now = time.time()
    with _CFG_LOCK:
        if (
            not force
            and _CFG_CACHE
            and _CFG_CACHE.get("site_key")
            and _CFG_CACHE.get("action_id")
            and _CFG_CACHE.get("state_tree")
            and (now - _CFG_CACHE_AT) < max(60.0, _CFG_TTL_SEC)
        ):
            return dict(_CFG_CACHE)
    cli = client or ProtocolClient(proxy=proxy)
    _log(log, "[*] 协议注册：获取 signup config ...")
    cfg = cli.fetch_config(should_stop=should_stop)
    with _CFG_LOCK:
        _CFG_CACHE = {
            "site_key": cfg["site_key"],
            "action_id": cfg["action_id"],
            "state_tree": cfg["state_tree"],
        }
        _CFG_CACHE_AT = time.time()
        out = dict(_CFG_CACHE)
    _log(
        log,
        f"[*] SITE_KEY={out['site_key'][:16]}... ACTION={out['action_id'][:12]}... (cached)",
    )
    return out


def clear_config_cache() -> None:
    global _CFG_CACHE, _CFG_CACHE_AT
    with _CFG_LOCK:
        _CFG_CACHE = None
        _CFG_CACHE_AT = 0.0


def mint_turnstile(
    site_key: str,
    page_url: str = SIGNUP_PAGE_URL,
    proxy: str = "",
    timeout: float = 90,
    log: Optional[Callable] = None,
    should_stop: Optional[Callable[[], bool]] = None,
    retries: int = 3,
) -> str:
    if _cancelled(should_stop):
        raise RuntimeError("用户已停止")
    script = _find_mint_script()
    if not script:
        raise RuntimeError("未找到 turnstile_mint.py（scripts/ 或 GROK_TURNSTILE_SCRIPT）")
    chrome = _find_chrome()
    last_err = ""
    for attempt in range(1, max(1, retries) + 1):
        if _cancelled(should_stop):
            raise RuntimeError("用户已停止")
        args = [
            sys.executable,
            script,
            "--site-key",
            site_key,
            "--url",
            page_url or SIGNUP_PAGE_URL,
            "--timeout",
            str(int(timeout)),
            "--no-headless",
        ]
        if proxy:
            args.extend(["--proxy", proxy])
        if chrome:
            args.extend(["--chrome", chrome])
        _log(
            log,
            f"[*] Turnstile mint attempt {attempt}/{retries} "
            f"(chrome={bool(chrome)}, proxy={bool(proxy)}, headed-offscreen) ...",
        )
        creationflags = 0
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout + 30,
                creationflags=creationflags,
            )
        except subprocess.TimeoutExpired as exc:
            last_err = f"timeout: {exc}"
            _log(log, f"[!] Turnstile mint timeout, retry...")
            continue
        out = (proc.stdout or "").strip()
        err = (proc.stderr or "").strip()
        if proc.returncode == 0 and len(out) > 10:
            if "\n" in out:
                out = out.split("\n", 1)[0].strip()
            _log(log, f"[*] Turnstile token ok (len={len(out)})")
            return out
        last_err = (err or out or "empty")[:300]
        _log(log, f"[!] Turnstile mint failed: {last_err}")
        time.sleep(min(2 * attempt, 6))
    raise RuntimeError(f"turnstile mint 失败: {last_err}")


class ProtocolClient:
    def __init__(self, proxy: str = "", user_agent: str = ""):
        self.proxy = (proxy or "").strip()
        self.ua = user_agent or DEFAULT_UA
        self.session = requests.Session()
        if self.proxy:
            self.session.proxies = {"http": self.proxy, "https": self.proxy}
        self.cfg: Dict[str, str] = {}

    def _browser_headers(self, extra: Optional[dict] = None) -> dict:
        h = {
            "User-Agent": self.ua,
            "Accept-Language": "en-US,en;q=0.9",
            "sec-ch-ua": '"Chromium";v="146", "Google Chrome";v="146", "Not_A Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        }
        if extra:
            h.update(extra)
        return h

    def _grpc_headers(self) -> dict:
        return self._browser_headers(
            {
                "Content-Type": "application/grpc-web+proto",
                "X-Grpc-Web": "1",
                "X-User-Agent": "connect-es/2.1.1",
                "Origin": SITE_URL,
                "Referer": SIGNUP_URL,
                "Accept": "*/*",
            }
        )

    def clear_auth_cookies(self) -> None:
        # curl_cffi cookie jar: drop sso / sso-rw by recreating session cookies carefully
        try:
            jar = self.session.cookies
            to_clear = []
            for c in list(jar):
                name = getattr(c, "name", "") or ""
                if name.lower() in ("sso", "sso-rw"):
                    to_clear.append(c)
            for c in to_clear:
                try:
                    jar.clear(c.domain, c.path, c.name)
                except Exception:
                    try:
                        del jar[c.name]
                    except Exception:
                        pass
        except Exception:
            pass

    def _request(self, method: str, url: str, **kwargs):
        kwargs.setdefault("timeout", 45)
        # curl_cffi impersonate 偶发 TLS 失败：重试并降级
        last = None
        for imp in ("chrome", "chrome131", None):
            try:
                opts = dict(kwargs)
                if imp:
                    opts["impersonate"] = imp
                else:
                    opts.pop("impersonate", None)
                if method.upper() == "GET":
                    return self.session.get(url, **opts)
                return self.session.post(url, **opts)
            except Exception as exc:
                last = exc
                time.sleep(0.4)
        raise RuntimeError(f"request failed: {last}")

    def fetch_config(self, should_stop: Optional[Callable] = None) -> Dict[str, str]:
        if _cancelled(should_stop):
            raise RuntimeError("用户已停止")
        last_err = None
        html = ""
        for attempt in range(1, 4):
            if _cancelled(should_stop):
                raise RuntimeError("用户已停止")
            try:
                resp = self._request(
                    "GET",
                    SIGNUP_URL,
                    headers=self._browser_headers(
                        {
                            "Accept": "text/html,application/xhtml+xml",
                            "Referer": "https://grok.com/",
                        }
                    ),
                    timeout=45,
                    allow_redirects=True,
                )
                html = resp.text or ""
                if resp.status_code != 200 or "just a moment" in html.lower()[:500]:
                    last_err = RuntimeError(f"signup page blocked status={resp.status_code}")
                    time.sleep(attempt)
                    continue
                break
            except Exception as exc:
                last_err = exc
                time.sleep(attempt)
        else:
            raise RuntimeError(f"fetch config failed: {last_err}")
        site_key = ""
        m = _SITE_KEY_RE.search(html)
        if m:
            site_key = m.group(0)
        state_tree = scrape_state_tree(html)
        action_id = ""
        for path in _JS_SRC_RE.findall(html):
            if action_id:
                break
            if _cancelled(should_stop):
                raise RuntimeError("用户已停止")
            try:
                js_resp = self._request(
                    "GET",
                    SITE_URL + path,
                    headers=self._browser_headers({"Referer": SIGNUP_URL}),
                    timeout=30,
                )
                js = js_resp.text or ""
            except Exception:
                continue
            if not any(k in js for k in ("createUser", "registerUser", "emailValidation")):
                continue
            hexes = _HEX40_RE.findall(js)
            if hexes:
                action_id = hexes[0]
        if not site_key or not action_id or not state_tree:
            raise RuntimeError(
                f"config incomplete site_key={bool(site_key)} action={bool(action_id)} state={bool(state_tree)}"
            )
        self.cfg = {
            "site_key": site_key,
            "action_id": action_id,
            "state_tree": state_tree,
        }
        return self.cfg

    def create_email_code(self, email: str) -> None:
        frame = _grpc_web_frame(_pb_str(1, email))
        resp = self._request(
            "POST",
            CONNECT_CREATE,
            data=frame,
            headers=self._grpc_headers(),
            timeout=45,
        )
        st = resp.headers.get("grpc-status") or "0"
        if resp.status_code != 200 or (st not in ("", "0")):
            raise RuntimeError(f"create email http={resp.status_code} grpc={st}")

    def verify_email_code(self, email: str, code: str) -> None:
        inner = _pb_str(1, email) + _pb_str(2, code)
        frame = _grpc_web_frame(inner)
        resp = self._request(
            "POST",
            CONNECT_VERIFY,
            data=frame,
            headers=self._grpc_headers(),
            timeout=45,
        )
        st = resp.headers.get("grpc-status") or "0"
        if resp.status_code != 200 or (st not in ("", "0")):
            raise RuntimeError(f"verify email http={resp.status_code} grpc={st}")

    def _session_sso_from_cookies(self) -> str:
        try:
            for c in list(self.session.cookies):
                name = getattr(c, "name", "") or ""
                val = getattr(c, "value", "") or ""
                if name == "sso" and is_session_sso(val):
                    return val
        except Exception:
            pass
        # dict-like
        try:
            val = self.session.cookies.get("sso")
            if val and is_session_sso(str(val)):
                return str(val)
        except Exception:
            pass
        return ""

    def _follow_sso_hop(self, start: str) -> str:
        hops = expand_sso_hop_urls([start])
        seen = set()
        i = 0
        while i < len(hops) and i < 10:
            hop = hops[i]
            i += 1
            if not hop or hop in seen:
                continue
            seen.add(hop)
            try:
                resp = self._request(
                    "GET",
                    hop,
                    headers=self._browser_headers(
                        {
                            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                            "Referer": SITE_URL + "/",
                            "Sec-Fetch-Site": "cross-site",
                            "Sec-Fetch-Mode": "navigate",
                            "Sec-Fetch-Dest": "document",
                            "Upgrade-Insecure-Requests": "1",
                        }
                    ),
                    timeout=30,
                    allow_redirects=False,
                )
            except Exception:
                continue
            body = resp.text or ""
            # Set-Cookie on response
            try:
                for c in resp.cookies:
                    name = getattr(c, "name", "") or ""
                    val = getattr(c, "value", "") or ""
                    if name == "sso" and is_session_sso(val):
                        return val
            except Exception:
                pass
            sso = extract_sso_from_text(body)
            if is_session_sso(sso):
                return sso
            sso = self._session_sso_from_cookies()
            if sso:
                return sso
            loc = resp.headers.get("Location") or ""
            if loc.startswith("/"):
                if "grokusercontent" in hop:
                    loc = "https://auth.grokusercontent.com" + loc
                else:
                    loc = SITE_URL + loc
            if 300 <= resp.status_code < 400 and loc.startswith("http"):
                for extra in expand_sso_hop_urls([loc]):
                    if extra not in seen:
                        hops.append(extra)
        return self._session_sso_from_cookies()

    def signup_server_action(
        self,
        body: bytes,
        action_id: str,
        state_tree: str,
    ) -> Tuple[str, str]:
        resp = self._request(
            "POST",
            SIGNUP_URL,
            data=body,
            headers=self._browser_headers(
                {
                    "Accept": "text/x-component",
                    "Content-Type": "text/plain;charset=UTF-8",
                    "Next-Action": action_id,
                    "Next-Router-State-Tree": state_tree,
                    "Origin": SITE_URL,
                    "Referer": SIGNUP_URL,
                }
            ),
            timeout=60,
            allow_redirects=True,
        )
        text = resp.text or ""
        sso = ""
        try:
            for c in resp.cookies:
                name = getattr(c, "name", "") or ""
                val = getattr(c, "value", "") or ""
                if name == "sso" and is_session_sso(val):
                    sso = val
                    break
        except Exception:
            pass
        if not is_session_sso(sso):
            for hop in expand_sso_hop_urls(extract_all_set_cookie_urls(text)):
                v = self._follow_sso_hop(hop)
                if is_session_sso(v):
                    sso = v
                    break
        if not is_session_sso(sso):
            sso = self._session_sso_from_cookies()
        if not is_session_sso(sso):
            cand = extract_sso_from_text(text)
            if is_session_sso(cand):
                sso = cand
        if not is_session_sso(sso):
            sso = ""
        if resp.status_code >= 400:
            raise RuntimeError(f"signup http={resp.status_code} body={text[:200]}")
        return text, sso


def register_one(
    *,
    get_email_and_token: Callable[[], Tuple[str, str]],
    get_oai_code: Callable[..., str],
    proxy: str = "",
    log: Optional[Callable] = None,
    should_stop: Optional[Callable[[], bool]] = None,
    client: Optional[ProtocolClient] = None,
    cfg: Optional[Dict[str, str]] = None,
    turnstile_token: str = "",
) -> Dict[str, Any]:
    """完成一次协议注册，返回 email/password/sso/profile。

    优化：进程内 config 缓存；Turnstile mint 与 建邮+发码+等码 并行。
    """
    if _cancelled(should_stop):
        raise RuntimeError("用户已停止")
    cli = client or ProtocolClient(proxy=proxy)
    if not cfg:
        cfg = get_cached_config(
            proxy=proxy,
            should_stop=should_stop,
            log=log,
            client=cli,
        )
    password = generate_password()
    given = random.choice(_GIVEN)
    family = random.choice(_FAMILY)

    token_holder: Dict[str, Any] = {"token": (turnstile_token or "").strip(), "err": None}
    mail_holder: Dict[str, Any] = {
        "email": "",
        "dev_token": "",
        "code": "",
        "err": None,
    }

    def _mint_branch() -> None:
        if token_holder["token"]:
            return
        try:
            token_holder["token"] = mint_turnstile(
                cfg["site_key"],
                page_url=SIGNUP_PAGE_URL,
                proxy=proxy,
                log=log,
                should_stop=should_stop,
            )
        except Exception as exc:
            token_holder["err"] = exc

    def _mail_branch() -> None:
        # 并行用独立 session，避免与 mint 子进程无关的 cookie 争用
        mail_cli = ProtocolClient(proxy=proxy, user_agent=cli.ua)
        try:
            email, dev_token = get_email_and_token()
            if not email:
                raise RuntimeError("获取邮箱失败")
            mail_holder["email"] = email
            mail_holder["dev_token"] = dev_token
            _log(log, f"[*] 已创建邮箱: {email}")
            mail_cli.clear_auth_cookies()
            _log(log, "[*] CreateEmailCode ...")
            mail_cli.create_email_code(email)
            if _cancelled(should_stop):
                raise RuntimeError("用户已停止")
            _log(log, "[*] 等待验证码 ...")
            code = get_oai_code(
                dev_token,
                email,
                log_callback=log,
                cancel_callback=should_stop,
            )
            if not code:
                raise RuntimeError("获取验证码失败")
            mail_holder["code"] = str(code).replace("-", "").strip()
            # 复用 mail_cli 的 cookie 给后续 Verify/Signup
            mail_holder["client"] = mail_cli
        except Exception as exc:
            mail_holder["err"] = exc

    _log(log, "[*] Turnstile ∥ 建邮发码（并行）...")
    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_mint = pool.submit(_mint_branch)
        fut_mail = pool.submit(_mail_branch)
        fut_mint.result()
        fut_mail.result()

    if _cancelled(should_stop):
        raise RuntimeError("用户已停止")
    if token_holder["err"] is not None:
        raise RuntimeError(f"turnstile: {token_holder['err']}") from token_holder["err"]
    if mail_holder["err"] is not None:
        raise RuntimeError(f"email/code: {mail_holder['err']}") from mail_holder["err"]

    token = token_holder["token"]
    email = mail_holder["email"]
    clean_code = mail_holder["code"]
    if not token or len(str(token)) <= 10:
        raise RuntimeError("turnstile token 为空")
    if not email or not clean_code:
        raise RuntimeError("邮箱或验证码为空")

    # 优先使用 mail 分支 session（已走过 CreateEmailCode）
    work_cli = mail_holder.get("client") or cli
    _log(log, f"[*] 验证码: {clean_code}")
    _log(log, "[*] VerifyEmailCode ...")
    work_cli.verify_email_code(email, clean_code)
    body = build_signup_body(email, password, clean_code, token)
    body_obj = json.loads(body.decode("utf-8"))
    body_obj[0]["createUserAndSessionRequest"]["givenName"] = given
    body_obj[0]["createUserAndSessionRequest"]["familyName"] = family
    body = json.dumps(body_obj, separators=(",", ":")).encode("utf-8")
    _log(log, "[*] SignupServerAction ...")
    text, sso = work_cli.signup_server_action(body, cfg["action_id"], cfg["state_tree"])
    if not sso:
        sso = extract_sso_from_text(text)
    if not sso:
        preview = (text or "")[:180]
        raise RuntimeError(f"signup 未拿到 SSO: {preview}")
    _log(log, f"[+] 协议注册成功: {email}")
    return {
        "email": email,
        "password": password,
        "sso": sso,
        "profile": {
            "given_name": given,
            "family_name": family,
            "password": password,
        },
    }
