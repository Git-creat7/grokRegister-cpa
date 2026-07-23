#!/usr/bin/env python3
"""
SSO cookie → CPA / grok auth.json 格式（纯 HTTP Device Authorization Flow）

对齐 grok-register-new / 健康号：
- Device Flow（无 referrer / plan / conversations scope）
- CPA headers 使用 grok-shell + x-compaction-at
- base_url=cli-chat-proxy.grok.com

用法:
  # 单个 / 批量 SSO，写出多个独立 auth 文件（每个可直接 cp 到 ~/.grok/auth.json）
  python3 sso_to_auth_json.py --sso sso_list.txt --out-dir ./auth_out

  # 合并到一个 json（key 带 user_id 后缀，避免覆盖）
  python3 sso_to_auth_json.py --sso sso_list.txt --out auth_merged.json --merge

  # 单行 sso
  python3 sso_to_auth_json.py --sso-cookie 'eyJ...' --out ~/.grok/auth.json

  # 只出 CPA
  python3 sso_to_auth_json.py --sso sso_list.txt --cpa-auth-dir /path/to/auths --proxy http://127.0.0.1:7890
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from curl_cffi import requests

CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
OIDC_ISSUER = "https://auth.x.ai"
AUTH_KEY = f"{OIDC_ISSUER}::{CLIENT_ID}"
# 健康号 / grok-register-new scope（不含 conversations:*，不注入 referrer）
SCOPES = "openid profile email offline_access grok-cli:access api:access"

# --- Device Authorization Flow 常量 ------------------------------------------
DISCOVERY_URL = f"{OIDC_ISSUER}/.well-known/openid-configuration"
DEVICE_VERIFY_URL = f"{OIDC_ISSUER}/oauth2/device/verify"
DEVICE_APPROVE_URL = f"{OIDC_ISSUER}/oauth2/device/approve"
# 兼容旧调用方；Device Flow 不再使用 redirect / referrer / plan
REDIRECT_URI = "http://127.0.0.1:56121/callback"
GROK_REFERRER = ""  # 已弃用：健康号 JWT 无 referrer claim
GROK_PLAN = ""
GROK_VERSION = "0.2.93"
GROK_TOKEN_UA = f"grok-shell/{GROK_VERSION} (linux; x86_64)"
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)
# 旧授权码 consent 路径遗留（仅作兼容，默认不再走）
NEXT_ACTION_ID = "401b73e22a5e68737d0037e1aa449fef82cd1b35fb"
_working_next_action_id = NEXT_ACTION_ID
_NEXT_ACTION_RE = re.compile(
    r'(?:\$ACTION_ID_|next-action["\']?\s*[:=]\s*["\']|["\'])([0-9a-f]{40,44})["\']',
    re.I,
)
_CREATE_SERVER_REF_RE = re.compile(
    r'createServerReference\)?\(["\']([0-9a-f]{40,44})["\']',
    re.I,
)
_CALL_SERVER_RE = re.compile(
    r'["\']([0-9a-f]{40,44})["\']\s*,\s*(?:callServer|findSourceMapURL)',
    re.I,
)
_SCRIPT_SRC_RE = re.compile(r'src=["\']([^"\']+)["\']', re.I)

# --- CLIProxyAPI (CPA) 扁平格式常量 ------------------------------------------
# CPA 的 internal/auth/xai/token.go TokenStorage 读的是扁平字段。
# Build/CLI token（scope 含 grok-cli:access）必须走 cli-chat-proxy.grok.com，
# 不能用默认 api.x.ai/v1（那是计费通道，会 402）。
# headers 对齐健康号 / grok-register-new（grok-shell + x-compaction-at）
CPA_TOKEN_ENDPOINT = f"{OIDC_ISSUER}/oauth2/token"
CPA_GROK_BASE_URL = "https://cli-chat-proxy.grok.com/v1"
CPA_GROK_HEADERS = {
    "User-Agent": GROK_TOKEN_UA,
    "X-XAI-Token-Auth": "xai-grok-cli",
    "x-authenticateresponse": "authenticate-response",
    "x-compaction-at": "400000",
    "x-grok-client-identifier": "grok-shell",
    "x-grok-client-version": GROK_VERSION,
    "x-xai-token-auth": "xai-grok-cli",
}
CPA_PROBE_MODEL = "grok-4.5"
CPA_PROBE_URL = f"{CPA_GROK_BASE_URL}/responses"
AUTO_SSO_PATTERNS = ("accounts_*.txt", "sso_pending.txt")


def b64url_decode(seg: str) -> bytes:
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg)


def decode_jwt_payload(token: str) -> dict:
    try:
        return json.loads(b64url_decode(token.split(".")[1]))
    except Exception:
        return {}


def rfc3339_ns(ts: float | None = None) -> str:
    """2026-07-10T01:00:00.000000000Z"""
    if ts is None:
        ts = time.time()
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + ".000000000Z"


def _urlopen(req, proxy: str = "", timeout: int = 15):
    """urllib 请求，proxy 非空时走代理。"""
    if proxy:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        )
        return opener.open(req, timeout=timeout)
    return urllib.request.urlopen(req, timeout=timeout)


def _gen_pkce() -> tuple[str, str, str, str]:
    """生成 (code_verifier, code_challenge, state, nonce)。"""
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    state = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode()
    nonce = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode()
    return verifier, challenge, state, nonce


def _parse_consent_code(body: str) -> str | None:
    """从 consent 提交的 text/x-component 响应里解析出 authorization code。"""
    for line in body.split("\n"):
        start = line.find("{")
        if start < 0:
            continue
        try:
            data = json.loads(line[start:])
        except Exception:
            continue
        if isinstance(data, dict) and data.get("code"):
            if data.get("success") is False:
                return None
            return data.get("code")
    return None


def _extract_next_action_ids(html: str) -> list[str]:
    """仅从 HTML 文本抽哈希（弱信号；真正 id 多在 JS chunk）。"""
    found: list[str] = []
    seen: set[str] = set()
    text = html or ""

    def _add(val: str):
        v = (val or "").strip().lower()
        if len(v) < 40 or v in seen:
            return
        seen.add(v)
        found.append(v)

    for m in _CREATE_SERVER_REF_RE.finditer(text):
        _add(m.group(1))
    for m in _CALL_SERVER_RE.finditer(text):
        _add(m.group(1))
    for m in _NEXT_ACTION_RE.finditer(text):
        _add(m.group(1))
    if NEXT_ACTION_ID and NEXT_ACTION_ID.lower() not in seen:
        found.append(NEXT_ACTION_ID.lower())
    return found


def _discover_action_ids_from_js(
    session,
    html: str,
    base_url: str = "https://accounts.x.ai",
    log=None,
    should_stop=None,
) -> list[str]:
    """从 consent 页引用的 /_next/static/chunks/*.js 解析 createServerReference 的 action id。

    HTML 内嵌的 40 位 hex 经常是错误候选（会 404）；真实 allow consent 在 JS 里。
    """
    found: list[str] = []
    seen: set[str] = set()
    priority: list[str] = []  # consent/oauth 相关 chunk 里的 id 优先

    def _add(val: str, prefer: bool = False):
        v = (val or "").strip().lower()
        if len(v) < 40 or v in seen:
            return
        seen.add(v)
        if prefer:
            priority.append(v)
        else:
            found.append(v)

    srcs = _SCRIPT_SRC_RE.findall(html or "")
    # 优先扫可能含 consent 逻辑的 chunk；其余也扫但限数量
    scored: list[tuple[int, str]] = []
    for src in srcs:
        low = src.lower()
        score = 0
        if "chunk" not in low and "/_next/" not in low:
            continue
        if any(k in low for k in ("consent", "oauth", "auth", "login", "sign")):
            score += 5
        scored.append((score, src))
    scored.sort(key=lambda x: (-x[0], x[1]))

    fetched = 0
    max_fetch = 40
    for score, src in scored:
        if should_stop and should_stop():
            break
        if fetched >= max_fetch:
            break
        full = src if src.startswith("http") else urllib.parse.urljoin(base_url.rstrip("/") + "/", src.lstrip("/"))
        try:
            resp = session.get(full, impersonate="chrome", timeout=15)
            text = str(resp.text or "")
        except Exception:
            continue
        fetched += 1
        prefer = score > 0 or ("consent" in text.lower() and "oauth" in text.lower())
        # 含 allow + createServerReference 的 chunk 更优先
        if "createServerReference" in text or "callServer" in text:
            prefer = True
        for m in _CREATE_SERVER_REF_RE.finditer(text):
            _add(m.group(1), prefer=prefer)
        for m in _CALL_SERVER_RE.finditer(text):
            _add(m.group(1), prefer=prefer)

    # HTML 弱信号放后
    for aid in _extract_next_action_ids(html):
        _add(aid, prefer=False)

    ordered = priority + [x for x in found if x not in priority]
    if log:
        log(f"  [*] 从 JS chunks 解析 Next-Action {len(ordered)} 个（扫 {fetched} 个脚本）")
    return ordered


def _device_location_error(loc: str) -> str | None:
    if not loc:
        return None
    try:
        err = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get("error", [None])[0]
    except Exception:
        return None
    return err or None


def _discover_device_endpoints(session, log=print) -> tuple[str, str] | None:
    try:
        resp = session.get(DISCOVERY_URL, impersonate="chrome", timeout=15)
    except Exception as e:
        log(f"  ❌ OIDC discovery 异常: {e}")
        return None
    if resp.status_code < 200 or resp.status_code >= 300:
        log(f"  ❌ OIDC discovery HTTP {resp.status_code}")
        return None
    try:
        doc = resp.json()
    except Exception:
        log("  ❌ OIDC discovery 非 JSON")
        return None
    device_ep = str(doc.get("device_authorization_endpoint") or "").strip()
    token_ep = str(doc.get("token_endpoint") or CPA_TOKEN_ENDPOINT).strip()
    if not device_ep or not token_ep:
        log("  ❌ OIDC discovery 缺少 device/token endpoint")
        return None
    return device_ep, token_ep


def sso_to_token(
    sso_cookie: str,
    proxy: str = "",
    log=print,
    should_stop=None,
) -> dict | None:
    """SSO cookie → token dict (access/refresh/expires_in)。

    使用 Device Authorization Flow（对齐 grok-register-new / 健康号）：
    - scope 不含 conversations:*
    - 不注入 referrer / plan
    - 纯 HTTP：device verify + approve + poll token
    """
    stop_logged = False

    def _cancelled() -> bool:
        nonlocal stop_logged
        stopped = bool(should_stop and should_stop())
        if stopped and not stop_logged:
            log("  [!] 用户停止授权转换")
            stop_logged = True
        return stopped

    if _cancelled():
        return None

    proxies = {"http": proxy, "https": proxy} if proxy else None
    s = requests.Session()
    if proxies:
        s.proxies = proxies
    for domain in (".x.ai", "accounts.x.ai", "auth.x.ai"):
        s.cookies.set("sso", sso_cookie, domain=domain)
        s.cookies.set("sso-rw", sso_cookie, domain=domain)

    try:
        r = s.get("https://accounts.x.ai/", impersonate="chrome", timeout=15)
    except Exception as e:
        log(f"  ❌ 网络错误: {e}")
        return None
    if _cancelled():
        return None
    if "sign-in" in r.url or "sign-up" in r.url:
        log("  ❌ sso 无效")
        return None
    log("  ✅ sso 有效")

    endpoints = _discover_device_endpoints(s, log=log)
    if not endpoints:
        return None
    device_ep, token_ep = endpoints
    if _cancelled():
        return None

    log("  🔑 Device Authorization Flow（无 referrer / plan）...")
    try:
        r = s.post(
            device_ep,
            data=urllib.parse.urlencode({
                "client_id": CLIENT_ID,
                "scope": SCOPES,
            }),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": BROWSER_UA,
                "Accept": "application/json",
            },
            impersonate="chrome",
            timeout=15,
        )
    except Exception as e:
        log(f"  ❌ device authorization 异常: {e}")
        return None
    if r.status_code < 200 or r.status_code >= 300:
        log(f"  ❌ device authorization HTTP {r.status_code}: {str(r.text)[:200]}")
        return None
    try:
        device_doc = r.json()
    except Exception:
        log(f"  ❌ device authorization 非 JSON: {str(r.text)[:200]}")
        return None

    device_code = str(device_doc.get("device_code") or "").strip()
    user_code = str(device_doc.get("user_code") or "").strip()
    verification_uri = (
        str(device_doc.get("verification_uri") or device_doc.get("verification_url") or "").strip()
    )
    verification_complete = str(device_doc.get("verification_uri_complete") or "").strip()
    expires_in = int(device_doc.get("expires_in") or 600)
    interval = float(device_doc.get("interval") or 5)
    if interval < 1:
        interval = 5
    if not device_code or not user_code:
        log(f"  ❌ device authorization 缺字段: {device_doc}")
        return None
    if not verification_complete:
        base = verification_uri or "https://accounts.x.ai/oauth2/device"
        sep = "&" if "?" in base else "?"
        verification_complete = f"{base}{sep}user_code={urllib.parse.quote(user_code)}"
    log(f"  [*] user_code={user_code} interval={interval}s")

    # confirm: verify + approve（纯 HTTP，SSO cookie）
    cookie_hdr = f"sso={sso_cookie}"
    verify_headers = {
        "User-Agent": BROWSER_UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Origin": "https://accounts.x.ai",
        "Referer": verification_complete,
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": cookie_hdr,
    }
    try:
        r = s.post(
            DEVICE_VERIFY_URL,
            data=urllib.parse.urlencode({"user_code": user_code}),
            headers=verify_headers,
            impersonate="chrome",
            timeout=15,
            allow_redirects=False,
        )
    except Exception as e:
        log(f"  ❌ device verify 异常: {e}")
        return None
    if _cancelled():
        return None
    loc = str(r.headers.get("Location") or "")
    loc_err = _device_location_error(loc)
    if loc_err:
        log(f"  ❌ device verify error={loc_err}")
        return None
    if r.status_code == 403:
        log("  ❌ device verify challenge/403")
        return None
    if "/oauth2/device/done" not in loc:
        consent_ref = loc
        if not consent_ref:
            consent_ref = (
                "https://accounts.x.ai/oauth2/device/consent?"
                f"user_code={urllib.parse.quote(user_code)}"
            )
        elif consent_ref.startswith("/"):
            consent_ref = "https://accounts.x.ai" + consent_ref
        approve_headers = dict(verify_headers)
        approve_headers["Referer"] = consent_ref
        try:
            r2 = s.post(
                DEVICE_APPROVE_URL,
                data=urllib.parse.urlencode({
                    "user_code": user_code,
                    "action": "allow",
                    "principal_type": "User",
                    "principal_id": "",
                }),
                headers=approve_headers,
                impersonate="chrome",
                timeout=15,
                allow_redirects=False,
            )
        except Exception as e:
            log(f"  ❌ device approve 异常: {e}")
            return None
        if _cancelled():
            return None
        aloc = str(r2.headers.get("Location") or "")
        aerr = _device_location_error(aloc)
        if aerr:
            log(f"  ❌ device approve error={aerr}")
            return None
        body_l = str(r2.text or "").lower()
        ok = (
            "device authorized" in body_l
            or "设备已授权" in (r2.text or "")
            or r2.status_code // 100 == 2
            or "device/done" in aloc
            or (aloc and not aerr)
        )
        if not ok:
            if r2.status_code == 403:
                log("  ❌ device approve challenge/403")
            else:
                log(f"  ❌ device approve 未知响应 status={r2.status_code}")
            return None
    log("  ✅ 设备已授权")

    # poll token
    deadline = time.time() + max(expires_in, 60)
    poll_interval = interval
    last_err = ""
    while time.time() < deadline:
        if _cancelled():
            return None
        try:
            tr = s.post(
                token_ep,
                data=urllib.parse.urlencode({
                    "client_id": CLIENT_ID,
                    "device_code": device_code,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                }),
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": BROWSER_UA,
                    "Accept": "application/json",
                },
                impersonate="chrome",
                timeout=15,
            )
        except Exception as e:
            last_err = f"token poll 异常: {e}"
            log(f"  ⚠️ {last_err}")
            time.sleep(poll_interval)
            continue
        try:
            doc = tr.json()
        except Exception:
            last_err = f"token 非 JSON status={tr.status_code}"
            time.sleep(poll_interval)
            continue
        if tr.status_code // 100 == 2 and doc.get("access_token"):
            token = doc
            if not token.get("expires_in"):
                token["expires_in"] = 21600
            if not token.get("token_type"):
                token["token_type"] = "Bearer"
            ap = decode_jwt_payload(token["access_token"])
            log(
                f"  ✅ access_token (expires_in={token.get('expires_in')}s)"
                f" scope={ap.get('scope')!r} referrer={ap.get('referrer')!r}"
                f" bot={ap.get('bot_flag_source')!r}"
                + (" + refresh_token" if token.get("refresh_token") else "")
            )
            return token
        err = str(doc.get("error") or "")
        if err == "authorization_pending":
            time.sleep(poll_interval)
            continue
        if err == "slow_down":
            poll_interval += 1
            time.sleep(poll_interval)
            continue
        if err in ("access_denied", "expired_token"):
            log(f"  ❌ token poll {err}")
            return None
        last_err = err or f"status={tr.status_code}"
        log(f"  ❌ token poll 失败: {last_err}")
        return None

    log(f"  ❌ token poll 超时: {last_err}")
    return None


def token_to_auth_entry(token: dict, email: str = "") -> tuple[str, dict]:
    """
    返回 (top_level_key, entry)
    top_level_key 固定为 issuer::client_id（与 ~/.grok/auth.json 一致）
    """
    access = token.get("access_token") or token.get("key") or ""
    refresh = token.get("refresh_token") or ""
    payload = decode_jwt_payload(access)

    user_id = payload.get("sub") or payload.get("principal_id") or ""
    principal_id = payload.get("principal_id") or user_id
    principal_type = payload.get("principal_type") or "User"

    expires_in = int(token.get("expires_in") or 21600)
    # 优先用 JWT exp
    if "exp" in payload:
        expires_at = rfc3339_ns(float(payload["exp"]))
    else:
        expires_at = rfc3339_ns(time.time() + expires_in)

    iat = payload.get("iat")
    create_time = rfc3339_ns(float(iat) if iat else time.time())

    entry = {
        "key": access,
        "auth_mode": "oidc",
        "create_time": create_time,
        "user_id": user_id,
        "email": email or "",
        "principal_type": principal_type,
        "principal_id": principal_id,
        "refresh_token": refresh,
        "expires_at": expires_at,
        "oidc_issuer": OIDC_ISSUER,
        "oidc_client_id": CLIENT_ID,
    }
    return AUTH_KEY, entry


def _iso_utc_from_unix(ts) -> str:
    """unix 秒 → CPA 认的 RFC3339（秒级，带 Z）。"""
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return ""


def _safe_email_for_filename(email: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "._-@" else "_" for ch in email)
    return safe or "unknown"


def token_to_cpa_record(token: dict, email: str = "", sso: str = "") -> dict:
    """token dict → CLIProxyAPI 扁平 xai auth 记录。

    对齐 CPA internal/auth/xai/token.go 与 grok-register-new / 健康号输出：
    无 redirect_uri、默认不写 sso 字段。
    """
    access = token.get("access_token") or token.get("key") or ""
    refresh = token.get("refresh_token") or ""
    id_token = token.get("id_token") or ""
    payload = decode_jwt_payload(access)
    id_payload = decode_jwt_payload(id_token) if id_token else {}

    if not email:
        email = id_payload.get("email") or payload.get("email") or ""
    sub = payload.get("sub") or id_payload.get("sub") or ""

    # expired: 优先 access token 的 exp，其次 expires_in 推算
    expired = ""
    if "exp" in payload:
        expired = _iso_utc_from_unix(payload["exp"])
    elif token.get("expires_in") is not None:
        try:
            expired = _iso_utc_from_unix(int(time.time()) + int(token["expires_in"]))
        except Exception:
            expired = ""

    record = {
        "type": "xai",
        "auth_kind": "oauth",
        "email": email or "",
        "sub": sub,
        "access_token": access,
        "refresh_token": refresh,
        "id_token": id_token,
        "token_type": token.get("token_type", "Bearer"),
        "expires_in": token.get("expires_in", None),
        "expired": expired,
        "last_refresh": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "token_endpoint": CPA_TOKEN_ENDPOINT,
        "base_url": CPA_GROK_BASE_URL,
        "headers": dict(CPA_GROK_HEADERS),
    }
    # sso 仅在显式需要时写入；健康号 / new-register 不带此字段
    sso_val = str(sso or "").strip()
    if sso_val and os.environ.get("CPA_INCLUDE_SSO", "").strip() in ("1", "true", "yes"):
        record["sso"] = sso_val
    return record


def cpa_auth_filename(record: dict) -> str:
    """生成 CPA auth 文件名：xai-<email>.json。"""
    ident = str(record.get("email") or "").strip() or str(record.get("sub") or "").strip()
    safe = _safe_email_for_filename(ident)
    # 避免 email 本地部分已是 xai 时出现 "xai-xai..."
    fname = safe if safe.lower().startswith("xai") else f"xai-{safe}"
    return f"{fname}.json"


def probe_cpa_record(
    record: dict,
    proxy: str = "",
    timeout: int = 30,
    model: str = CPA_PROBE_MODEL,
    warmup: bool = True,
    retries: int = 3,
) -> tuple[int | None, str]:
    """直连 CLI chat proxy 自测，返回 (HTTP 状态码, 响应摘要)。

    对齐 grok-register-new Probe：新 token 常有瞬时 403，warmup + 重试。
    """
    access = str(record.get("access_token") or "").strip()
    if not access:
        return None, "missing access_token"

    if warmup:
        time.sleep(3)

    last_code: int | None = None
    last_summary = ""
    sub = str(record.get("sub") or "").strip() or f"probe-{int(time.time() * 1000)}"
    email = str(record.get("email") or "").strip()

    for attempt in range(max(1, int(retries or 1))):
        if attempt > 0:
            time.sleep(4)
        headers = dict(record.get("headers") or CPA_GROK_HEADERS)
        headers["Authorization"] = f"Bearer {access}"
        headers["Content-Type"] = "application/json"
        headers["Accept"] = "application/json"
        rid = f"{int(time.time() * 1_000_000)}"
        headers["x-grok-session-id"] = f"probe-{sub}"
        headers["x-grok-conv-id"] = f"probe-{sub}"
        headers["x-grok-req-id"] = rid
        headers["x-grok-turn-idx"] = "1"
        headers["x-grok-agent-id"] = f"agent-{rid[:8]}"
        headers["x-grok-model-override"] = model
        if email:
            headers["x-email"] = email
        if sub:
            headers["x-userid"] = sub
        # 对齐 new-register / acpa_watchdog 的 responses body
        payload = {
            "model": model,
            "store": False,
            "stream": False,
            "max_output_tokens": 16,
            "input": [
                {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": "ok"}],
                }
            ],
        }
        kwargs = {
            "headers": headers,
            "json": payload,
            "impersonate": "chrome",
            "timeout": timeout,
        }
        if proxy:
            kwargs["proxy"] = proxy
        try:
            resp = requests.post(CPA_PROBE_URL, **kwargs)
            summary = str(resp.text or "").replace("\n", " ").strip()
            last_code, last_summary = int(resp.status_code), summary[:300]
            if last_code == 200:
                return last_code, last_summary
            low = last_summary.lower()
            if last_code == 403 and (
                "permission-denied" in low
                or "chat endpoint is denied" in low
                or "denied" in low
            ):
                continue
            return last_code, last_summary
        except Exception as exc:
            last_code, last_summary = None, str(exc)[:300]
    return last_code, last_summary


def write_cpa_auth(auth_dir: Path, record: dict) -> Path:
    """写出 CPA 可热加载的 xai-<email>.json（原子替换）。

    无 email 时用 sub(user_id) 命名，避免多个无 email 账号写成同一个
    xai-unknown.json 互相覆盖。
    """
    auth_dir.mkdir(parents=True, exist_ok=True)
    path = auth_dir / cpa_auth_filename(record)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return path


def upload_cpa_auth_remote(
    base_url: str,
    management_key: str,
    record: dict,
    timeout: int = 30,
) -> str:
    """通过 CPA Management API 上传 auth 文件到远程实例。

    POST /v0/management/auth-files?name=<file.json>
    Header: Authorization: Bearer <management_key>
    Body: raw JSON auth record
    """
    import requests

    base = str(base_url or "").strip().rstrip("/")
    key = str(management_key or "").strip()
    if not base:
        raise ValueError("cpa_remote_url 为空")
    if not key:
        raise ValueError("cpa_management_key 为空")

    name = cpa_auth_filename(record)
    url = f"{base}/v0/management/auth-files"
    resp = requests.post(
        url,
        params={"name": name},
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        },
        data=json.dumps(record, ensure_ascii=False).encode("utf-8"),
        timeout=timeout,
    )
    if resp.status_code >= 400:
        body = (resp.text or "").strip()
        if len(body) > 300:
            body = body[:300] + "..."
        raise RuntimeError(f"远程上传失败 HTTP {resp.status_code}: {body or resp.reason}")
    return name


def write_auth_json(path: Path, auth_key: str, entry: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {auth_key: entry}
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def merge_auth_json(path: Path, auth_key: str, entry: dict, unique: bool = True) -> None:
    """
    合并写入。unique=True 时 key 变成 issuer::client_id::user_id，避免多账号互相覆盖。
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    existing: dict = {}
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            existing = {}
    key = auth_key
    if unique and entry.get("user_id"):
        key = f"{auth_key}::{entry['user_id']}"
    existing[key] = entry
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(existing, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def parse_sso_line(raw_line: str) -> tuple[str, str]:
    """解析一行 SSO，返回 (email, sso)。"""
    line = str(raw_line or "").strip()
    if "----" not in line:
        return "", line
    parts = line.split("----")
    first = parts[0].strip()
    email = first if "@" in first and len(parts) >= 2 else ""
    return email, parts[-1].strip()


def load_sso_entries(path: str | None, single: str | None) -> list[tuple[str, str]]:
    if single:
        return [("", single.strip())]
    if not path:
        return []
    out = []
    for raw_line in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        email, sso = parse_sso_line(line)
        if sso:
            out.append((email, sso))
    return out


def load_sso_list(path: str | None, single: str | None) -> list[str]:
    """兼容旧调用方，仅返回 SSO 值。"""
    return [sso for _email, sso in load_sso_entries(path, single)]


def _auth_email_from_object(value: object) -> str:
    if not isinstance(value, dict):
        return ""
    email = str(value.get("email") or "").strip().casefold()
    if not email or not (value.get("access_token") or value.get("key")):
        return ""
    return email


def _contains_auth_credential(value: object) -> bool:
    if isinstance(value, dict):
        if value.get("access_token") or value.get("key"):
            return True
        return any(_contains_auth_credential(child) for child in value.values())
    if isinstance(value, list):
        return any(_contains_auth_credential(child) for child in value)
    return False


def _auth_emails_from_json(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return set()

    found: set[str] = set()

    def walk(value: object):
        if isinstance(value, dict):
            email = _auth_email_from_object(value)
            if email:
                found.add(email)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(data)
    # 兼容旧版 CPA 文件：文件名带邮箱，但记录正文没有 email 字段。
    if not found and _contains_auth_credential(data):
        stem = path.stem
        if stem.lower().startswith("xai-"):
            filename_email = stem[4:].strip().casefold()
            if "@" in filename_email:
                found.add(filename_email)
    return found


def collect_existing_auth_emails(
    out: str | None = None,
    out_dir: str | None = None,
    cpa_auth_dir: str | None = None,
) -> set[str]:
    """扫描本地输出中的有效 auth，返回已存在邮箱（损坏文件不会被视为已存在）。"""
    paths: list[Path] = []
    if out:
        paths.append(Path(out))
    for directory in (out_dir, cpa_auth_dir):
        if directory:
            paths.extend(Path(directory).glob("*.json"))

    emails: set[str] = set()
    for path in paths:
        if path.is_file():
            emails.update(_auth_emails_from_json(path))
    return emails


def collect_remote_auth_emails(
    base_url: str,
    management_key: str,
    timeout: int = 15,
) -> set[str]:
    """通过 CPA Management API 获取远程已存在的 auth 邮箱。"""
    import requests

    base = str(base_url or "").strip().rstrip("/")
    key = str(management_key or "").strip()
    if not base or not key:
        return set()
    try:
        response = requests.get(
            f"{base}/v0/management/auth-files",
            headers={"Authorization": f"Bearer {key}"},
            timeout=timeout,
        )
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        raise RuntimeError(f"远程 CPA 已有账号检索失败: {exc}") from exc

    items = payload.get("files", []) if isinstance(payload, dict) else payload
    emails: set[str] = set()
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        provider = str(item.get("type") or item.get("provider") or "").strip().lower()
        if provider and provider != "xai":
            continue
        email = str(item.get("email") or "").strip().casefold()
        if not email:
            name = Path(str(item.get("name") or "")).stem
            if name.lower().startswith("xai-"):
                email = name[4:].strip().casefold()
        if "@" in email:
            emails.add(email)
    return emails


def discover_sso_files(scan_dir: str | Path = ".") -> list[Path]:
    root = Path(scan_dir)
    found: dict[Path, None] = {}
    for pattern in AUTO_SSO_PATTERNS:
        for path in sorted(root.glob(pattern)):
            if path.is_file():
                found[path] = None
    return list(found)


def scan_sso_entries(scan_dir: str | Path = ".") -> tuple[list[tuple[str, str]], list[Path]]:
    """扫描安全 TXT 并去重；同邮箱保留后扫描到的最新 SSO。"""
    files = discover_sso_files(scan_dir)
    unique: dict[str, tuple[str, str]] = {}
    for path in files:
        for email, sso in load_sso_entries(str(path), None):
            key = f"email:{email.casefold()}" if email else f"sso:{sso}"
            unique[key] = (email, sso)
    return list(unique.values()), files


def load_conversion_config(path: str | Path) -> dict:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    return value if isinstance(value, dict) else {}


def convert_sso_entries(
    entries: list[tuple[str, str]],
    *,
    out: str | None = None,
    out_dir: str | None = None,
    merge: bool = False,
    cpa_auth_dir: str | None = None,
    cpa_remote_url: str | None = None,
    cpa_management_key: str | None = None,
    proxy: str = "",
    delay: int = 0,
    fallback_email: str = "",
    workers: int = 1,
    log=print,
    should_stop=None,
) -> dict:
    local_emails = collect_existing_auth_emails(
        out=out,
        out_dir=out_dir,
        cpa_auth_dir=cpa_auth_dir,
    )
    if cpa_remote_url:
        # 补转以远程 CPA 为准：本地 TXT 提供候选，远程缺失才转换。
        # 本地已有 JSON 但远程缺失时仍需重转/上传，不能被本地文件跳过。
        existing_emails = collect_remote_auth_emails(
            cpa_remote_url,
            str(cpa_management_key or ""),
        )
    else:
        existing_emails = local_emails

    workers = max(1, min(int(workers or 1), 8))
    total = len(entries)
    # 合并写同一 out 文件时强制单线程，避免 JSON 交错
    if workers > 1 and out and (merge or total > 1) and not out_dir and not cpa_auth_dir and not cpa_remote_url:
        workers = 1

    log(f"🚀 SSO → auth.json: {total} 个, delay={delay}s, workers={workers}")
    if existing_emails:
        log(f"[*] 已检索到已有账号: {len(existing_emails)} 个，重复账号将跳过")

    lock = threading.Lock()
    stats = {"ok": 0, "fail": 0, "skipped": 0, "stopped": False}

    def _log(message: str, worker_id: int | None = None) -> None:
        prefix = f"[W{worker_id}] " if worker_id is not None and workers > 1 else ""
        with lock:
            log(f"{prefix}{message}")

    def _process_one(i: int, source_email: str, sso: str, worker_id: int | None = None) -> None:
        if should_stop and should_stop():
            with lock:
                stats["stopped"] = True
            return

        email = (source_email or fallback_email or "").strip()
        email_key = email.casefold()
        with lock:
            if email_key and email_key in existing_emails:
                stats["skipped"] += 1
                already = True
            else:
                already = False
        if already:
            _log(f"⏭️ [{i}/{total}] 跳过已存在账号: {email}", worker_id)
            return

        _log(f"[{i}/{total}] 开始检查", worker_id)
        try:
            def worker_log(msg):
                _log(str(msg), worker_id)

            token = sso_to_token(
                sso,
                proxy=proxy,
                log=worker_log,
                should_stop=should_stop,
            )
            if not token:
                with lock:
                    stats["fail"] += 1
                _log(f"❌ [{i}/{total}] 失败", worker_id)
                return
            key, entry = token_to_auth_entry(token, email=email)
            uid = entry.get("user_id") or secrets.token_hex(4)

            if out_dir:
                path = Path(out_dir) / f"{uid}.json"
                with lock:
                    write_auth_json(path, key, entry)
                _log(f"💾 {path}", worker_id)
            if out:
                with lock:
                    if merge or total > 1:
                        merge_auth_json(Path(out), key, entry, unique=True)
                        out_msg = f"💾 merge → {out}"
                    else:
                        write_auth_json(Path(out), key, entry)
                        out_msg = f"💾 {out}"
                _log(out_msg, worker_id)

            if cpa_auth_dir or cpa_remote_url:
                record = token_to_cpa_record(token, email=email, sso=sso)
                if cpa_auth_dir:
                    with lock:
                        path = write_cpa_auth(Path(cpa_auth_dir), record)
                    _log(f"💾 CPA 本地 → {path}", worker_id)
                if cpa_remote_url:
                    name = upload_cpa_auth_remote(
                        cpa_remote_url,
                        str(cpa_management_key or ""),
                        record,
                    )
                    _log(
                        f"💾 CPA 远程 → {cpa_remote_url.rstrip('/')}/.../{name}",
                        worker_id,
                    )

            with lock:
                stats["ok"] += 1
                if email_key:
                    existing_emails.add(email_key)
            _log(f"✅ [{i}/{total}] 完成 user_id={uid[:12]}...", worker_id)
        except Exception as exc:
            with lock:
                stats["fail"] += 1
            _log(f"❌ [{i}/{total}] 异常: {exc}", worker_id)

        if delay > 0:
            time.sleep(delay)

    if workers <= 1:
        for i, (source_email, sso) in enumerate(entries, 1):
            if should_stop and should_stop():
                stats["stopped"] = True
                log("[!] 用户停止补转，剩余 SSO 未处理")
                break
            _process_one(i, source_email, sso, worker_id=None)
    else:
        # 均匀分片：worker k 处理 entries[k::workers]
        shards: list[list[tuple[int, str, str]]] = [[] for _ in range(workers)]
        for i, (source_email, sso) in enumerate(entries, 1):
            shards[(i - 1) % workers].append((i, source_email, sso))
        log(f"[*] 分片: {workers} 线程, 每片约 {total // workers}~{(total + workers - 1) // workers} 个")

        def _run_shard(worker_id: int, items: list[tuple[int, str, str]]) -> None:
            for i, source_email, sso in items:
                if should_stop and should_stop():
                    with lock:
                        stats["stopped"] = True
                    _log("[!] 用户停止补转，剩余 SSO 未处理", worker_id)
                    return
                _process_one(i, source_email, sso, worker_id=worker_id)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [
                pool.submit(_run_shard, wid + 1, shard)
                for wid, shard in enumerate(shards)
                if shard
            ]
            for fut in as_completed(futures):
                fut.result()

    result = {
        "total": total,
        "ok": stats["ok"],
        "skipped": stats["skipped"],
        "fail": stats["fail"],
        "stopped": stats["stopped"],
        "workers": workers,
    }
    status = "已停止" if stats["stopped"] else "完成"
    log(
        f"📊 {status}: {stats['ok']}/{total} 成功, "
        f"{stats['skipped']} 跳过, {stats['fail']} 失败, workers={workers}"
    )
    return result


def main() -> int:
    try:
        sys.stdout.reconfigure(errors="replace")
    except (AttributeError, OSError):
        pass
    ap = argparse.ArgumentParser(description="SSO cookie → grok auth.json (纯 HTTP)")
    ap.add_argument("--sso", metavar="FILE", help="sso 列表文件（一行一个 JWT，或 邮箱----密码----sso）")
    ap.add_argument("--sso-cookie", metavar="JWT", help="单个 sso cookie")
    ap.add_argument(
        "--scan-dir",
        default=None,
        help="自动扫描目录中的 accounts_*.txt 和 sso_pending.txt；未提供 SSO 时默认当前目录",
    )
    ap.add_argument(
        "--config",
        default=None,
        help="自动扫描模式使用的 config.json；默认取扫描目录/config.json",
    )
    ap.add_argument("--out", default=None, help="输出 auth.json 路径（单账号或 --merge）")
    ap.add_argument(
        "--out-dir",
        default=None,
        help="批量时每个账号写一个 {user_id}.json（可直接 cp 到 ~/.grok/auth.json）",
    )
    ap.add_argument(
        "--merge",
        action="store_true",
        help="合并到 --out，key 用 issuer::client_id::user_id",
    )
    ap.add_argument("--delay", type=int, default=0, help="每个间隔秒数")
    ap.add_argument("--email", default="", help="写入 entry.email（可选）")
    ap.add_argument(
        "--cpa-auth-dir",
        default=None,
        help="额外写出 CLIProxyAPI 扁平格式 xai-<email>.json 到该目录（CPA 热加载）",
    )
    ap.add_argument(
        "--cpa-remote-url",
        default=None,
        help="远程 CPA 地址，如 http://你的CPA地址:8317；配合 --cpa-management-key 通过 Management API 上传",
    )
    ap.add_argument(
        "--cpa-management-key",
        default=None,
        help="远程 CPA 管理密钥（remote-management.secret-key 明文）",
    )
    ap.add_argument("--proxy", default="", help="授权码流程走代理，如 http://127.0.0.1:7890")
    ap.add_argument(
        "--workers",
        type=int,
        default=1,
        help="并发线程数（分片处理 SSO），默认 1，最大 8",
    )
    args = ap.parse_args()

    auto_scan = not args.sso and not args.sso_cookie
    scan_files: list[Path] = []
    if auto_scan:
        scan_dir = Path(args.scan_dir or ".")
        entries, scan_files = scan_sso_entries(scan_dir)
        config_path = Path(args.config) if args.config else scan_dir / "config.json"
        saved_config = load_conversion_config(config_path)
        if args.cpa_auth_dir is None:
            args.cpa_auth_dir = str(saved_config.get("cpa_auth_dir") or "") or None
        if args.cpa_remote_url is None:
            args.cpa_remote_url = str(saved_config.get("cpa_remote_url") or "") or None
        if args.cpa_management_key is None:
            args.cpa_management_key = str(saved_config.get("cpa_management_key") or "") or None
        if not args.proxy:
            args.proxy = str(saved_config.get("proxy") or "")
        print(
            f"[*] 自动扫描 {scan_dir.resolve()}: {len(scan_files)} 个 TXT，"
            f"{len(entries)} 个去重 SSO"
        )
    else:
        entries = load_sso_entries(args.sso, args.sso_cookie)
    if not entries:
        ap.error("未找到可转换的 SSO；请检查 accounts_*.txt / sso_pending.txt 或显式传入 --sso")

    if args.cpa_remote_url and not args.cpa_management_key:
        ap.error("使用 --cpa-remote-url 时必须同时提供 --cpa-management-key")
    if args.cpa_management_key and not args.cpa_remote_url:
        ap.error("使用 --cpa-management-key 时必须同时提供 --cpa-remote-url")

    if (
        len(entries) > 1
        and not args.out_dir
        and not args.merge
        and not args.cpa_auth_dir
        and not args.cpa_remote_url
    ):
        # 默认批量写目录
        args.out_dir = args.out_dir or "./auth_out"
        print(f"批量模式默认 --out-dir {args.out_dir}")

    # 只指定 CPA 目标时不再默认写官方 ~/.grok/auth.json
    if (
        args.out is None
        and args.out_dir is None
        and not args.cpa_auth_dir
        and not args.cpa_remote_url
        and len(entries) == 1
    ):
        args.out = str(Path.home() / ".grok" / "auth.json")

    result = convert_sso_entries(
        entries,
        out=args.out,
        out_dir=args.out_dir,
        merge=args.merge,
        cpa_auth_dir=args.cpa_auth_dir,
        cpa_remote_url=args.cpa_remote_url,
        cpa_management_key=args.cpa_management_key,
        proxy=args.proxy,
        delay=args.delay,
        fallback_email=args.email,
        workers=args.workers,
    )
    return 0 if result["fail"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
