#!/usr/bin/env python3
"""
SSO cookie → CPA / grok auth.json 格式（纯 HTTP 授权码流程）

对齐 grok-build-auth 的 CPA 导出格式；authorize 注入 referrer=grok-build + plan=generic，
写出 CLIProxyAPI 扁平 xai-*.json（base_url=cli-chat-proxy.grok.com）。

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
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from curl_cffi import requests

CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
OIDC_ISSUER = "https://auth.x.ai"
AUTH_KEY = f"{OIDC_ISSUER}::{CLIENT_ID}"
# 与当前可用号 JWT scope 对齐（含 conversations:*）
SCOPES = (
    "openid profile email offline_access grok-cli:access "
    "api:access conversations:read conversations:write"
)

# --- Authorization Code Flow 常量 --------------------------------------------
# authorize 必须注入 referrer=grok-build，否则 access_token 无该 claim，
# cli-chat-proxy 会 403。实测 referrer=cli-proxy-api 会得到 referrer=None。
# plan=generic 对齐 grok-build-auth；consent.referrer 仍置空。
REDIRECT_URI = "http://127.0.0.1:56121/callback"
GROK_REFERRER = "grok-build"
GROK_PLAN = "generic"
GROK_VERSION = "0.2.93"
GROK_TOKEN_UA = f"grok-pager/{GROK_VERSION} grok-shell/{GROK_VERSION} (linux; x86_64)"
# consent 提交用的 Next.js Server Action ID（快速路径；失效时再从 consent 页 JS 动态解析）
# 2026-07 实测 createServerReference 在 accounts.x.ai chunks 内，HTML 里的 400b2e4e... 不是 consent allow
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
# headers 对齐 @xai-official/grok CLI / grok-build-auth（无 x-authenticateresponse）
CPA_TOKEN_ENDPOINT = f"{OIDC_ISSUER}/oauth2/token"
CPA_GROK_BASE_URL = "https://cli-chat-proxy.grok.com/v1"
CPA_GROK_HEADERS = {
    "User-Agent": GROK_TOKEN_UA,
    "X-XAI-Token-Auth": "xai-grok-cli",
    "x-authenticateresponse": "authenticate-response",
    "x-grok-client-identifier": "grok-pager",
    "x-grok-client-version": GROK_VERSION,
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


def _discover_action_ids_from_js(session, html: str, base_url: str = "https://accounts.x.ai", log=None) -> list[str]:
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


def sso_to_token(sso_cookie: str, proxy: str = "", log=print) -> dict | None:
    """SSO cookie → token dict (access/refresh/expires_in)。

    使用授权码流程（Authorization Code + PKCE）：
    authorize 注入 referrer=grok-build + plan=generic，
    consent 优先复用已成功的 Next-Action，失效时才扫描页面 JS 并重试。
    """
    global _working_next_action_id

    proxies = {"http": proxy, "https": proxy} if proxy else None
    s = requests.Session()
    if proxies:
        s.proxies = proxies
    # accounts.x.ai / auth.x.ai 都要带 sso（与 grok-build 授权码流程一致）
    for domain in (".x.ai", "accounts.x.ai", "auth.x.ai"):
        s.cookies.set("sso", sso_cookie, domain=domain)
        s.cookies.set("sso-rw", sso_cookie, domain=domain)

    try:
        r = s.get("https://accounts.x.ai/", impersonate="chrome", timeout=15)
    except Exception as e:
        log(f"  ❌ 网络错误: {e}")
        return None
    if "sign-in" in r.url or "sign-up" in r.url:
        log("  ❌ sso 无效")
        return None
    log("  ✅ sso 有效")

    verifier, challenge, state, nonce = _gen_pkce()

    # 1) 打开 authorize 页，跟随重定向进入 consent
    log(f"  🔑 Authorization Code Flow (referrer={GROK_REFERRER}, plan={GROK_PLAN})...")
    authorize_params = urllib.parse.urlencode({
        "client_id": CLIENT_ID,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "nonce": nonce,
        "plan": GROK_PLAN,
        "redirect_uri": REDIRECT_URI,
        "referrer": GROK_REFERRER,
        "response_type": "code",
        "scope": SCOPES,
        "state": state,
    })
    authorize_url = f"{OIDC_ISSUER}/oauth2/authorize?{authorize_params}"

    def _open_consent(discover_actions=False):
        try:
            resp = s.get(
                authorize_url,
                impersonate="chrome",
                timeout=15,
                allow_redirects=True,
            )
        except Exception as e:
            log(f"  ❌ authorize 异常: {e}")
            return None, "", []
        url = str(resp.url)
        if "sign-in" in url or "sign-up" in url:
            log("  ❌ sso 无效")
            return None, url, []
        if "/oauth2/consent" not in url:
            log(f"  ❌ authorize 未进入 consent: {url}")
            return None, url, []
        html = str(resp.text or "")
        # consent 实际在 accounts.x.ai（从 auth.x.ai authorize 重定向）
        base = "https://accounts.x.ai"
        if "auth.x.ai" in url and "accounts.x.ai" not in url:
            base = "https://auth.x.ai"
        if discover_actions:
            action_ids = _discover_action_ids_from_js(s, html, base_url=base, log=log)
        else:
            action_ids = []
            cached = str(_working_next_action_id or "").strip().lower()
            if cached:
                action_ids.append(cached)
            for action_id in _extract_next_action_ids(html):
                if action_id not in action_ids:
                    action_ids.append(action_id)
            log(f"  [*] consent 快速路径 Next-Action {len(action_ids)} 个（跳过 JS chunks 扫描）")
        return resp, url, action_ids

    r, final_url, action_ids = _open_consent()
    if r is None:
        return None
    if not action_ids:
        action_ids = [NEXT_ACTION_ID]
        log(f"  ⚠️ 未解析到 Next-Action，使用 fallback {NEXT_ACTION_ID[:12]}...")
    else:
        log(f"  [*] consent Next-Action 候选 {len(action_ids)} 个（首个 {action_ids[0][:12]}...）")

    # 2) 提交 consent（allow），拿 authorization code
    # consent 也必须带 referrer=grok-build，否则 JWT claim 为 None
    consent_payload = json.dumps([{
        "action": "allow",
        "clientId": CLIENT_ID,
        "redirectUri": REDIRECT_URI,
        "scope": SCOPES,
        "state": state,
        "codeChallenge": challenge,
        "codeChallengeMethod": "S256",
        "nonce": nonce,
        "principalType": "User",
        "principalId": "",
        "referrer": GROK_REFERRER,
    }])

    code = None
    last_err = ""
    tried: set[str] = set()
    # 最多 2 轮：第一轮优先试上次成功/内置 id；失败再重开 consent 扫 JS chunks。
    for round_i in range(2):
        if round_i > 0:
            log("  [*] consent 失败，重新进入 authorize/consent 并解析 Next-Action...")
            r, final_url, action_ids = _open_consent(discover_actions=True)
            if r is None:
                return None
            if not action_ids:
                action_ids = [NEXT_ACTION_ID]

        for action_id in action_ids[:8]:
            if action_id in tried:
                continue
            tried.add(action_id)
            try:
                r = s.post(
                    final_url,
                    data=consent_payload,
                    headers={
                        "Content-Type": "text/plain;charset=UTF-8",
                        "Accept": "text/x-component",
                        "Origin": "https://accounts.x.ai",
                        "Referer": final_url,
                        "Next-Action": action_id,
                    },
                    impersonate="chrome",
                    timeout=15,
                    allow_redirects=True,
                )
            except Exception as e:
                last_err = f"consent 异常: {e}"
                log(f"  ❌ {last_err}")
                continue
            body = str(r.text or "")
            if r.status_code == 404 or "server action not found" in body.lower():
                last_err = f"consent HTTP {r.status_code}: {body[:160]}"
                log(f"  ⚠️ Next-Action {action_id[:12]}... 无效: {last_err}")
                continue
            if r.status_code < 200 or r.status_code >= 300:
                last_err = f"consent HTTP {r.status_code}: {body[:200]}"
                log(f"  ⚠️ {last_err}")
                continue
            code = _parse_consent_code(body)
            if code:
                _working_next_action_id = action_id
                log(f"  [*] Next-Action {action_id[:12]}... 返回 authorization code")
                break
            # 200 但无 code：多半是别的 server action（如读用户信息），继续试
            last_err = f"consent 未返回 code: {body[:180]}"
            log(f"  ⚠️ Next-Action {action_id[:12]}... 非 allow 响应，继续试")
        if code:
            break

    if not code:
        log(f"  ❌ consent 失败（已试 {len(tried)} 个 Next-Action）: {last_err}")
        return None
    log("  ✅ 授权确认")

    # 3) 用 authorization code 换 token
    token_data = urllib.parse.urlencode({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "code_verifier": verifier,
    })
    try:
        r = s.post(
            f"{OIDC_ISSUER}/oauth2/token",
            data=token_data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": GROK_TOKEN_UA,
                "X-Grok-Client-Version": GROK_VERSION,
                "Accept": "*/*",
            },
            impersonate="chrome",
            timeout=15,
        )
    except Exception as e:
        log(f"  ❌ token 异常: {e}")
        return None
    if r.status_code < 200 or r.status_code >= 300:
        log(f"  ❌ token HTTP {r.status_code}: {str(r.text)[:200]}")
        return None
    try:
        token = r.json()
    except Exception:
        log(f"  ❌ token 返回非 JSON: {str(r.text)[:200]}")
        return None
    if not token.get("access_token"):
        log(f"  ❌ token 缺少 access_token: {token}")
        return None
    if not token.get("expires_in"):
        token["expires_in"] = 21600
    if not token.get("token_type"):
        token["token_type"] = "Bearer"

    # 校验 referrer claim（authorize 注入 cli-proxy-api 后应写入 JWT）
    ap = decode_jwt_payload(token["access_token"])
    ref = ap.get("referrer")
    if ref not in (GROK_REFERRER, "grok-build", "cli-proxy-api"):
        log(f"  ⚠️ access_token referrer={ref!r}（预期 {GROK_REFERRER!r} 或 grok-build）")
    else:
        log(f"  ✅ access_token referrer={ref!r}")
    log(
        f"  ✅ access_token (expires_in={token.get('expires_in')}s)"
        + (" + refresh_token" if token.get("refresh_token") else "")
    )
    return token


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

    对齐 CPA internal/auth/xai/token.go 的 TokenStorage 字段，以及
    grok-build-auth build_cliproxyapi_auth_record 的输出。
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
        "redirect_uri": REDIRECT_URI,
        "token_endpoint": CPA_TOKEN_ENDPOINT,
        "base_url": CPA_GROK_BASE_URL,
        "disabled": False,
        "headers": dict(CPA_GROK_HEADERS),
    }
    sso_val = str(sso or "").strip()
    if sso_val:
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
) -> tuple[int | None, str]:
    """直连 CLI chat proxy 自测，返回 (HTTP 状态码, 响应摘要)。"""
    access = str(record.get("access_token") or "").strip()
    if not access:
        return None, "missing access_token"

    headers = dict(record.get("headers") or {})
    headers["Authorization"] = f"Bearer {access}"
    headers["Content-Type"] = "application/json"
    kwargs = {
        "headers": headers,
        "json": {
            "model": model,
            "input": "ping",
            "max_output_tokens": 2,
            "stream": False,
        },
        "impersonate": "chrome",
        "timeout": timeout,
    }
    if proxy:
        kwargs["proxy"] = proxy
    try:
        resp = requests.post(CPA_PROBE_URL, **kwargs)
        summary = str(resp.text or "").replace("\n", " ").strip()
        return int(resp.status_code), summary[:300]
    except Exception as exc:
        return None, str(exc)[:300]


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
    log=print,
    should_stop=None,
) -> dict:
    local_target_configured = bool(out or out_dir or cpa_auth_dir)
    local_emails = collect_existing_auth_emails(
        out=out,
        out_dir=out_dir,
        cpa_auth_dir=cpa_auth_dir,
    )
    if cpa_remote_url:
        remote_emails = collect_remote_auth_emails(
            cpa_remote_url,
            str(cpa_management_key or ""),
        )
        existing_emails = (
            local_emails.intersection(remote_emails)
            if local_target_configured
            else remote_emails
        )
    else:
        existing_emails = local_emails
    log(f"🚀 SSO → auth.json: {len(entries)} 个, delay={delay}s")
    if existing_emails:
        log(f"[*] 已检索到本地有效账号: {len(existing_emails)} 个，重复账号将跳过")

    ok = 0
    fail = 0
    skipped = 0
    stopped = False
    total = len(entries)
    for i, (source_email, sso) in enumerate(entries, 1):
        if should_stop and should_stop():
            stopped = True
            log("[!] 用户停止补转，剩余 SSO 未处理")
            break
        log(f"[{i}/{total}] 开始检查")
        email = (source_email or fallback_email or "").strip()
        email_key = email.casefold()
        if email_key and email_key in existing_emails:
            skipped += 1
            log(f"⏭️ [{i}] 跳过已存在账号: {email}")
            continue
        try:
            token = sso_to_token(sso, proxy=proxy, log=log)
            if not token:
                fail += 1
                log(f"❌ [{i}] 失败")
                continue
            key, entry = token_to_auth_entry(token, email=email)
            uid = entry.get("user_id") or secrets.token_hex(4)

            if out_dir:
                path = Path(out_dir) / f"{uid}.json"
                write_auth_json(path, key, entry)
                log(f"💾 {path}")
            if out:
                if merge or total > 1:
                    merge_auth_json(Path(out), key, entry, unique=True)
                    log(f"💾 merge → {out}")
                else:
                    write_auth_json(Path(out), key, entry)
                    log(f"💾 {out}")

            if cpa_auth_dir or cpa_remote_url:
                record = token_to_cpa_record(token, email=email, sso=sso)
                if cpa_auth_dir:
                    path = write_cpa_auth(Path(cpa_auth_dir), record)
                    log(f"💾 CPA 本地 → {path}")
                if cpa_remote_url:
                    name = upload_cpa_auth_remote(
                        cpa_remote_url,
                        str(cpa_management_key or ""),
                        record,
                    )
                    log(f"💾 CPA 远程 → {cpa_remote_url.rstrip('/')}/.../{name}")

            ok += 1
            if email_key:
                existing_emails.add(email_key)
            log(f"✅ [{i}] 完成 user_id={uid[:12]}...")
        except Exception as exc:
            fail += 1
            log(f"❌ [{i}] 异常: {exc}")

        if delay > 0 and i < total:
            time.sleep(delay)

    result = {
        "total": total,
        "ok": ok,
        "skipped": skipped,
        "fail": fail,
        "stopped": stopped,
    }
    status = "已停止" if stopped else "完成"
    log(f"📊 {status}: {ok}/{total} 成功, {skipped} 跳过, {fail} 失败")
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
    )
    return 0 if result["fail"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
