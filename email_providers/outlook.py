"""Outlook OAuth2 mailbox provider used by the registration flow.

The legacy input format is::

    email----password----client_id----refresh_token

The password column is accepted for compatibility and discarded immediately.
Only Microsoft Graph is used to read verification emails.
"""

from __future__ import annotations

import html
import json
import os
import re
import secrets
import ssl
import tempfile
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

from email_providers.common import extract_verification_code


GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
TOKEN_URL_TEMPLATE = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
GRAPH_DELEGATED_SCOPE = "https://graph.microsoft.com/Mail.Read offline_access"
DEFAULT_TENANT = "consumers"


class OutlookError(RuntimeError):
    pass


class OutlookConfigError(OutlookError, ValueError):
    pass


class OutlookAuthError(OutlookError):
    pass


class OutlookHTTPError(OutlookError):
    def __init__(self, status: int, message: str):
        self.status = int(status)
        self.message = str(message or "")
        super().__init__(f"HTTP {self.status}: {self.message}")


class OutlookPoolExhausted(OutlookError):
    pass


class OutlookLeaseError(OutlookError):
    pass


@dataclass
class OutlookAccount:
    email: str
    client_id: str
    refresh_token: str = field(repr=False)
    tenant: str = DEFAULT_TENANT


@dataclass
class _OutlookLease:
    account: OutlookAccount = field(repr=False)
    acquired_at: datetime
    state: str = "leased"


def _redact_message(value: Any) -> str:
    secret_keys = {"refresh_token", "refreshtoken", "access_token", "accesstoken", "password"}

    def redact_object(item: Any) -> Any:
        if isinstance(item, dict):
            return {
                key: "<redacted>"
                if str(key).replace("-", "_").lower() in secret_keys
                else redact_object(item_value)
                for key, item_value in item.items()
            }
        if isinstance(item, list):
            return [redact_object(entry) for entry in item]
        return item

    if isinstance(value, (dict, list)):
        text = json.dumps(redact_object(value), ensure_ascii=False)
    else:
        text = str(value or "")
        try:
            parsed = json.loads(text)
        except (TypeError, ValueError):
            pass
        else:
            if isinstance(parsed, (dict, list)):
                text = json.dumps(redact_object(parsed), ensure_ascii=False)
    text = re.sub(
        r"(?i)((?:['\"])?(?:refresh[_-]?token|access[_-]?token|password)(?:['\"])?\s*[:=]\s*(?:['\"])?)([^'\"\s,}&]+)",
        r"\1<redacted>",
        text,
    )
    text = re.sub(r"(?i)bearer\s+[^\s,}]+", "Bearer <redacted>", text)
    return text[:400]


def _required_string(item: Dict[str, Any], *names: str) -> str:
    for name in names:
        value = item.get(name)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _account_from_mapping(item: Any, source: str) -> OutlookAccount:
    if not isinstance(item, dict):
        raise OutlookConfigError(f"{source}: 每个账号必须是 JSON 对象")
    email = _required_string(item, "email", "account", "address")
    client_id = _required_string(item, "client_id", "clientid", "clientId")
    refresh_token = _required_string(item, "refresh_token", "refreshToken")
    tenant = _required_string(item, "tenant", "tenant_id", "tenantId") or DEFAULT_TENANT
    missing = [
        name
        for name, value in (
            ("email", email),
            ("client_id", client_id),
            ("refresh_token", refresh_token),
        )
        if not value
    ]
    if missing:
        raise OutlookConfigError(f"{source}: 缺少 {', '.join(missing)}")
    return OutlookAccount(email, client_id, refresh_token, tenant)


def _deduplicate(accounts: List[OutlookAccount]) -> List[OutlookAccount]:
    unique = []
    seen = set()
    for account in accounts:
        key = account.email.strip().casefold()
        if key in seen:
            continue
        seen.add(key)
        unique.append(account)
    return unique


def parse_accounts_text(text: str, source: str = "Outlook 输入") -> List[OutlookAccount]:
    """Parse JSON or four-field text without retaining the password field."""

    raw_text = str(text or "")
    if not raw_text.strip():
        raise OutlookConfigError("Outlook 账号内容为空")
    accounts: List[OutlookAccount] = []
    if Path(source).suffix.lower() == ".json" or raw_text.lstrip().startswith(("[", "{")):
        try:
            payload = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise OutlookConfigError(f"Outlook JSON 格式错误: {exc}") from exc
        if isinstance(payload, dict):
            payload = payload.get("accounts")
        if not isinstance(payload, list):
            raise OutlookConfigError("Outlook JSON 顶层必须是数组或包含 accounts 数组")
        for index, item in enumerate(payload, 1):
            accounts.append(_account_from_mapping(item, f"{source}[{index}]"))
    else:
        for line_number, raw_line in enumerate(raw_text.splitlines(), 1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            fields = [part.strip() for part in line.split("----", 3)]
            if len(fields) != 4:
                raise OutlookConfigError(
                    f"{source}:{line_number}: 需要 email----password----client_id----refresh_token"
                )
            email, _password, client_id, refresh_token = fields
            accounts.append(
                _account_from_mapping(
                    {
                        "email": email,
                        "client_id": client_id,
                        "refresh_token": refresh_token,
                    },
                    f"{source}:{line_number}",
                )
            )
    if not accounts:
        raise OutlookConfigError("Outlook 账号内容没有有效记录")
    return _deduplicate(accounts)


def load_accounts_file(path: str) -> List[OutlookAccount]:
    if not str(path or "").strip():
        raise OutlookConfigError("未配置 Outlook 账号文件")
    file_path = Path(path).expanduser()
    if not file_path.is_file():
        raise OutlookConfigError(f"Outlook 账号文件不存在: {file_path}")
    try:
        text = file_path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise OutlookConfigError(f"无法读取 Outlook 账号文件: {exc}") from exc
    return parse_accounts_text(text, source=str(file_path))


def write_accounts_json(path: str, accounts: List[OutlookAccount]) -> str:
    """Atomically write a password-free local JSON account file."""

    payload = [
        {
            "email": account.email,
            "client_id": account.client_id,
            "refresh_token": account.refresh_token,
            "tenant": account.tenant,
        }
        for account in _deduplicate(list(accounts or []))
    ]
    if not payload:
        raise OutlookConfigError("没有可写入的 Outlook 账号")
    file_path = Path(path).expanduser()
    file_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{file_path.name}.", suffix=".tmp", dir=str(file_path.parent)
    )
    try:
        os.chmod(temporary_name, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        os.replace(temporary_name, file_path)
        try:
            os.chmod(file_path, 0o600)
        except OSError:
            pass
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise
    return str(file_path)


def _verified_ssl_context() -> ssl.SSLContext:
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def _http_json(
    url: str,
    *,
    method: str = "GET",
    form: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 30,
    proxy: str = "",
) -> Dict[str, Any]:
    request_headers = {"Accept": "application/json"}
    request_headers.update(headers or {})
    data = None
    if form is not None:
        request_headers["Content-Type"] = "application/x-www-form-urlencoded"
        data = urlencode(form).encode("utf-8")
    request = Request(url, data=data, headers=request_headers, method=method)
    handlers = [HTTPSHandler(context=_verified_ssl_context())]
    if str(proxy or "").strip():
        handlers.append(ProxyHandler({"http": proxy, "https": proxy}))
    try:
        with build_opener(*handlers).open(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
            status = int(getattr(response, "status", 200) or 200)
    except HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw)
            error = payload.get("error") if isinstance(payload, dict) else ""
            description = payload.get("error_description") if isinstance(payload, dict) else ""
            detail = ": ".join(part for part in (str(error or ""), str(description or "")) if part) or payload
        except Exception:
            detail = raw
        raise OutlookHTTPError(exc.code, _redact_message(detail)) from exc
    except (OSError, URLError) as exc:
        raise OutlookError(f"Outlook 网络请求失败: {_redact_message(exc)}") from exc
    if status >= 400:
        raise OutlookHTTPError(status, _redact_message(raw))
    try:
        payload = json.loads(raw) if raw else {}
    except json.JSONDecodeError as exc:
        raise OutlookError("Outlook 返回了无效 JSON") from exc
    if not isinstance(payload, dict):
        raise OutlookError("Outlook 返回的 JSON 不是对象")
    return payload


def refresh_access_token(
    account: OutlookAccount,
    *,
    proxy: str = "",
) -> Tuple[str, Optional[str]]:
    """Exchange the account refresh token for a Microsoft Graph token."""

    url = TOKEN_URL_TEMPLATE.format(tenant=account.tenant or DEFAULT_TENANT)
    base_form = {
        "client_id": account.client_id,
        "grant_type": "refresh_token",
        "refresh_token": account.refresh_token,
    }
    payload = None
    for index, scope in enumerate((GRAPH_SCOPE, GRAPH_DELEGATED_SCOPE, None)):
        form = dict(base_form)
        if scope:
            form["scope"] = scope
        try:
            payload = _http_json(url, method="POST", form=form, proxy=proxy)
            break
        except OutlookHTTPError as exc:
            detail = exc.message.lower()
            scope_error = any(
                marker in detail for marker in ("aadsts70000", "aadsts70011", "invalid_scope")
            )
            if not scope_error or index == 2:
                raise OutlookAuthError(
                    f"{account.email} OAuth2 刷新失败（{exc.status}）: {_redact_message(exc.message)}"
                ) from exc
    access_token = str((payload or {}).get("access_token") or "").strip()
    if not access_token:
        raise OutlookAuthError(f"{account.email} OAuth2 刷新失败: 缺少 access_token")
    rotated = str((payload or {}).get("refresh_token") or "").strip() or None
    return access_token, rotated


def _graph_url(path: str, params: Optional[Dict[str, Any]] = None) -> str:
    url = f"{GRAPH_BASE_URL.rstrip('/')}/{path.lstrip('/')}"
    if params:
        url += "?" + urlencode(params)
    return url


def graph_list_messages(
    access_token: str,
    *,
    top: int = 25,
    proxy: str = "",
) -> List[Dict[str, Any]]:
    payload = _http_json(
        _graph_url(
            "/me/mailFolders/inbox/messages",
            {
                "$select": "id,subject,bodyPreview,receivedDateTime,from",
                "$orderby": "receivedDateTime desc",
                "$top": max(1, min(int(top or 25), 100)),
            },
        ),
        headers={"Authorization": f"Bearer {access_token}"},
        proxy=proxy,
    )
    value = payload.get("value")
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def graph_get_message(access_token: str, message_id: str, *, proxy: str = "") -> Dict[str, Any]:
    return _http_json(
        _graph_url(
            f"/me/messages/{quote(str(message_id), safe='')}",
            {"$select": "id,subject,body,bodyPreview,receivedDateTime"},
        ),
        headers={"Authorization": f"Bearer {access_token}"},
        proxy=proxy,
    )


def _message_text(message: Dict[str, Any]) -> str:
    body = message.get("body") or {}
    content = str(body.get("content") or "") if isinstance(body, dict) else ""
    return "\n".join(
        [
            str(message.get("subject") or ""),
            str(message.get("bodyPreview") or ""),
            html.unescape(content),
        ]
    )


def _received_at(message: Dict[str, Any]) -> Optional[datetime]:
    raw = str(message.get("receivedDateTime") or "").strip()
    if not raw:
        return None
    try:
        value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def wait_for_code_graph(
    account: OutlookAccount,
    *,
    timeout: int = 180,
    poll_interval: int = 3,
    not_before: Optional[datetime] = None,
    log_callback: Optional[Callable[[str], None]] = None,
    cancel_callback: Optional[Callable[[], bool]] = None,
    resend_callback: Optional[Callable[[], None]] = None,
    refresh_token_callback: Optional[Callable[[OutlookAccount, str], None]] = None,
    proxy: str = "",
) -> str:
    deadline = time.time() + max(1, int(timeout or 180))
    next_resend_at = time.time() + 35
    cutoff = not_before
    if cutoff is not None:
        if cutoff.tzinfo is None:
            cutoff = cutoff.replace(tzinfo=timezone.utc)
        cutoff = cutoff.astimezone(timezone.utc)
    seen_ids = set()
    access_token, rotated = refresh_access_token(account, proxy=proxy)
    if rotated and refresh_token_callback:
        refresh_token_callback(account, rotated)
    while time.time() < deadline:
        if cancel_callback and cancel_callback():
            raise OutlookError("Outlook 收信已取消")
        if resend_callback and time.time() >= next_resend_at:
            resend_callback()
            next_resend_at = time.time() + 35
        try:
            messages = graph_list_messages(access_token, proxy=proxy)
        except OutlookHTTPError as exc:
            if exc.status != 401:
                raise
            access_token, rotated = refresh_access_token(account, proxy=proxy)
            if rotated and refresh_token_callback:
                refresh_token_callback(account, rotated)
            messages = graph_list_messages(access_token, proxy=proxy)
        for summary in messages:
            message_id = str(summary.get("id") or "")
            if not message_id or message_id in seen_ids:
                continue
            received = _received_at(summary)
            if cutoff is not None and (received is None or received < cutoff):
                seen_ids.add(message_id)
                continue
            try:
                detail = graph_get_message(access_token, message_id, proxy=proxy)
            except OutlookError:
                continue
            code = extract_verification_code(_message_text(detail), str(detail.get("subject") or ""))
            seen_ids.add(message_id)
            if code:
                return code
        remaining = max(0.0, deadline - time.time())
        time.sleep(min(max(0.1, float(poll_interval or 3)), remaining))
    raise OutlookError(f"Outlook Graph 在 {timeout}s 内未找到验证码")


class OutlookBatchRuntime:
    """Single-use Outlook account pool for one registration batch."""

    @classmethod
    def from_file(cls, path: str, *, proxy: str = "") -> "OutlookBatchRuntime":
        return cls(load_accounts_file(path), proxy=proxy)

    def __init__(self, accounts: List[OutlookAccount], *, proxy: str = ""):
        unique = _deduplicate(list(accounts or []))
        if not unique:
            raise OutlookConfigError("没有可用的 Outlook 账号")
        self.proxy = str(proxy or "")
        self._lock = threading.RLock()
        self._available: Deque[OutlookAccount] = deque(unique)
        self._leases: Dict[str, _OutlookLease] = {}
        self._total_count = len(unique)
        self._succeeded_count = 0
        self._failed_count = 0
        self._closed = False

    def acquire(self) -> Tuple[str, str]:
        with self._lock:
            if self._closed:
                raise OutlookLeaseError("Outlook 批次已关闭")
            if not self._available:
                raise OutlookPoolExhausted("Outlook 账号池已耗尽")
            account = self._available.popleft()
            lease_id = secrets.token_urlsafe(24)
            self._leases[lease_id] = _OutlookLease(
                account=account,
                acquired_at=datetime.now(timezone.utc),
            )
            return account.email, lease_id

    def resolve(self, lease_id: str) -> OutlookAccount:
        with self._lock:
            lease = self._leases.get(str(lease_id or ""))
            if lease is None or lease.state != "leased":
                raise OutlookLeaseError("Outlook 账号租约无效或已结算")
            return lease.account

    def wait_code(self, lease_id: str, **kwargs: Any) -> str:
        with self._lock:
            lease = self._leases.get(str(lease_id or ""))
            if lease is None or lease.state != "leased":
                raise OutlookLeaseError("Outlook 账号租约无效或已结算")
            account = lease.account
            acquired_at = lease.acquired_at

        def _update_refresh_token(target: OutlookAccount, refresh_token: str) -> None:
            target.refresh_token = refresh_token

        return wait_for_code_graph(
            account,
            not_before=acquired_at,
            refresh_token_callback=_update_refresh_token,
            proxy=self.proxy,
            **kwargs,
        )

    def _settle(self, lease_id: str, state: str) -> bool:
        with self._lock:
            lease_id = str(lease_id or "").strip()
            if not lease_id:
                return False
            lease = self._leases.get(lease_id)
            if lease is None or lease.state != "leased":
                return False
            lease.state = state
            if state == "succeeded":
                self._succeeded_count += 1
            else:
                self._failed_count += 1
            return True

    def succeed(self, lease_id: str) -> bool:
        return self._settle(lease_id, "succeeded")

    def fail(self, lease_id: str) -> bool:
        return self._settle(lease_id, "failed")

    def _only_active_lease_id(self) -> str:
        with self._lock:
            active = [lease_id for lease_id, lease in self._leases.items() if lease.state == "leased"]
            return active[0] if len(active) == 1 else ""

    def succeed_current(self) -> bool:
        return self.succeed(self._only_active_lease_id())

    def fail_current(self) -> bool:
        return self.fail(self._only_active_lease_id())

    @property
    def total_count(self) -> int:
        return self._total_count

    @property
    def available_count(self) -> int:
        with self._lock:
            return len(self._available)

    @property
    def succeeded_count(self) -> int:
        return self._succeeded_count

    @property
    def failed_count(self) -> int:
        return self._failed_count

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            for account in self._available:
                account.refresh_token = ""
            for lease in self._leases.values():
                lease.account.refresh_token = ""
            self._available.clear()
            self._leases.clear()
            self._closed = True


def check_account(account: OutlookAccount, *, proxy: str = "", top: int = 5) -> Dict[str, Any]:
    access_token, rotated = refresh_access_token(account, proxy=proxy)
    if rotated:
        account.refresh_token = rotated
    messages = graph_list_messages(access_token, top=top, proxy=proxy)
    return {
        "email": account.email,
        "protocol": "graph",
        "message_count": len(messages),
    }


__all__ = [
    "GRAPH_SCOPE",
    "OutlookAccount",
    "OutlookAuthError",
    "OutlookBatchRuntime",
    "OutlookConfigError",
    "OutlookError",
    "OutlookHTTPError",
    "OutlookLeaseError",
    "OutlookPoolExhausted",
    "check_account",
    "graph_get_message",
    "graph_list_messages",
    "load_accounts_file",
    "parse_accounts_text",
    "refresh_access_token",
    "wait_for_code_graph",
    "write_accounts_json",
]
