# -*- coding: utf-8 -*-
"""启动前连通性检查：代理 / 邮箱 API / CPA。"""

from __future__ import annotations

import os
import socket
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from email_providers import cloudflare as cloudflare_provider

CheckResult = Tuple[str, bool, str]  # name, ok, detail


def _tcp_open(host: str, port: int, timeout: float = 2.0) -> bool:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def is_local_or_private_host(host: str) -> bool:
    """本机 / RFC1918 局域网：CPA 探测与上传强制直连，避免被系统代理劫持。"""
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return True
    if h in {"127.0.0.1", "localhost", "::1", "0.0.0.0"}:
        return True
    if h.startswith("192.168.") or h.startswith("10."):
        return True
    if h.startswith("172."):
        parts = h.split(".")
        if len(parts) >= 2 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
            return True
    return False


def resolve_config_proxy(config: Optional[dict] = None, proxy: str = "") -> str:
    """与注册流程一致：显式 proxy → config.proxy → 环境变量。"""
    explicit = str(proxy or "").strip()
    if explicit:
        return explicit
    if config:
        from_config = str(config.get("proxy", "") or "").strip()
        if from_config:
            return from_config
    for key in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"):
        val = str(os.environ.get(key, "") or "").strip()
        if val:
            return val
    return ""


def proxies_for_cpa_host(host: str, proxy: str = "") -> Dict[str, str]:
    """返回 requests 用的 proxies。

    - 本机/局域网：始终 ``{}``（强制直连，禁用环境代理）
    - 公网且配置了 proxy：``{http,https: proxy}``
    - 公网且无 proxy：``{}``（与探测一致，显式直连）
    """
    proxy = str(proxy or "").strip()
    if proxy and not is_local_or_private_host(host):
        return {"http": proxy, "https": proxy}
    return {}


def check_proxy(proxy_url: str, http_get: Callable) -> CheckResult:
    proxy_url = (proxy_url or "").strip()
    if not proxy_url:
        return "代理", True, "未配置（直连）"
    try:
        u = urlparse(proxy_url)
        host = u.hostname or "127.0.0.1"
        port = u.port or (443 if u.scheme == "https" else 80)
        if not _tcp_open(host, port):
            return "代理", False, f"无法连接 {host}:{port}"
        # 轻量探测
        try:
            http_get(
                "https://www.cloudflare.com/cdn-cgi/trace",
                timeout=8,
                proxies={"http": proxy_url, "https": proxy_url},
            )
        except Exception as exc:
            # TCP 通但出站失败也提示
            return "代理", False, f"TCP 通，出站探测失败: {exc}"
        return "代理", True, f"{host}:{port} 可用"
    except Exception as exc:
        return "代理", False, str(exc)


def check_email_api(
    provider: str, config: dict, http_get: Callable, http_post: Callable
) -> CheckResult:
    provider = (provider or "").strip().lower()
    try:
        if provider == "cloudflare":
            base = str(config.get("cloudflare_api_base", "") or "").rstrip("/")
            if not base:
                return "邮箱API", False, "未配置 cloudflare_api_base"
            # 试 domains 或根
            path = str(
                config.get("cloudflare_path_domains", "/api/domains") or "/api/domains"
            )
            if not path.startswith("/"):
                path = "/" + path
            url = f"{base}{path}"
            api_key = str(config.get("cloudflare_api_key", "") or "")
            auth_mode = str(config.get("cloudflare_auth_mode", "none") or "none")
            custom_auth = str(config.get("cloudflare_custom_auth", "") or "")
            headers = cloudflare_provider.build_headers(api_key, auth_mode, custom_auth)
            params = cloudflare_provider.apply_auth_params({}, api_key, auth_mode)
            resp = http_get(url, headers=headers, params=params, timeout=10)
            if resp.status_code >= 400:
                accounts_path = (
                    str(
                        config.get("cloudflare_path_accounts", "/api/new_address")
                        or "/api/new_address"
                    )
                    .rstrip("/")
                    .lower()
                )
                # 非 admin 的 /new_address：注册不依赖 domains 列表
                direct_create = accounts_path.endswith(
                    "/new_address"
                ) and not accounts_path.endswith("/admin/new_address")
                if direct_create and resp.status_code in (401, 403):
                    return (
                        "邮箱API",
                        True,
                        f"Cloudflare 直建模式可继续（domains HTTP {resp.status_code}，注册流程不依赖该接口）",
                    )
                # cloudflare_temp_email：/api/domains 常 401；改探公开 settings
                settings_detail = ""
                try:
                    settings_headers = cloudflare_provider.apply_custom_auth(
                        {}, custom_auth
                    )
                    settings_resp = http_get(
                        f"{base}/open_api/settings",
                        headers=settings_headers,
                        timeout=10,
                    )
                    if settings_resp.status_code < 400:
                        return (
                            "邮箱API",
                            True,
                            f"Cloudflare 可达（open_api/settings HTTP {settings_resp.status_code}；domains HTTP {resp.status_code} 可忽略）",
                        )
                    settings_detail = (
                        f"open_api/settings HTTP {settings_resp.status_code}"
                    )
                except (OSError, TimeoutError, ConnectionError, ValueError) as exc:
                    settings_detail = f"open_api/settings 异常: {exc}"
                except Exception as exc:
                    # requests 等第三方异常类型不一，保留摘要便于排障
                    settings_detail = (
                        f"open_api/settings 异常: {type(exc).__name__}: {exc}"
                    )
                # admin 建号亦不依赖 domains；有凭证且 worker 已由 settings 证明可达时上面已返回。
                # settings 也失败时不再仅凭「配了 admin path」判 OK，避免死实例假绿。
                if cloudflare_provider.is_admin_create_path(accounts_path) and (
                    api_key or custom_auth
                ):
                    extra = f"；{settings_detail}" if settings_detail else ""
                    return (
                        "邮箱API",
                        False,
                        f"Cloudflare admin 建号模式：domains HTTP {resp.status_code}，"
                        f"且未能确认 worker 可达{extra}",
                    )
                fail = f"Cloudflare HTTP {resp.status_code}"
                if settings_detail:
                    fail = f"{fail}；{settings_detail}"
                return "邮箱API", False, fail
            return "邮箱API", True, f"Cloudflare 可达 HTTP {resp.status_code}"

        if provider == "duckmail":
            base = str(
                config.get("duckmail_api_base", "") or "https://api.duckmail.sbs"
            ).rstrip("/")
            resp = http_get(
                f"{base}/domains", headers={"Accept": "application/json"}, timeout=12
            )
            if resp.status_code >= 400:
                return "邮箱API", False, f"DuckMail/Mail.tm HTTP {resp.status_code}"
            return "邮箱API", True, f"DuckMail/Mail.tm 可达 HTTP {resp.status_code}"

        if provider == "yyds":
            key = str(config.get("yyds_api_key", "") or "")
            jwt = str(config.get("yyds_jwt", "") or "")
            if not key and not jwt:
                return "邮箱API", False, "YYDS 需配置 API Key 或 JWT"
            headers = {}
            if jwt:
                headers["Authorization"] = f"Bearer {jwt}"
            elif key:
                headers["X-API-Key"] = key
            resp = http_get(
                "https://maliapi.215.im/v1/domains", headers=headers, timeout=12
            )
            ok = resp.status_code < 400
            return "邮箱API", ok, f"YYDS HTTP {resp.status_code}"

        if provider == "mailnest":
            key = str(config.get("mailnest_api_key", "") or "").strip()
            if not key:
                return "邮箱API", False, "MailNest 需配置 API Key"
            # 不实际买号，只检查鉴权头能否打到站点
            resp = http_get(
                "https://mailnest.top/",
                headers={"Authorization": f"Bearer {key}"},
                timeout=12,
            )
            return (
                "邮箱API",
                resp.status_code < 400,
                f"MailNest 站点 HTTP {resp.status_code}",
            )

        if provider == "cloudmail":
            url = str(config.get("cloudmail_url", "") or "").rstrip("/")
            if not url:
                return "邮箱API", False, "未配置 cloudmail_url"
            resp = http_get(url, timeout=10)
            return (
                "邮箱API",
                resp.status_code < 400,
                f"CloudMail HTTP {resp.status_code}",
            )

        return "邮箱API", True, f"提供商 {provider} 跳过深度探测"
    except Exception as exc:
        return "邮箱API", False, str(exc)


def check_cpa(config: dict, http_get: Callable) -> CheckResult:
    if not config.get("cpa_auto_add"):
        return "CPA", True, "未开启 SSO→auth（跳过）"
    auth_dir = str(config.get("cpa_auth_dir", "") or "").strip()
    remote = str(config.get("cpa_remote_url", "") or "").strip()
    key = str(config.get("cpa_management_key", "") or "").strip()
    if not auth_dir and not remote:
        return "CPA", False, "已开启但未配置 auth 目录或远程地址"
    parts = []
    if auth_dir:
        if os.path.isdir(auth_dir):
            parts.append("本地目录OK")
        else:
            return "CPA", False, f"auth 目录不存在: {auth_dir}"
    if remote:
        if not key:
            return "CPA", False, "已配远程地址但缺少管理密钥"
        try:
            u = urlparse(remote)
            host = (u.hostname or "127.0.0.1").lower()
            port = u.port or (443 if u.scheme == "https" else 80)
            base = remote.rstrip("/")
            # 与 upload_cpa_auth_remote / collect_remote_auth_emails 共用同一策略
            proxy = resolve_config_proxy(config)
            req_proxies = proxies_for_cpa_host(host, proxy)
            use_proxy = bool(req_proxies)
            if not use_proxy:
                tcp_host = "127.0.0.1" if host == "localhost" else host
                if not _tcp_open(tcp_host, port):
                    return "CPA", False, f"远程不可达 {host}:{port}"
            resp = http_get(
                f"{base}/v0/management/auth-files",
                headers={"Authorization": f"Bearer {key}"},
                timeout=12,
                proxies=req_proxies,
            )
            if resp.status_code in (401, 403):
                return "CPA", False, f"管理密钥无效 HTTP {resp.status_code}"
            if resp.status_code >= 500:
                return "CPA", False, f"CPA 服务异常 HTTP {resp.status_code}"
            via = "via proxy" if use_proxy else "direct"
            parts.append(f"远程OK HTTP {resp.status_code} ({via})")
        except Exception as exc:
            return "CPA", False, f"远程探测失败: {exc}"
    return "CPA", True, "；".join(parts) if parts else "OK"


def run_connectivity_checks(
    config: dict, http_get: Callable, http_post: Callable
) -> List[CheckResult]:
    results = []
    results.append(check_proxy(resolve_config_proxy(config), http_get))
    results.append(
        check_email_api(
            str(config.get("email_provider", "") or ""),
            config,
            http_get,
            http_post,
        )
    )
    results.append(check_cpa(config, http_get))
    return results


def format_check_results(results: List[CheckResult]) -> str:
    lines = []
    for name, ok, detail in results:
        mark = "OK" if ok else "FAIL"
        lines.append(f"[{mark}] {name}: {detail}")
    return "\n".join(lines)
