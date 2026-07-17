# -*- coding: utf-8 -*-
"""启动前连通性检查：代理 / 邮箱 API / CPA。"""
from __future__ import annotations

import socket
import time
from typing import Callable, List, Tuple
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


def check_email_api(provider: str, config: dict, http_get: Callable, http_post: Callable) -> CheckResult:
    provider = (provider or "").strip().lower()
    try:
        if provider == "cloudflare":
            base = str(config.get("cloudflare_api_base", "") or "").rstrip("/")
            if not base:
                return "邮箱API", False, "未配置 cloudflare_api_base"
            # 试 domains 或根
            path = str(config.get("cloudflare_path_domains", "/api/domains") or "/api/domains")
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
                accounts_path = str(
                    config.get("cloudflare_path_accounts", "/api/new_address")
                    or "/api/new_address"
                ).rstrip("/").lower()
                direct_anonymous_create = (
                    accounts_path.endswith("/new_address")
                    and not api_key
                    and not custom_auth
                    and auth_mode.lower() == "none"
                )
                if direct_anonymous_create and resp.status_code in (401, 403):
                    return (
                        "邮箱API",
                        True,
                        f"Cloudflare 直建模式可用（domains HTTP {resp.status_code}，当前流程不依赖该接口）",
                    )
                # cloudflare_temp_email 常见：无 /api/domains 或鉴权后仍 401。
                # 实际建号走 /api/new_address 或 /admin/new_address；改探 open_api/settings。
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
                except Exception:
                    pass
                # admin 建号路径：domains 非必须
                if cloudflare_provider.is_admin_create_path(accounts_path) and (
                    api_key or custom_auth
                ):
                    return (
                        "邮箱API",
                        True,
                        f"Cloudflare admin 建号模式可用（domains HTTP {resp.status_code}，当前流程不依赖该接口）",
                    )
                return "邮箱API", False, f"Cloudflare HTTP {resp.status_code}"
            return "邮箱API", True, f"Cloudflare 可达 HTTP {resp.status_code}"

        if provider == "duckmail":
            base = str(config.get("duckmail_api_base", "") or "https://api.duckmail.sbs").rstrip("/")
            resp = http_get(f"{base}/domains", headers={"Accept": "application/json"}, timeout=12)
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
            resp = http_get("https://maliapi.215.im/v1/domains", headers=headers, timeout=12)
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
            return "邮箱API", resp.status_code < 400, f"MailNest 站点 HTTP {resp.status_code}"

        if provider == "cloudmail":
            url = str(config.get("cloudmail_url", "") or "").rstrip("/")
            if not url:
                return "邮箱API", False, "未配置 cloudmail_url"
            resp = http_get(url, timeout=10)
            return "邮箱API", resp.status_code < 400, f"CloudMail HTTP {resp.status_code}"

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
        import os
        if os.path.isdir(auth_dir):
            parts.append(f"本地目录OK")
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
            # 远程 CPA 可能需走 config.proxy（国内直连 443 常超时，但经代理 HTTP 正常）。
            # 本机 / 局域网地址强制直连，避免把 localhost 塞进系统代理导致假失败。
            proxy = str(config.get("proxy", "") or "").strip()
            is_local_host = host in {
                "127.0.0.1",
                "localhost",
                "::1",
                "0.0.0.0",
            } or host.startswith("192.168.") or host.startswith("10.") or (
                host.startswith("172.")
                and len(host.split(".")) >= 2
                and host.split(".")[1].isdigit()
                and 16 <= int(host.split(".")[1]) <= 31
            )
            req_kwargs = {
                "headers": {"Authorization": f"Bearer {key}"},
                "timeout": 12,
            }
            use_proxy = bool(proxy) and not is_local_host
            if use_proxy:
                req_kwargs["proxies"] = {"http": proxy, "https": proxy}
            else:
                # 未配代理或本机 CPA：先 TCP 预检，再强制直连
                if not _tcp_open(host if host != "localhost" else "127.0.0.1", port):
                    return "CPA", False, f"远程不可达 {host}:{port}"
                req_kwargs["proxies"] = {}
            resp = http_get(f"{base}/v0/management/auth-files", **req_kwargs)
            if resp.status_code in (401, 403):
                return "CPA", False, f"管理密钥无效 HTTP {resp.status_code}"
            if resp.status_code >= 500:
                return "CPA", False, f"CPA 服务异常 HTTP {resp.status_code}"
            via = "via proxy" if use_proxy else "direct"
            parts.append(f"远程OK HTTP {resp.status_code} ({via})")
        except Exception as exc:
            return "CPA", False, f"远程探测失败: {exc}"
    return "CPA", True, "；".join(parts) if parts else "OK"


def run_connectivity_checks(config: dict, http_get: Callable, http_post: Callable) -> List[CheckResult]:
    results = []
    results.append(check_proxy(str(config.get("proxy", "") or ""), http_get))
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
