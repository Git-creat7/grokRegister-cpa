#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Grok 注册机 - TTK GUI 版本
整合 DrissionPage_example.py, openai_register.py, batch_open_nsfw.py
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import datetime
import time
import os
import sys
import signal
import gc
import queue
import secrets
import struct
import random
import re
import string
import json
import base64

os.environ.setdefault("TK_SILENCE_DEPRECATION", "1")

from DrissionPage import Chromium, ChromiumOptions
from DrissionPage.errors import PageDisconnectedError
from curl_cffi import requests

# SSO → CLIProxyAPI(CPA) 扁平格式转换（复用 sso_to_auth_json 的授权码流程 + 写入器）
import sso_to_auth_json as _s2cpa
from email_providers import cloudflare as cloudflare_provider
from email_providers import cloudmail as cloudmail_provider
from email_providers import duckmail as duckmail_provider
from email_providers import mailnest as mailnest_provider
from email_providers import yyds as yyds_provider
from email_providers.common import extract_verification_code as _extract_code
from email_providers.common import generate_username as _generate_username
from email_providers.common import pick_list_payload as _pick_list

import browser_session as _bs
import register_flow as _rf
import connectivity as _conn
from nsfw_retry import NsfwRetryWorker
from browser_session import (
    browser,
    page,
    active_browser as _active_browser,
    active_page as _active_page,
    set_browser_session as _set_browser_session,
    start_browser,
    stop_browser,
    restart_browser,
    cleanup_runtime_memory,
    refresh_active_page,
    extract_cf_clearance_and_ua,
    create_browser_options,
    get_start_fail_streak,
)
from register_flow import (
    SIGNUP_URL,
    click_email_signup_button,
    open_signup_page,
    has_profile_form,
    detect_email_domain_rejection,
    raise_if_email_domain_rejected,
    fill_email_and_submit,
    fill_code_and_submit,
    getTurnstileToken,
    build_profile,
    fill_profile_and_submit,
    wait_for_sso_cookie,
)
import protocol_signup as _protocol
import protocol_pipeline as _pipeline



APP_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(APP_DIR, "config.json")
NSFW_PENDING_FILE = os.path.join(APP_DIR, "nsfw_pending.txt")
NSFW_CANCEL_TIMEOUT = 15.0
MEMORY_CLEANUP_INTERVAL = 5

_session_log_path = None
_session_log_lock = threading.Lock()


def initialize_session_log(log_dir=None, now=None):
    """为本次程序启动创建一个独立的 UTF-8 日志文件。"""
    global _session_log_path
    with _session_log_lock:
        if _session_log_path:
            return _session_log_path

        target_dir = log_dir or os.path.join(APP_DIR, "log")
        os.makedirs(target_dir, exist_ok=True)
        timestamp = (now or datetime.datetime.now()).strftime("%Y%m%d_%H%M%S")
        suffix = 1
        while True:
            suffix_text = "" if suffix == 1 else f"_{suffix}"
            path = os.path.join(target_dir, f"app_{timestamp}{suffix_text}.log")
            try:
                with open(path, "x", encoding="utf-8", newline="\n"):
                    pass
            except FileExistsError:
                suffix += 1
                continue
            _session_log_path = path
            return path


def append_session_log(line):
    path = _session_log_path
    if not path:
        return
    try:
        with _session_log_lock:
            with open(path, "a", encoding="utf-8", newline="\n") as log_file:
                log_file.write(f"{line}\n")
    except OSError:
        # 持久化日志失败不应中断正在进行的注册任务。
        pass

UI_BG = "#242424"
UI_PANEL_BG = "#2b2b2b"
UI_FG = "#f2f2f2"
UI_MUTED_FG = "#b8b8b8"
UI_ENTRY_BG = "#333333"
UI_BUTTON_BG = "#3a3a3a"
UI_ACTIVE_BG = "#4a6078"

DEFAULT_CONFIG = {
    "email_provider": "cloudflare",
    "duckmail_api_key": "",
    "duckmail_api_base": "https://api.duckmail.sbs",
    "defaultDomains": "",
    "cloudmail_url": "",
    "cloudmail_admin_email": "",
    "cloudmail_password": "",
    "cloudflare_api_base": "",
    "cloudflare_api_key": "",
    "cloudflare_auth_mode": "none",
    "cloudflare_custom_auth": "",
    "cloudflare_path_domains": "/api/domains",
    "cloudflare_path_accounts": "/api/new_address",
    "cloudflare_path_token": "/api/token",
    "cloudflare_path_messages": "/api/mails",
    # 开启后创建 user@随机子域.主域（需 Worker RANDOM_SUBDOMAIN_DOMAINS 包含该主域）
    "cloudflare_random_subdomain": False,
    "proxy": "http://127.0.0.1:7890",
    "enable_nsfw": True,
    "close_browser_on_stop": False,
    "log_level": "info",
    "register_count": 1,
    "register_workers": 1,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    # CLIProxyAPI(CPA) 直出：注册拿到 SSO 后自动走授权码流程换 token 并写成 CPA 扁平格式
    "cpa_auto_add": False,
    "cpa_auth_dir": "",
    # 远程 CPA：通过 Management API POST /v0/management/auth-files 上传
    "cpa_remote_url": "",
    "cpa_management_key": "",
    "mailnest_api_key": "",
    "mailnest_project_code": "x-ai001",
    # YYDS：留空自动选已验证域名；填写则固定该域名
    "yyds_default_domain": "",
    # 协议 HTTP 注册（对齐 grok-register-new）：默认开启，避免浏览器 UI 打 bot 标
    "register_mode": "protocol",
}

config = DEFAULT_CONFIG.copy()
_cf_domain_index = 0


class RegistrationCancelled(Exception):
    pass


class AccountRetryNeeded(Exception):
    pass


class EmailDomainRejected(Exception):
    """xAI 拒绝当前邮箱域名（如公共临时域被拉黑）。"""

    def __init__(self, email="", message=""):
        self.email = email or ""
        self.message = message or "邮箱域名已被拒绝"
        domain = ""
        if "@" in self.email:
            domain = self.email.split("@", 1)[1]
        detail = self.message
        if domain and domain not in detail:
            detail = f"{detail}（域名: {domain}）"
        if self.email and self.email not in detail:
            detail = f"{detail} | 邮箱: {self.email}"
        super().__init__(detail)



FAIL_DOMAIN = "domain_rejected"
FAIL_CODE = "code_timeout"
FAIL_BROWSER = "browser"
FAIL_CPA = "cpa"
FAIL_STUCK = "stuck_retry"
FAIL_SSO = "sso_timeout"
FAIL_OTHER = "other"

FAIL_LABELS = {
    FAIL_DOMAIN: "域名拒绝",
    FAIL_CODE: "验证码超时",
    FAIL_BROWSER: "浏览器断开",
    FAIL_CPA: "CPA失败",
    FAIL_STUCK: "流程卡住",
    FAIL_SSO: "SSO超时",
    FAIL_OTHER: "其它",
}


def classify_failure(exc) -> str:
    if isinstance(exc, EmailDomainRejected):
        return FAIL_DOMAIN
    msg = str(exc or "")
    low = msg.lower()
    if isinstance(exc, AccountRetryNeeded) or "达到最大重试" in msg or "流程卡住" in msg:
        return FAIL_STUCK
    if "sso_timeout" in low or "未获取到 sso" in msg or "未获取到 sso cookie" in msg:
        return FAIL_SSO
    if "未收到验证码" in msg or "验证码阶段失败" in msg or "验证码" in msg and "失败" in msg:
        return FAIL_CODE
    if (
        "浏览器" in msg
        or "page disconnected" in low
        or "与页面的连接已断开" in msg
        or "PageDisconnected" in msg
        or "disconnected" in low
    ):
        return FAIL_BROWSER
    if "[CPA]" in msg or "CPA" in msg and ("失败" in msg or "跳过" in msg):
        return FAIL_CPA
    return FAIL_OTHER


def empty_fail_stats():
    return {k: 0 for k in FAIL_LABELS}


def format_fail_stats(stats: dict) -> str:
    parts = [f"{FAIL_LABELS.get(k, k)}={stats.get(k, 0)}" for k in FAIL_LABELS if stats.get(k, 0)]
    if not parts:
        return "无分类失败"
    return " | ".join(parts)



def load_config():
    global config
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            config = {**DEFAULT_CONFIG, **loaded}
        except Exception:
            config = DEFAULT_CONFIG.copy()
    return config


def save_config():
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
    except Exception as e:
        print(f"保存配置失败: {e}")


def ensure_stable_python_runtime():
    if sys.version_info < (3, 14) or os.environ.get("DPE_REEXEC_DONE") == "1":
        return

    local_app_data = os.environ.get("LOCALAPPDATA", "")
    candidates = [
        os.path.join(local_app_data, "Programs", "Python", "Python312", "python.exe"),
        os.path.join(local_app_data, "Programs", "Python", "Python313", "python.exe"),
    ]

    current_python = os.path.normcase(os.path.abspath(sys.executable))
    for candidate in candidates:
        if not os.path.isfile(candidate):
            continue
        if os.path.normcase(os.path.abspath(candidate)) == current_python:
            return

        print(
            f"[*] 检测到 Python {sys.version.split()[0]}，自动切换到更稳定的解释器: {candidate}"
        )
        env = os.environ.copy()
        env["DPE_REEXEC_DONE"] = "1"
        os.execve(candidate, [candidate, os.path.abspath(__file__), *sys.argv[1:]], env)


def warn_runtime_compatibility():
    if sys.version_info >= (3, 14):
        print(
            "[提示] 当前 Python 为 3.14+；若出现 Mail.tm TLS 异常，建议改用 Python 3.12 或 3.13。"
        )


ensure_stable_python_runtime()
warn_runtime_compatibility()

load_config()

EXTENSION_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "turnstilePatch")
)


DUCKMAIL_API_BASE_DEFAULT = duckmail_provider.API_BASE_DEFAULT


def get_proxies():
    proxy = config.get("proxy", "")
    if proxy:
        return {"http": proxy, "https": proxy}
    return {}


def get_duckmail_api_base():
    return duckmail_provider.normalize_base(str(config.get("duckmail_api_base", "") or ""))


def get_duckmail_api_key():
    return config.get("duckmail_api_key", "")



def get_cloudflare_api_base():
    return str(config.get("cloudflare_api_base", "") or "").rstrip("/")


def get_cloudflare_api_key():
    return config.get("cloudflare_api_key", "")


def get_cloudflare_auth_mode():
    return str(config.get("cloudflare_auth_mode", "none") or "none").lower()


def get_cloudflare_custom_auth():
    """全局访问密码（cloudflare_temp_email 的 PASSWORDS）。"""
    return str(config.get("cloudflare_custom_auth", "") or "").strip()


def cloudflare_apply_custom_auth(headers):
    return cloudflare_provider.apply_custom_auth(headers, get_cloudflare_custom_auth())


def get_cloudflare_path(key, default_path):
    return cloudflare_provider.path_from_config(config, key, default_path)


def cloudflare_build_headers(content_type=False):
    return cloudflare_provider.build_headers(
        get_cloudflare_api_key(),
        get_cloudflare_auth_mode(),
        get_cloudflare_custom_auth(),
        content_type=content_type,
    )


def cloudflare_apply_auth_params(params=None):
    return cloudflare_provider.apply_auth_params(
        params, get_cloudflare_api_key(), get_cloudflare_auth_mode()
    )


def cloudflare_next_default_domain():
    global _cf_domain_index
    domains = [x.strip() for x in str(config.get("defaultDomains", "") or "").split(",") if x.strip()]
    domain, _cf_domain_index = cloudflare_provider.next_default_domain(domains, _cf_domain_index)
    return domain


def cloudflare_is_admin_create_path(path):
    return cloudflare_provider.is_admin_create_path(path)


def _pick_list_payload(data):
    return _pick_list(data)


def cloudflare_random_subdomain_enabled():
    return bool(config.get("cloudflare_random_subdomain", False))


def cloudflare_create_temp_address(api_base):
    return cloudflare_provider.create_temp_address(
        http_post,
        api_base,
        accounts_path=get_cloudflare_path("cloudflare_path_accounts", "/api/new_address"),
        domain=cloudflare_next_default_domain(),
        api_key=get_cloudflare_api_key(),
        auth_mode=get_cloudflare_auth_mode(),
        custom_auth=get_cloudflare_custom_auth(),
        name=generate_username(10),
        enable_random_subdomain=cloudflare_random_subdomain_enabled(),
    )


MAILNEST_API_BASE = mailnest_provider.API_BASE
MAILNEST_DEFAULT_PROJECT_CODE = mailnest_provider.DEFAULT_PROJECT_CODE


def get_mailnest_api_key():
    key = str(config.get("mailnest_api_key", "") or "").strip()
    if not key:
        raise Exception(f"请在配置文件中配置 mailnest_api_key | 注册网址：{MAILNEST_API_BASE}")
    return key


def get_mailnest_project_code():
    code = str(config.get("mailnest_project_code", "") or "").strip()
    return code or MAILNEST_DEFAULT_PROJECT_CODE


def mailnest_buy_email():
    return mailnest_provider.buy_email(http_post, get_mailnest_api_key(), get_mailnest_project_code())


def mailnest_receive_email(email):
    return mailnest_provider.receive_email(http_post, get_mailnest_api_key(), email)


def mailnest_get_code(email, timeout=180, poll_interval=3, log_callback=None, cancel_callback=None):
    return mailnest_provider.wait_for_code(
        http_post,
        get_mailnest_api_key(),
        email,
        timeout=timeout,
        poll_interval=poll_interval,
        raise_if_cancelled=raise_if_cancelled,
        sleep_with_cancel=sleep_with_cancel,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
    )


def get_user_agent():
    return config.get(
        "user_agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    )


def _normalize_sso_token(raw_token):
    token = str(raw_token or "").strip()
    if token.startswith("sso="):
        token = token[4:]
    return token


def _resolve_cpa_proxy():
    """CPA 换 token 用的代理：优先 config.proxy，其次环境变量，否则直连。"""
    proxy = str(config.get("proxy", "") or "").strip()
    if proxy:
        return proxy
    for key in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"):
        val = str(os.environ.get(key, "") or "").strip()
        if val:
            return val
    return ""


def _append_sso_pending(email: str, sso: str, log_callback=None):
    """CPA 失败时保留 SSO，便于事后 sso_to_auth_json 重转。"""
    try:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sso_pending.txt")
        line = f"{email}----{sso}\n" if email else f"{sso}\n"
        with open(path, "a", encoding="utf-8") as f:
            f.write(line)
        if log_callback:
            log_callback(f"[CPA] 已追加待重转 SSO → {path}")
    except Exception as exc:
        if log_callback:
            log_callback(f"[CPA] 写入 sso_pending 失败: {exc}")


def use_protocol_register() -> bool:
    mode = str(config.get("register_mode", "protocol") or "protocol").strip().lower()
    env = str(os.environ.get("GROK_REGISTER_MODE", "") or "").strip().lower()
    if env:
        mode = env
    return mode in ("protocol", "http", "api", "1", "true", "yes")


def use_protocol_pipeline(count: int, workers: int = 1) -> bool:
    """批量协议注册走 S/P/C/O 流水线（target>=2）。单号走 register_one（内含并行）。"""
    if not use_protocol_register():
        return False
    env = str(os.environ.get("GROK_PROTOCOL_PIPELINE", "") or "").strip().lower()
    if env in ("0", "false", "no", "off"):
        return False
    if env in ("1", "true", "yes", "on"):
        return int(count or 0) >= 1
    return int(count or 0) >= 2


def run_protocol_pipeline_batch(
    count,
    *,
    log_callback=None,
    should_stop=None,
    on_account=None,
    register_workers=1,
):
    """跑协议 S/P/C/O 流水线。on_account(email, password, sso, profile) 在 O 阶段调用。"""
    proxy = _resolve_cpa_proxy()
    if log_callback:
        log_callback("[*] 注册模式: protocol pipeline（S/P/C/O）")

    def _on_sso(email, password, sso, profile):
        if on_account:
            on_account(email, password, sso, profile or {})
        else:
            add_sso_to_cpa(
                sso,
                email=email,
                log_callback=log_callback,
                should_stop=should_stop,
            )

    pipe = _pipeline.ProtocolPipeline(
        target=int(count or 1),
        proxy=proxy,
        get_email_and_token=get_email_and_token,
        get_oai_code=get_oai_code,
        on_sso=_on_sso,
        log=log_callback,
        should_stop=should_stop,
        register_workers=register_workers,
    )
    return pipe.run()


def register_account_once(log_callback=None, cancel_callback=None):
    """注册一个账号，返回 (email, password, sso, profile)。

    默认走纯 HTTP 协议路径（无注册页浏览器）；register_mode=browser 时回退 UI 路径。
    """
    if use_protocol_register():
        proxy = _resolve_cpa_proxy()
        if log_callback:
            log_callback("[*] 注册模式: protocol（无注册页浏览器）")
        result = _protocol.register_one(
            get_email_and_token=get_email_and_token,
            get_oai_code=get_oai_code,
            proxy=proxy,
            log=log_callback,
            should_stop=cancel_callback,
        )
        return (
            result["email"],
            result.get("password", ""),
            result["sso"],
            result.get("profile") or {},
        )

    if log_callback:
        log_callback("[*] 注册模式: browser（DrissionPage UI）")
    open_signup_page(log_callback=log_callback, cancel_callback=cancel_callback)
    email, dev_token = fill_email_and_submit(
        log_callback=log_callback, cancel_callback=cancel_callback
    )
    code = fill_code_and_submit(
        email,
        dev_token,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
    )
    del code
    profile = fill_profile_and_submit(
        log_callback=log_callback, cancel_callback=cancel_callback
    )
    sso = wait_for_sso_cookie(
        log_callback=log_callback, cancel_callback=cancel_callback
    )
    return email, profile.get("password", ""), sso, profile


def add_sso_to_cpa(raw_token, email="", log_callback=None, should_stop=None) -> bool:
    """SSO → 授权码流程换 token → 写入本地 CPA auth 目录和/或远程 CPA。

    返回 True 表示 CPA 入库成功（或未开启/无需转换）；False 表示转换失败（SSO 仍可能已写入 accounts）。
    """
    if not config.get("cpa_auto_add", False):
        if log_callback:
            log_callback("[*] 已关闭 SSO→CPA auth，仅保存 SSO（不写 auth）")
        return True
    auth_dir = str(config.get("cpa_auth_dir", "") or "").strip()
    remote_url = str(config.get("cpa_remote_url", "") or "").strip()
    management_key = str(config.get("cpa_management_key", "") or "").strip()
    if not auth_dir and not remote_url:
        if log_callback:
            log_callback("[Debug] 已开启 CPA 直出但未配置 cpa_auth_dir 或 cpa_remote_url，跳过")
        return True
    if remote_url and not management_key:
        if log_callback:
            log_callback("[Debug] 已配置 cpa_remote_url 但未配置 cpa_management_key，跳过远程上传")
        remote_url = ""
    if not auth_dir and not remote_url:
        return True
    sso = _normalize_sso_token(raw_token)
    if not sso:
        return False
    proxy = _resolve_cpa_proxy()

    def _cpa_log(message):
        if log_callback:
            log_callback(f"[CPA] {str(message).strip()}")

    try:
        if should_stop and should_stop():
            _cpa_log("用户停止，跳过授权转换")
            return False
        _cpa_log(f"SSO → Device Flow 换 token (proxy={proxy}) ...")
        token = _s2cpa.sso_to_token(
            sso,
            proxy=proxy,
            log=_cpa_log,
            should_stop=should_stop,
        )
        if not token:
            if should_stop and should_stop():
                _cpa_log("用户停止，SSO 已保存在 accounts 文件")
                return False
            _cpa_log("Device Flow 换 token 失败；SSO 已在 accounts 文件，稍后可重转")
            _append_sso_pending(email, sso, log_callback=log_callback)
            return False
        if should_stop and should_stop():
            _cpa_log("用户停止，跳过 auth 写入")
            return False
        record = _s2cpa.token_to_cpa_record(token, email=email, sso=sso)
        ap = _s2cpa.decode_jwt_payload(record.get("access_token", ""))
        ref = ap.get("referrer")
        bot = ap.get("bot_flag_source")
        scope = ap.get("scope")
        if ref:
            _cpa_log(f"警告: access_token 仍带 referrer={ref!r}（健康号应为空）")
        else:
            _cpa_log("access_token 无 referrer（健康样式）")
        if bot is not None:
            _cpa_log(f"警告: bot_flag_source={bot!r}")
        _cpa_log(f"scope={scope!r}")
        wrote_ok = False
        if auth_dir:
            try:
                path = _s2cpa.write_cpa_auth(_s2cpa.Path(auth_dir), record)
                _cpa_log(f"已写入本地 {path}")
                wrote_ok = True
            except Exception as local_exc:
                _cpa_log(f"本地写入失败: {local_exc}")
        if remote_url:
            if should_stop and should_stop():
                _cpa_log("用户停止，跳过远程上传")
                return wrote_ok
            try:
                name = _s2cpa.upload_cpa_auth_remote(remote_url, management_key, record)
                _cpa_log(f"已上传远程 {remote_url.rstrip('/')}/.../{name}")
                wrote_ok = True
            except Exception as remote_exc:
                _cpa_log(f"远程上传失败: {remote_exc}")
        if not wrote_ok:
            _cpa_log("token 已换出但本地/远程均未写入成功")
            _append_sso_pending(email, sso, log_callback=log_callback)
            return False
        # 测活：对齐健康号路径，新 token 可能瞬时 403，内置 warmup+retry
        try:
            code, summary = _s2cpa.probe_cpa_record(
                record, proxy=proxy, timeout=40, warmup=True, retries=3
            )
            _cpa_log(f"probe HTTP {code}: {(summary or '')[:160]}")
            if code != 200:
                _cpa_log("测活未通过，仍保留 auth（可稍后重试 probe）")
        except Exception as probe_exc:
            _cpa_log(f"probe 异常: {probe_exc}")
        return True
    except Exception as exc:
        if should_stop and should_stop():
            _cpa_log("用户停止，SSO 已保存在 accounts 文件")
            return False
        _cpa_log(f"直出失败: {exc}")
        _append_sso_pending(email, sso, log_callback=log_callback)
        return False


# create_browser_options -> browser_session

def _build_request_kwargs(**kwargs):
    request_kwargs = dict(kwargs)
    proxies = request_kwargs.pop("proxies", None)
    if proxies is None:
        proxies = get_proxies()
    if proxies:
        request_kwargs["proxies"] = proxies
    request_kwargs.setdefault("timeout", 15)
    return request_kwargs


def http_get(url, **kwargs):
    try:
        return requests.get(url, **_build_request_kwargs(**kwargs))
    except Exception as exc:
        err = str(exc)
        # 代理不可用时自动回退为直连，避免整个流程直接失败
        if "127.0.0.1 port 7890" in err or "Could not connect to server" in err:
            retry_kwargs = dict(kwargs)
            retry_kwargs["proxies"] = {}
            return requests.get(url, **_build_request_kwargs(**retry_kwargs))
        raise


def http_post(url, **kwargs):
    try:
        return requests.post(url, **_build_request_kwargs(**kwargs))
    except Exception as exc:
        err = str(exc)
        if "127.0.0.1 port 7890" in err or "Could not connect to server" in err:
            retry_kwargs = dict(kwargs)
            retry_kwargs["proxies"] = {}
            return requests.post(url, **_build_request_kwargs(**retry_kwargs))
        raise


def http_delete(url, **kwargs):
    try:
        return requests.delete(url, **_build_request_kwargs(**kwargs))
    except Exception as exc:
        err = str(exc)
        if "127.0.0.1 port 7890" in err or "Could not connect to server" in err:
            retry_kwargs = dict(kwargs)
            retry_kwargs["proxies"] = {}
            return requests.delete(url, **_build_request_kwargs(**retry_kwargs))
        raise


def raise_if_cancelled(cancel_callback=None):
    if cancel_callback and cancel_callback():
        raise RegistrationCancelled("用户停止注册")


def sleep_with_cancel(seconds, cancel_callback=None):
    deadline = time.time() + max(seconds, 0)
    while True:
        raise_if_cancelled(cancel_callback)
        remaining = deadline - time.time()
        if remaining <= 0:
            return
        time.sleep(min(0.2, remaining))


def get_domains(api_key=None):
    return duckmail_provider.get_domains(
        http_get,
        get_duckmail_api_base(),
        api_key=api_key or get_duckmail_api_key(),
    )


def create_account(address, password, api_key=None, expires_in=0):
    return duckmail_provider.create_account(
        http_post,
        get_duckmail_api_base(),
        address,
        password,
        api_key=api_key or get_duckmail_api_key(),
        expires_in=expires_in,
    )


def get_token(address, password):
    return duckmail_provider.get_token(
        http_post,
        get_duckmail_api_base(),
        address,
        password,
    )


def get_messages(token):
    return duckmail_provider.get_messages(
        http_get,
        get_duckmail_api_base(),
        token,
    )


def get_message_detail(token, message_id):
    return duckmail_provider.get_message_detail(
        http_get,
        get_duckmail_api_base(),
        token,
        message_id,
    )



def cloudflare_get_domains(api_base, api_key=None):
    return cloudflare_provider.get_domains(
        http_get,
        api_base,
        domains_path=get_cloudflare_path("cloudflare_path_domains", "/domains"),
        api_key=api_key or get_cloudflare_api_key(),
        auth_mode=get_cloudflare_auth_mode(),
        custom_auth=get_cloudflare_custom_auth(),
    )


def cloudflare_create_account(api_base, address, password, api_key=None, expires_in=0):
    return cloudflare_provider.create_account(
        http_post,
        api_base,
        address,
        password,
        accounts_path=get_cloudflare_path("cloudflare_path_accounts", "/accounts"),
        api_key=api_key or get_cloudflare_api_key(),
        auth_mode=get_cloudflare_auth_mode(),
        custom_auth=get_cloudflare_custom_auth(),
        expires_in=expires_in,
    )


def cloudflare_get_token(api_base, address, password, api_key=None):
    return cloudflare_provider.get_token(
        http_post,
        api_base,
        address,
        password,
        token_path=get_cloudflare_path("cloudflare_path_token", "/token"),
        api_key=api_key or get_cloudflare_api_key(),
        auth_mode=get_cloudflare_auth_mode(),
        custom_auth=get_cloudflare_custom_auth(),
    )


def cloudflare_get_messages(api_base, token):
    return cloudflare_provider.get_messages(
        http_get,
        api_base,
        token,
        messages_path=get_cloudflare_path("cloudflare_path_messages", "/messages"),
        api_key=get_cloudflare_api_key(),
        auth_mode=get_cloudflare_auth_mode(),
        custom_auth=get_cloudflare_custom_auth(),
    )


def cloudflare_get_message_detail(api_base, token, message_id):
    return cloudflare_provider.get_message_detail(
        http_get,
        api_base,
        token,
        message_id,
        messages_path=get_cloudflare_path("cloudflare_path_messages", "/messages"),
        api_key=get_cloudflare_api_key(),
        auth_mode=get_cloudflare_auth_mode(),
        custom_auth=get_cloudflare_custom_auth(),
    )


YYDS_API_BASE = yyds_provider.API_BASE


def get_yyds_api_key():
    return config.get("yyds_api_key", "")


def get_yyds_jwt():
    return config.get("yyds_jwt", "")


def get_yyds_default_domain():
    return str(config.get("yyds_default_domain", "") or "").strip()


def yyds_get_domains(api_key=None, jwt=None):
    return yyds_provider.get_domains(http_get, api_key=api_key or get_yyds_api_key(), jwt=jwt or get_yyds_jwt())


def yyds_create_account(local_part=None, domain=None, api_key=None, jwt=None):
    return yyds_provider.create_account(
        http_post,
        local_part=local_part or "",
        domain=domain or "",
        api_key=api_key or get_yyds_api_key(),
        jwt=jwt or get_yyds_jwt(),
    )


def yyds_get_token(address, api_key=None, jwt=None):
    return yyds_provider.get_token(http_post, address, api_key=api_key or get_yyds_api_key(), jwt=jwt or get_yyds_jwt())


def yyds_get_messages(address, token=None, api_key=None, jwt=None):
    return yyds_provider.get_messages(
        http_get,
        address,
        token=token or "",
        api_key=api_key or get_yyds_api_key(),
        jwt=jwt or get_yyds_jwt(),
    )


def yyds_get_message_detail(message_id, token=None, api_key=None, jwt=None):
    return yyds_provider.get_message_detail(
        http_get,
        message_id,
        token=token or "",
        api_key=api_key or get_yyds_api_key(),
        jwt=jwt or get_yyds_jwt(),
    )


def yyds_generate_username(length=10):
    return yyds_provider.generate_username(length)


def yyds_pick_domain(api_key=None, jwt=None):
    return yyds_provider.pick_domain(http_get, api_key=api_key or get_yyds_api_key(), jwt=jwt or get_yyds_jwt())


def yyds_get_email_and_token(api_key=None, jwt=None):
    key = api_key or get_yyds_api_key()
    token = jwt or get_yyds_jwt()
    if not token and not key:
        raise Exception("YYDS API Key 或 JWT 未配置")
    domain = get_yyds_default_domain() or yyds_pick_domain(api_key=key, jwt=token)
    username = yyds_generate_username(10)
    result = yyds_create_account(
        local_part=username, domain=domain, api_key=key, jwt=token
    )
    address = result.get("address") or f"{username}@{domain}"
    temp_token = result.get("token")
    if not temp_token:
        temp_token = yyds_get_token(address, api_key=key, jwt=token)
    if not temp_token:
        raise Exception("获取 YYDS token 失败")
    print(f"[*] 已创建 YYDS 邮箱: {address}")
    return address, temp_token


def yyds_get_oai_code(token, address, timeout=180, poll_interval=3, log_callback=None, jwt=None, cancel_callback=None):
    return yyds_provider.wait_for_code(
        http_get,
        token,
        address,
        timeout=timeout,
        poll_interval=poll_interval,
        jwt=jwt or get_yyds_jwt(),
        raise_if_cancelled=raise_if_cancelled,
        sleep_with_cancel=sleep_with_cancel,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
    )



def generate_username(length=10):
    return _generate_username(length)


def pick_domain(api_key=None):
    return duckmail_provider.pick_domain(get_domains(api_key=api_key))


def get_cloudmail_url():
    return str(os.environ.get("CLOUDMAIL_URL") or config.get("cloudmail_url", "") or "").strip().rstrip("/")


def get_cloudmail_admin_email():
    return str(os.environ.get("CLOUDMAIL_ADMIN_EMAIL") or config.get("cloudmail_admin_email", "") or "").strip()


def get_cloudmail_password():
    return str(os.environ.get("CLOUDMAIL_PASSWORD") or config.get("cloudmail_password", "") or "")


def cloudmail_get_email_and_token():
    raw_domains = str(config.get("defaultDomains", "") or "")
    domains = [item.strip() for item in re.split(r"[,，\s]+", raw_domains) if item.strip()]
    return cloudmail_provider.create_mailbox(
        http_post,
        get_cloudmail_url(),
        get_cloudmail_admin_email(),
        get_cloudmail_password(),
        domains,
        username=generate_username(10),
    )


def cloudmail_get_oai_code(
    dev_token,
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
    resend_callback=None,
):
    del dev_token
    return cloudmail_provider.wait_for_code(
        http_post,
        http_delete,
        get_cloudmail_url(),
        get_cloudmail_admin_email(),
        get_cloudmail_password(),
        email,
        timeout=timeout,
        poll_interval=poll_interval,
        raise_if_cancelled=raise_if_cancelled,
        sleep_with_cancel=sleep_with_cancel,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
        resend_callback=resend_callback,
    )


def get_email_provider():
    return config.get("email_provider", "cloudflare")


def get_email_and_token(api_key=None):
    provider = get_email_provider()
    if provider == "yyds":
        return yyds_get_email_and_token(api_key=api_key, jwt=get_yyds_jwt())
    if provider == "cloudmail":
        return cloudmail_get_email_and_token()
    if provider == "cloudflare":
        api_base = get_cloudflare_api_base()
        if not api_base:
            raise Exception("Cloudflare API Base 未配置")
        try:
            # cloudflare_temp_email 专用模式
            return cloudflare_create_temp_address(api_base)
        except Exception as primary_exc:
            try:
                return cloudflare_provider.create_mailbox_fallback(
                    http_get,
                    http_post,
                    api_base,
                    domains_path=get_cloudflare_path("cloudflare_path_domains", "/domains"),
                    accounts_path=get_cloudflare_path("cloudflare_path_accounts", "/accounts"),
                    token_path=get_cloudflare_path("cloudflare_path_token", "/token"),
                    api_key=api_key or get_cloudflare_api_key(),
                    auth_mode=get_cloudflare_auth_mode(),
                    custom_auth=get_cloudflare_custom_auth(),
                )
            except Exception:
                raise Exception(f"Cloudflare 创建邮箱失败: {primary_exc}")
    if provider == "mailnest":
        return mailnest_buy_email(), "_"
    return duckmail_provider.create_mailbox(
        http_get,
        http_post,
        get_duckmail_api_base(),
        api_key=api_key or get_duckmail_api_key(),
        expires_in=0,
    )


def get_oai_code(
    dev_token,
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
    resend_callback=None,
):
    provider = get_email_provider()
    if provider == "yyds":
        return yyds_get_oai_code(
            dev_token,
            email,
            timeout=timeout,
            poll_interval=poll_interval,
            log_callback=log_callback,
            jwt=get_yyds_jwt(),
            cancel_callback=cancel_callback,
        )
    if provider == "cloudmail":
        return cloudmail_get_oai_code(
            dev_token,
            email,
            timeout=timeout,
            poll_interval=poll_interval,
            log_callback=log_callback,
            cancel_callback=cancel_callback,
            resend_callback=resend_callback,
        )
    if provider == "cloudflare":
        return cloudflare_get_oai_code(
            dev_token,
            email,
            timeout=timeout,
            poll_interval=poll_interval,
            log_callback=log_callback,
            cancel_callback=cancel_callback,
            resend_callback=resend_callback,
        )
    if provider == "mailnest":
        return mailnest_get_code(
            email,
            timeout=timeout,
            poll_interval=poll_interval,
            log_callback=log_callback,
            cancel_callback=cancel_callback,
        )
    return duckmail_get_oai_code(
        dev_token,
        email,
        timeout=timeout,
        poll_interval=poll_interval,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
    )



def extract_verification_code(text, subject=""):
    return _extract_code(text, subject)


def duckmail_get_oai_code(
    dev_token,
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
):
    return duckmail_provider.wait_for_code(
        http_get,
        get_duckmail_api_base(),
        dev_token,
        email,
        timeout=timeout,
        poll_interval=poll_interval,
        extract_code=extract_verification_code,
        raise_if_cancelled=raise_if_cancelled,
        sleep_with_cancel=sleep_with_cancel,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
    )


def cloudflare_get_oai_code(
    dev_token,
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
    resend_callback=None,
):
    return cloudflare_provider.wait_for_code(
        http_get,
        get_cloudflare_api_base(),
        dev_token,
        email,
        messages_path=get_cloudflare_path("cloudflare_path_messages", "/messages"),
        api_key=get_cloudflare_api_key(),
        auth_mode=get_cloudflare_auth_mode(),
        custom_auth=get_cloudflare_custom_auth(),
        timeout=timeout,
        poll_interval=poll_interval,
        raise_if_cancelled=raise_if_cancelled,
        sleep_with_cancel=sleep_with_cancel,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
        resend_callback=resend_callback,
    )


def generate_random_birthdate():
    import datetime as dt

    today = dt.date.today()
    age = random.randint(20, 40)
    birth_year = today.year - age
    birth_month = random.randint(1, 12)
    birth_day = random.randint(1, 28)
    return f"{birth_year}-{birth_month:02d}-{birth_day:02d}T16:00:00.000Z"


def response_preview(res, limit=200):
    """安全预览 HTTP 响应体；gRPC/二进制内容不直接当文本打印。"""
    try:
        headers = {str(k).lower(): str(v).lower() for k, v in dict(getattr(res, "headers", {}) or {}).items()}
        content_type = headers.get("content-type", "")
        raw = getattr(res, "content", None)
        if raw is None:
            try:
                raw = (res.text or "").encode("utf-8", errors="replace")
            except Exception:
                raw = b""
        if not isinstance(raw, (bytes, bytearray)):
            raw = str(raw).encode("utf-8", errors="replace")
        raw = bytes(raw)

        # gRPC / protobuf 常见 content-type 或正文以不可打印字节为主
        is_binaryish = (
            "grpc" in content_type
            or "protobuf" in content_type
            or "octet-stream" in content_type
            or (raw[:1] in (b"\x00", b"\x01") and b"grpc-status" in raw)
        )
        if is_binaryish or (raw and sum(1 for b in raw[:64] if b < 9 or (13 < b < 32)) > 8):
            # 尽量抽出可读的 trailer 片段（如 grpc-status:0）
            readable = re.findall(rb"[ -~]{3,}", raw)
            text = " ".join(part.decode("ascii", errors="ignore") for part in readable)
            text = re.sub(r"\s+", " ", text).strip()
            if not text:
                text = f"<binary {len(raw)} bytes>"
            return text[:limit]

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
        text = re.sub(r"\s+", " ", text).strip()
        return text[:limit]
    except Exception:
        return ""


def is_cloudflare_block_response(res):
    try:
        headers = {str(k).lower(): str(v).lower() for k, v in dict(res.headers).items()}
        text = str(res.text or "").lower()
        server = headers.get("server", "")
        content_type = headers.get("content-type", "")
        return (
            res.status_code in (403, 429, 503)
            and (
                "cloudflare" in server
                or "cloudflare" in text
                or "cf-error" in text
                or "__cf_chl" in text
                or "text/html" in content_type
            )
        )
    except Exception:
        return False


def set_birth_date(session, log_callback=None, timeout=15):
    url = "https://grok.com/rest/auth/set-birth-date"
    new_headers = {
        "content-type": "application/json",
        "origin": "https://grok.com",
        "referer": "https://grok.com/",
    }
    payload = {"birthDate": generate_random_birthdate()}
    try:
        res = session.post(url, json=payload, headers=new_headers, timeout=timeout)
        body_preview = response_preview(res)
        if log_callback:
            log_callback(
                f"[Debug] set_birth_date status: {res.status_code}, body: {body_preview}"
            )
        if 200 <= res.status_code < 300:
            return True, "ok"
        # 生日一旦写过就不能改；算已完成，不能当失败中断后续 NSFW
        text = str(res.text or "")
        if res.status_code in (400, 409, 429) and (
            "birth-date-change-limit-reached" in text
            or "Birth date is locked" in text
            or "already set" in text.lower()
        ):
            return True, "already_set"
        if is_cloudflare_block_response(res):
            return (
                False,
                "set_birth_date 被 grok.com 的 Cloudflare 防护拦截，HTTP "
                f"{res.status_code}",
            )
        return False, f"set_birth_date HTTP {res.status_code}: {body_preview}"
    except Exception as e:
        if log_callback:
            log_callback(f"[set_birth_date] 异常: {e}")
        return False, f"set_birth_date 异常: {e}"


def set_tos_accepted(session, log_callback=None, timeout=15):
    url = "https://accounts.x.ai/auth_mgmt.AuthManagement/SetTosAcceptedVersion"
    payload = struct.pack("B", (2 << 3) | 0) + struct.pack("B", 1)
    data = b"\x00" + struct.pack(">I", len(payload)) + payload
    new_headers = {
        "content-type": "application/grpc-web+proto",
        "x-grpc-web": "1",
        "x-user-agent": "connect-es/2.1.1",
        "origin": "https://accounts.x.ai",
        "referer": "https://accounts.x.ai/accept-tos",
    }
    try:
        res = session.post(url, data=data, headers=new_headers, timeout=timeout)
        if log_callback:
            log_callback(f"[Debug] set_tos_accepted status: {res.status_code}")
        if 200 <= res.status_code < 300:
            return True, "ok"
        if is_cloudflare_block_response(res):
            return (
                False,
                "set_tos_accepted 被 accounts.x.ai 的 Cloudflare 防护拦截，HTTP "
                f"{res.status_code}",
            )
        return False, f"set_tos_accepted HTTP {res.status_code}: {response_preview(res)}"
    except Exception as e:
        if log_callback:
            log_callback(f"[set_tos_accepted] 异常: {e}")
        return False, f"set_tos_accepted 异常: {e}"


def encode_grpc_nsfw_settings():
    field1_content = bytes([0x10, 0x01])
    field1 = bytes([0x0A, len(field1_content)]) + field1_content
    nsfw_string = b"always_show_nsfw_content"
    field2_inner = bytes([0x0A, len(nsfw_string)]) + nsfw_string
    field2 = bytes([0x12, len(field2_inner)]) + field2_inner
    payload = field1 + field2
    return b"\x00" + struct.pack(">I", len(payload)) + payload


def update_nsfw_settings(session, log_callback=None, timeout=15):
    url = "https://grok.com/auth_mgmt.AuthManagement/UpdateUserFeatureControls"
    data = encode_grpc_nsfw_settings()
    new_headers = {
        "content-type": "application/grpc-web+proto",
        "x-grpc-web": "1",
        "origin": "https://grok.com",
        "referer": "https://grok.com/",
    }
    try:
        res = session.post(url, data=data, headers=new_headers, timeout=timeout)
        if log_callback:
            log_callback(
                f"[Debug] update_nsfw status: {res.status_code}, body: {response_preview(res)}"
            )
        if 200 <= res.status_code < 300:
            return True, "ok"
        if is_cloudflare_block_response(res):
            return (
                False,
                "update_nsfw_settings 被 grok.com 的 Cloudflare 防护拦截，HTTP "
                f"{res.status_code}",
            )
        return False, f"update_nsfw_settings HTTP {res.status_code}: {response_preview(res)}"
    except Exception as e:
        if log_callback:
            log_callback(f"[update_nsfw] 异常: {e}")
        return False, f"update_nsfw_settings 异常: {e}"


def enable_nsfw_via_browser(
    token="",
    log_callback=None,
    cancel_callback=None,
    navigate=True,
):
    """在已登录的注册浏览器内调用 grok.com 接口，绕过外部 HTTP 的 CF 拦截。

    协议注册模式通常无暖页；冷启易卡 CF，默认 worker 不再走此路径。
    """
    page_obj = _active_page()
    if page_obj is None:
        return False, "浏览器页面未就绪"

    birth = generate_random_birthdate()
    nsfw_bytes = encode_grpc_nsfw_settings()
    nsfw_b64 = base64.b64encode(nsfw_bytes).decode("ascii")

    def _cancelled():
        return bool(cancel_callback and cancel_callback())

    try:
        if _cancelled():
            return False, "用户已停止"
        current_url = str(getattr(page_obj, "url", "") or "").lower()
        should_navigate = bool(navigate or not current_url.startswith("https://grok.com"))
        if log_callback:
            if should_navigate:
                log_callback("[*] 浏览器内开启 NSFW：打开 grok.com ...")
            else:
                log_callback("[*] 浏览器内开启 NSFW：复用 grok.com 会话 ...")
        # 确保 SSO cookie 在浏览器上下文中
        if token:
            try:
                page_obj.set.cookies(
                    [
                        {"name": "sso", "value": token, "domain": ".x.ai", "path": "/"},
                        {"name": "sso-rw", "value": token, "domain": ".x.ai", "path": "/"},
                        {"name": "sso", "value": token, "domain": ".grok.com", "path": "/"},
                        {"name": "sso-rw", "value": token, "domain": ".grok.com", "path": "/"},
                    ]
                )
            except Exception:
                try:
                    page_obj.run_js(
                        """
const token = arguments[0];
document.cookie = 'sso=' + token + '; path=/; domain=.grok.com';
document.cookie = 'sso-rw=' + token + '; path=/; domain=.grok.com';
                        """,
                        token,
                    )
                except Exception:
                    pass
        if _cancelled():
            return False, "用户已停止"
        if should_navigate:
            page_obj.get("https://grok.com/")
            try:
                page_obj.wait.doc_loaded()
            except Exception:
                pass
            # 等 CF 挑战结束（短等，不强制 cf_clearance cookie）
            for _ in range(15):
                if _cancelled():
                    return False, "用户已停止"
                try:
                    title = str(page_obj.run_js("return document.title || '';") or "").lower()
                    body = str(
                        page_obj.run_js(
                            "return (document.body && (document.body.innerText||'')) || '';"
                        )
                        or ""
                    ).lower()
                    if "just a moment" not in title and "just a moment" not in body[:200]:
                        if "checking your browser" not in body[:300]:
                            break
                except Exception:
                    pass
                time.sleep(1.0)
            else:
                if log_callback:
                    log_callback("[!] grok.com 仍停在 Cloudflare 挑战页，浏览器内 NSFW 可能失败")
            time.sleep(0.5)

        if _cancelled():
            return False, "用户已停止"

        result = page_obj.run_js(
            r"""
const birthDate = arguments[0];
const nsfwB64 = arguments[1];
function b64ToBytes(b64) {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}
async function fetchWithTimeout(url, options, timeoutMs = 6000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}
return (async () => {
  const out = { birthStatus: 0, birthBody: '', nsfwStatus: 0, nsfwBody: '', url: location.href };
  try {
    const birthRes = await fetchWithTimeout('https://grok.com/rest/auth/set-birth-date', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'content-type': 'application/json',
        'origin': 'https://grok.com',
        'referer': 'https://grok.com/',
      },
      body: JSON.stringify({ birthDate }),
    });
    out.birthStatus = birthRes.status;
    out.birthBody = (await birthRes.text()).slice(0, 240);
  } catch (e) {
    out.birthBody = String(e);
  }
  const birthOk = (out.birthStatus >= 200 && out.birthStatus < 300)
    || /birth-date-change-limit-reached|Birth date is locked|already set/i.test(out.birthBody || '');
  if (!birthOk) {
    return out;
  }
  try {
    const body = b64ToBytes(nsfwB64);
    const nsfwRes = await fetchWithTimeout('https://grok.com/auth_mgmt.AuthManagement/UpdateUserFeatureControls', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'content-type': 'application/grpc-web+proto',
        'x-grpc-web': '1',
        'origin': 'https://grok.com',
        'referer': 'https://grok.com/',
      },
      body,
    });
    out.nsfwStatus = nsfwRes.status;
    out.nsfwBody = (await nsfwRes.text()).slice(0, 240);
  } catch (e) {
    out.nsfwBody = String(e);
  }
  return out;
})();
            """,
            birth,
            nsfw_b64,
        )
        if not isinstance(result, dict):
            return False, f"浏览器 NSFW 返回异常: {result!r}"

        if log_callback:
            log_callback(
                f"[Debug] browser NSFW birth={result.get('birthStatus')} "
                f"nsfw={result.get('nsfwStatus')} body={str(result.get('birthBody') or '')[:120]}"
            )

        birth_status = int(result.get("birthStatus") or 0)
        birth_body = str(result.get("birthBody") or "")
        birth_ok = (200 <= birth_status < 300) or (
            birth_status in (400, 409, 429)
            and (
                "birth-date-change-limit-reached" in birth_body
                or "Birth date is locked" in birth_body
                or "already set" in birth_body.lower()
            )
        )
        if not birth_ok:
            if "just a moment" in birth_body.lower() or birth_status == 403:
                return False, f"浏览器内 set_birth_date 仍被 CF 拦截 HTTP {birth_status}"
            return False, f"浏览器内 set_birth_date HTTP {birth_status}: {birth_body[:160]}"

        nsfw_status = int(result.get("nsfwStatus") or 0)
        nsfw_body = str(result.get("nsfwBody") or "")
        if 200 <= nsfw_status < 300:
            return True, "成功开启 NSFW（浏览器内）"
        if "just a moment" in nsfw_body.lower() or nsfw_status == 403:
            return False, f"浏览器内 update_nsfw 被 CF 拦截 HTTP {nsfw_status}"
        return False, f"浏览器内 update_nsfw HTTP {nsfw_status}: {nsfw_body[:160]}"
    except Exception as exc:
        if log_callback:
            log_callback(f"[Debug] 浏览器内 NSFW 异常: {exc}")
        return False, f"浏览器内 NSFW 异常: {exc}"


def enable_nsfw_for_token(
    token,
    cf_clearance="",
    user_agent="",
    log_callback=None,
    cancel_callback=None,
    allow_browser_fallback=True,
    http_budget=None,
    tos_only=False,
):
    proxies = get_proxies()
    ua = user_agent or get_user_agent()
    if log_callback:
        log_callback(
            f"[Debug] NSFW 准备: cf_clearance={'有' if cf_clearance else '无'} | ua_len={len(ua)} | browser={'有' if _active_page() else '无'}"
        )

    def _cancelled():
        return bool(cancel_callback and cancel_callback())

    def _browser_fallback(reason):
        if _cancelled():
            return False, "用户已停止"
        if not allow_browser_fallback:
            return False, reason
        if _active_page() is None:
            return False, reason
        if log_callback:
            log_callback(f"[*] NSFW HTTP 快速路径未成功: {reason}，回退浏览器过盾...")
        ok, message = enable_nsfw_via_browser(
            token=token,
            log_callback=log_callback,
            cancel_callback=cancel_callback,
        )
        if ok:
            return True, message
        return False, f"{reason}; browser fallback: {message}"

    try:
        if _cancelled():
            return False, "用户已停止"
        deadline = None
        if http_budget is not None:
            deadline = time.monotonic() + max(float(http_budget), 0.1)

        def _request_timeout():
            if deadline is None:
                return 15.0
            remaining = deadline - time.monotonic()
            return min(15.0, remaining) if remaining > 0 else 0.0

        if log_callback:
            log_callback("[*] NSFW 先尝试 HTTP 快速路径...")
        with requests.Session(impersonate="chrome120", proxies=proxies) as session:
            cookie_parts = [f"sso={token}", f"sso-rw={token}"]
            if cf_clearance:
                cookie_parts.append(f"cf_clearance={cf_clearance}")
            session.headers.update(
                {
                    "user-agent": ua,
                    "cookie": "; ".join(cookie_parts),
                    "accept": "application/json, text/plain, */*",
                    "accept-language": "en-US,en;q=0.9",
                }
            )
            timeout = _request_timeout()
            if timeout <= 0:
                return _browser_fallback("NSFW HTTP 快速路径超时")
            ok, message = set_tos_accepted(session, log_callback, timeout=timeout)
            if not ok:
                return _browser_fallback(message)
            if tos_only:
                return True, "TOS 已确认"
            if _cancelled():
                return False, "用户已停止"
            timeout = _request_timeout()
            if timeout <= 0:
                return _browser_fallback("NSFW HTTP 快速路径超时")
            ok, message = set_birth_date(session, log_callback, timeout=timeout)
            if not ok:
                return _browser_fallback(message)
            if _cancelled():
                return False, "用户已停止"
            timeout = _request_timeout()
            if timeout <= 0:
                return _browser_fallback("NSFW HTTP 快速路径超时")
            ok, message = update_nsfw_settings(session, log_callback, timeout=timeout)
            if not ok:
                return _browser_fallback(message)
            return True, "成功开启 NSFW（HTTP 快速路径）"
    except Exception as e:
        return _browser_fallback(f"HTTP 快速路径异常: {e}")


def enable_nsfw_with_reused_browser(
    sso,
    *,
    log_callback=print,
    should_stop=None,
    attempts=2,
    retry_delay=8.0,
):
    """在后台复用一个浏览器补开；CF 拦截时保留会话后重试。

    仅供 cmd/retry_pending_nsfw 等离线补开；注册批内默认不走浏览器。
    """

    def stopped():
        return bool(should_stop and should_stop())

    if stopped():
        return False, "用户已停止"
    if _active_page() is None:
        start_browser(log_callback=log_callback, cancel_callback=stopped)
    if stopped():
        return False, "用户已停止"
    last_result = (False, "浏览器补开未执行")
    attempt_count = max(int(attempts or 1), 1)
    for attempt in range(1, attempt_count + 1):
        if stopped():
            return False, "用户已停止"
        page_obj = _active_page()
        current_url = str(getattr(page_obj, "url", "") or "").lower()
        navigate = attempt > 1 or not current_url.startswith("https://grok.com")
        last_result = enable_nsfw_via_browser(
            token=sso,
            log_callback=log_callback,
            cancel_callback=stopped,
            navigate=navigate,
        )
        if last_result[0]:
            return last_result
        message = str(last_result[1] or "")
        cf_blocked = "cf" in message.lower() or "403" in message
        if not cf_blocked or attempt >= attempt_count:
            return last_result
        if log_callback:
            log_callback(
                f"[NSFW] 浏览器仍被 CF 拦截，保留会话后重试 ({attempt}/{attempt_count})"
            )
        deadline = time.monotonic() + max(float(retry_delay), 0)
        while time.monotonic() < deadline:
            if stopped():
                return False, "用户已停止"
            time.sleep(min(0.5, max(deadline - time.monotonic(), 0)))
        if stopped():
            return False, "用户已停止"
    return last_result


def create_nsfw_retry_worker(
    log_callback=print,
    idle_timeout=90.0,
    cancel_callback=None,
    allow_browser=False,
):
    """创建 NSFW 补开 worker（对齐初版：纯 HTTP，不挡注册、不抢 Turnstile 代理）。

    allow_browser=True 时才冷启浏览器（离线 pending 补开可用）。
    """

    def nsfw_log(message):
        if log_callback:
            log_callback(str(message))

    def retry(email, sso, worker_should_stop):
        def should_stop():
            return bool(
                worker_should_stop()
                or (cancel_callback and cancel_callback())
            )

        # 初版路径：sso cookie + HTTP set_tos → set_birth → update_nsfw
        ok, message = enable_nsfw_for_token(
            sso,
            log_callback=nsfw_log,
            cancel_callback=should_stop,
            allow_browser_fallback=False,
            http_budget=12,
            tos_only=False,
        )
        if should_stop() or ok or not allow_browser:
            return ok, message

        nsfw_log(f"[NSFW] HTTP 未成功，转浏览器: {message}")
        return enable_nsfw_with_reused_browser(
            sso,
            log_callback=nsfw_log,
            should_stop=should_stop,
        )

    return NsfwRetryWorker(
        NSFW_PENDING_FILE,
        retry,
        cleanup_callback=stop_browser if allow_browser else None,
        log=nsfw_log,
        idle_timeout=idle_timeout,
    )


# browser session state -> browser_session

def setup_light_theme(root):
    try:
        root.option_add("*Background", UI_BG)
        root.option_add("*Foreground", UI_FG)
        root.option_add("*selectBackground", UI_ACTIVE_BG)
        root.option_add("*selectForeground", UI_FG)
        root.option_add("*insertBackground", UI_FG)
        root.option_add("*Entry.Background", UI_ENTRY_BG)
        root.option_add("*Text.Background", UI_ENTRY_BG)
        root.option_add("*Menu.Background", UI_ENTRY_BG)
        root.option_add("*Menu.Foreground", UI_FG)
        style = ttk.Style(root)
        available = set(style.theme_names())
        if "clam" in available:
            style.theme_use("clam")
        elif "default" in available:
            style.theme_use("default")
        root.configure(bg=UI_BG)
        style.configure(".", background=UI_BG, foreground=UI_FG, fieldbackground=UI_ENTRY_BG)
        style.configure("TFrame", background=UI_BG)
        style.configure("TLabelframe", background=UI_BG, foreground=UI_FG)
        style.configure("TLabelframe.Label", background=UI_BG, foreground=UI_FG)
        style.configure("TLabel", background=UI_BG, foreground=UI_FG)
        style.configure("TCheckbutton", background=UI_BG, foreground=UI_FG)
        style.configure("TButton", background=UI_BUTTON_BG, foreground=UI_FG)
        style.configure("TEntry", fieldbackground=UI_ENTRY_BG, foreground=UI_FG)
        style.configure("TCombobox", fieldbackground=UI_ENTRY_BG, foreground=UI_FG)
        style.configure("TSpinbox", fieldbackground=UI_ENTRY_BG, foreground=UI_FG)
    except Exception:
        pass


def tk_label(parent, text="", **kwargs):
    return tk.Label(parent, text=text, bg=kwargs.pop("bg", UI_BG), fg=kwargs.pop("fg", UI_FG), **kwargs)


def tk_entry(parent, textvariable=None, width=30, **kwargs):
    return tk.Entry(
        parent,
        textvariable=textvariable,
        width=width,
        bg=UI_ENTRY_BG,
        fg=UI_FG,
        insertbackground=UI_FG,
        disabledbackground="#2f2f2f",
        disabledforeground=UI_MUTED_FG,
        highlightthickness=1,
        highlightbackground="#555555",
        relief=tk.SOLID,
        **kwargs,
    )


def tk_button(parent, text="", command=None, state=tk.NORMAL, **kwargs):
    return tk.Button(
        parent,
        text=text,
        command=command,
        state=state,
        bg=UI_BUTTON_BG,
        fg=UI_FG,
        activebackground=UI_ACTIVE_BG,
        activeforeground=UI_FG,
        disabledforeground="#777777",
        relief=tk.RAISED,
        padx=10,
        pady=3,
        **kwargs,
    )


def tk_checkbutton(parent, text="", variable=None, **kwargs):
    return tk.Checkbutton(
        parent,
        text=text,
        variable=variable,
        bg=UI_BG,
        fg=UI_FG,
        activebackground=UI_BG,
        activeforeground=UI_FG,
        selectcolor="#3d7be0",
        **kwargs,
    )


def tk_option_menu(parent, variable, values, width=12):
    menu = tk.OptionMenu(parent, variable, *values)
    menu.configure(
        width=width,
        bg=UI_ENTRY_BG,
        fg=UI_FG,
        activebackground=UI_ACTIVE_BG,
        activeforeground=UI_FG,
        highlightthickness=1,
        highlightbackground="#555555",
        relief=tk.SOLID,
    )
    menu["menu"].configure(bg=UI_ENTRY_BG, fg=UI_FG, activebackground=UI_ACTIVE_BG, activeforeground=UI_FG)
    return menu

def should_close_browser_after_run(user_stopped: bool) -> bool:
    """正常结束默认关浏览器；用户主动停止时由 close_browser_on_stop 控制。"""
    if user_stopped and not config.get("close_browser_on_stop", False):
        return False
    return True


def maybe_stop_browser(user_stopped: bool = False, log_callback=None):
    if should_close_browser_after_run(user_stopped):
        stop_browser()
        return
    if log_callback and user_stopped:
        log_callback("[*] 用户停止：已保留浏览器（勾选「停止时关闭浏览器」可改为关闭）")


def get_log_level() -> str:
    level = str(config.get("log_level", "info") or "info").strip().lower()
    return level if level in ("info", "debug") else "info"


def should_emit_log(message: str) -> bool:
    """info 级别过滤 [Debug] 行；debug 全开。"""
    if get_log_level() == "debug":
        return True
    text = str(message or "")
    if text.lstrip().startswith("[Debug]") or " [Debug] " in text:
        return False
    return True


def _wire_runtime_modules(gui_mode=False, headless=None):
    """把主模块依赖注入到 browser_session / register_flow。"""
    if headless is None:
        env = str(os.environ.get("GROK_HEADLESS", "") or "").strip().lower()
        if env in ("1", "true", "yes", "on"):
            headless = True
        elif env in ("0", "false", "no", "off"):
            headless = False
        else:
            # 纯 headless 会被 Cloudflare 拦；默认用有界面但后台置底窗口
            headless = False
    keep_bg = (gui_mode or not headless)
    _bs.configure(
        get_proxies=get_proxies,
        extension_path=EXTENSION_PATH,
        keep_windows_background=keep_bg,
        headless=bool(headless),
    )
    _rf.configure(
        get_email_and_token=get_email_and_token,
        get_oai_code=get_oai_code,
        raise_if_cancelled=raise_if_cancelled,
        sleep_with_cancel=sleep_with_cancel,
        RegistrationCancelled=RegistrationCancelled,
        EmailDomainRejected=EmailDomainRejected,
        AccountRetryNeeded=AccountRetryNeeded,
    )

# register page flow -> register_flow

class GrokRegisterGUI:
    def __init__(self, root):
        self.root = root
        self._ui_thread_id = threading.get_ident()
        self.root.title("Grok 注册机")
        self.root.geometry("1120x900")
        self.root.minsize(960, 700)
        self.is_running = False
        self.sso_convert_running = False
        self.sso_convert_stop_requested = False
        self.batch_count = 0
        self.success_count = 0
        self.fail_count = 0
        self.results = []
        self.stop_requested = False
        self.ui_queue = queue.Queue()
        self.accounts_output_file = ""
        self.nsfw_retry_worker = None
        self._closing = False
        self.setup_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(50, self._drain_ui_queue)

    def _queue_ui_call(self, callback, *args):
        if getattr(self, "_closing", False):
            return True
        if threading.get_ident() == self._ui_thread_id:
            return False
        self.ui_queue.put((callback, args))
        return True

    def _drain_ui_queue(self):
        while True:
            try:
                callback, args = self.ui_queue.get_nowait()
            except queue.Empty:
                break
            try:
                callback(*args)
            except (tk.TclError, RuntimeError):
                pass
        try:
            self.root.after(50, self._drain_ui_queue)
        except (tk.TclError, RuntimeError):
            pass

    def setup_ui(self):
        load_config()
        _wire_runtime_modules(gui_mode=True)
        main_frame = tk.Frame(self.root, bg=UI_BG, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(3, weight=1)

        config_frame = tk.LabelFrame(
            main_frame,
            text="配置",
            bg=UI_PANEL_BG,
            fg=UI_FG,
            padx=10,
            pady=10,
            relief=tk.GROOVE,
            borderwidth=1,
        )
        config_frame.grid(row=0, column=0, sticky=tk.EW, pady=(0, 8))
        config_frame.grid_columnconfigure(1, weight=1, minsize=260)
        config_frame.grid_columnconfigure(3, weight=1, minsize=260)

        def add_label(row, column, text):
            tk_label(config_frame, text=text, bg=UI_PANEL_BG).grid(
                row=row,
                column=column,
                sticky=tk.W,
                padx=(0, 6),
                pady=3,
            )

        def add_field(widget, row, column, columnspan=1, sticky=tk.EW):
            widget.grid(
                row=row,
                column=column,
                columnspan=columnspan,
                sticky=sticky,
                padx=(0, 14),
                pady=3,
            )

        # 公共配置
        add_label(0, 0, "邮箱服务商:")
        self.email_provider_var = tk.StringVar(value=config.get("email_provider", "cloudflare"))
        self.email_provider_combo = tk_option_menu(
            config_frame,
            self.email_provider_var,
            ["duckmail", "yyds", "cloudflare", "mailnest", "cloudmail"],
            width=12,
        )
        add_field(self.email_provider_combo, 0, 1, sticky=tk.W)

        add_label(0, 2, "注册数量:")
        self.count_var = tk.StringVar(value=str(config.get("register_count", 1)))
        self.count_spinbox = tk.Spinbox(
            config_frame,
            from_=1,
            to=2500,
            width=8,
            textvariable=self.count_var,
            bg=UI_ENTRY_BG,
            fg=UI_FG,
            insertbackground=UI_FG,
            buttonbackground=UI_BUTTON_BG,
            disabledbackground="#2f2f2f",
            disabledforeground=UI_MUTED_FG,
            relief=tk.SOLID,
        )
        add_field(self.count_spinbox, 0, 3, sticky=tk.W)

        add_label(1, 0, "注册选项:")
        opt_frame = tk.Frame(config_frame, bg=UI_PANEL_BG)
        add_field(opt_frame, 1, 1, sticky=tk.W)
        self.nsfw_var = tk.BooleanVar(value=config.get("enable_nsfw", True))
        self.nsfw_check = tk_checkbutton(opt_frame, text="注册后开启 NSFW（可选）", variable=self.nsfw_var)
        self.nsfw_check.pack(side=tk.LEFT)
        self.log_level_var = tk.StringVar(value=str(config.get("log_level", "info") or "info"))
        tk_label(opt_frame, text="日志:", bg=UI_PANEL_BG).pack(side=tk.LEFT, padx=(12, 2))
        self.log_level_combo = tk_option_menu(opt_frame, self.log_level_var, ["info", "debug"], width=6)
        self.log_level_combo.pack(side=tk.LEFT)

        add_label(1, 2, "代理（可选）:")
        self.proxy_var = tk.StringVar(value=config.get("proxy", ""))
        self.proxy_entry = tk_entry(config_frame, textvariable=self.proxy_var, width=34)
        add_field(self.proxy_entry, 1, 3)

        # 服务商专属配置（按选择显示）
        self.provider_frame = tk.LabelFrame(
            config_frame,
            text="邮箱服务商配置",
            bg=UI_PANEL_BG,
            fg=UI_FG,
            padx=8,
            pady=6,
            relief=tk.GROOVE,
            borderwidth=1,
        )
        self.provider_frame.grid(row=2, column=0, columnspan=4, sticky=tk.EW, pady=(6, 4))
        self.provider_frame.grid_columnconfigure(1, weight=1, minsize=240)
        self.provider_frame.grid_columnconfigure(3, weight=1, minsize=240)

        def p_label(row, column, text):
            w = tk_label(self.provider_frame, text=text, bg=UI_PANEL_BG)
            w.grid(row=row, column=column, sticky=tk.W, padx=(0, 6), pady=3)
            return w

        def p_field(widget, row, column, columnspan=1, sticky=tk.EW):
            widget.grid(
                row=row,
                column=column,
                columnspan=columnspan,
                sticky=sticky,
                padx=(0, 14),
                pady=3,
            )
            return widget

        # DuckMail / Mail.tm
        self.api_key_var = tk.StringVar(value=config.get("duckmail_api_key", ""))
        self.duckmail_api_base_var = tk.StringVar(
            value=str(config.get("duckmail_api_base", "") or DUCKMAIL_API_BASE_DEFAULT)
        )
        self._duckmail_widgets = [
            p_label(0, 0, "API Base（可选）:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.duckmail_api_base_var, width=52), 0, 1, columnspan=3),
            p_label(1, 0, "API Key（可选）:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.api_key_var, width=34), 1, 1),
            p_label(1, 2, "说明:"),
            p_field(
                tk_label(
                    self.provider_frame,
                    text="Mail.tm 填 https://api.mail.tm；公共域可不填 Key",
                    bg=UI_PANEL_BG,
                ),
                1,
                3,
                sticky=tk.W,
            ),
        ]

        # Cloudflare
        self.cloudflare_auth_mode_var = tk.StringVar(value=config.get("cloudflare_auth_mode", "none"))
        self.cloudflare_api_base_var = tk.StringVar(value=config.get("cloudflare_api_base", ""))
        self.cloudflare_api_key_var = tk.StringVar(value=config.get("cloudflare_api_key", ""))
        self.cloudflare_paths_var = tk.StringVar(
            value=",".join(
                [
                    config.get("cloudflare_path_domains", "/api/domains"),
                    config.get("cloudflare_path_accounts", "/api/new_address"),
                    config.get("cloudflare_path_token", "/api/token"),
                    config.get("cloudflare_path_messages", "/api/mails"),
                ]
            )
        )
        self.default_domains_var = tk.StringVar(value=str(config.get("defaultDomains", "")))
        self.cloudflare_custom_auth_var = tk.StringVar(value=str(config.get("cloudflare_custom_auth", "")))
        self.cloudflare_random_subdomain_var = tk.BooleanVar(
            value=bool(config.get("cloudflare_random_subdomain", False))
        )
        self._cloudflare_widgets = [
            p_label(0, 0, "API Base:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.cloudflare_api_base_var, width=52), 0, 1, columnspan=3),
            p_label(1, 0, "鉴权模式（可选）:"),
            p_field(
                tk_option_menu(
                    self.provider_frame,
                    self.cloudflare_auth_mode_var,
                    ["query-key", "bearer", "x-api-key", "x-admin-auth", "none"],
                    width=12,
                ),
                1,
                1,
                sticky=tk.W,
            ),
            p_label(1, 2, "API Key（可选）:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.cloudflare_api_key_var, width=34), 1, 3),
            p_label(2, 0, "收信域名（可选）:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.default_domains_var, width=34), 2, 1),
            p_label(2, 2, "全局密码（可选）:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.cloudflare_custom_auth_var, width=34), 2, 3),
            p_label(3, 0, "CF 路径（可选）:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.cloudflare_paths_var, width=52), 3, 1, columnspan=3),
            p_field(
                tk_checkbutton(
                    self.provider_frame,
                    text="随机三级域名（user@子域.主域，需 Worker 开启 RANDOM_SUBDOMAIN）",
                    variable=self.cloudflare_random_subdomain_var,
                ),
                4,
                0,
                columnspan=4,
                sticky=tk.W,
            ),
        ]

        # YYDS
        self.yyds_api_key_var = tk.StringVar(value=str(config.get("yyds_api_key", "")))
        self.yyds_jwt_var = tk.StringVar(value=str(config.get("yyds_jwt", "")))
        self.yyds_default_domain_var = tk.StringVar(value=str(config.get("yyds_default_domain", "")))
        self._yyds_widgets = [
            p_label(0, 0, "API Key（可选）:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.yyds_api_key_var, width=34), 0, 1),
            p_label(0, 2, "JWT（可选）:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.yyds_jwt_var, width=34), 0, 3),
            p_label(1, 0, "固定收信域名（可选）:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.yyds_default_domain_var, width=34), 1, 1),
            p_label(1, 2, "说明:"),
            p_field(
                tk_label(self.provider_frame, text="Key/JWT 二选一；域名留空则自动选", bg=UI_PANEL_BG),
                1,
                3,
                sticky=tk.W,
            ),
        ]

        # MailNest
        self.mailnest_api_key_var = tk.StringVar(value=str(config.get("mailnest_api_key", "")))
        self.mailnest_project_code_var = tk.StringVar(
            value=str(config.get("mailnest_project_code", MAILNEST_DEFAULT_PROJECT_CODE) or MAILNEST_DEFAULT_PROJECT_CODE)
        )
        self._mailnest_widgets = [
            p_label(0, 0, "API Key:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.mailnest_api_key_var, width=34), 0, 1),
            p_label(0, 2, "项目代码（可选）:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.mailnest_project_code_var, width=34), 0, 3),
        ]

        # CloudMail
        self.cloudmail_url_var = tk.StringVar(value=str(config.get("cloudmail_url", "")))
        self.cloudmail_admin_email_var = tk.StringVar(value=str(config.get("cloudmail_admin_email", "")))
        self.cloudmail_password_var = tk.StringVar(value=str(config.get("cloudmail_password", "")))
        # CloudMail 也用 defaultDomains；与 CF 共用变量即可
        self._cloudmail_widgets = [
            p_label(0, 0, "站点 URL:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.cloudmail_url_var, width=52), 0, 1, columnspan=3),
            p_label(1, 0, "管理员邮箱:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.cloudmail_admin_email_var, width=34), 1, 1),
            p_label(1, 2, "管理员密码:"),
            p_field(
                tk_entry(self.provider_frame, textvariable=self.cloudmail_password_var, width=34, show="*"),
                1,
                3,
            ),
            p_label(2, 0, "收信域名:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.default_domains_var, width=34), 2, 1),
            p_label(2, 2, "说明:"),
            p_field(
                tk_label(self.provider_frame, text="多个域名用逗号分隔", bg=UI_PANEL_BG),
                2,
                3,
                sticky=tk.W,
            ),
        ]

        self._provider_widget_groups = {
            "duckmail": self._duckmail_widgets,
            "cloudflare": self._cloudflare_widgets,
            "yyds": self._yyds_widgets,
            "mailnest": self._mailnest_widgets,
            "cloudmail": self._cloudmail_widgets,
        }

        add_label(3, 0, "并发数（可选）:")
        self.workers_var = tk.StringVar(value=str(config.get("register_workers", 1)))
        self.workers_spinbox = tk.Spinbox(
            config_frame,
            from_=1,
            to=8,
            width=8,
            textvariable=self.workers_var,
            bg=UI_ENTRY_BG,
            fg=UI_FG,
            insertbackground=UI_FG,
            buttonbackground=UI_BUTTON_BG,
            disabledbackground="#2f2f2f",
            disabledforeground=UI_MUTED_FG,
            relief=tk.SOLID,
        )
        add_field(self.workers_spinbox, 3, 1, sticky=tk.W)

        # SSO → CPA auth 可选
        self.cpa_frame = tk.LabelFrame(
            config_frame,
            text="SSO → CPA auth（可选）",
            bg=UI_PANEL_BG,
            fg=UI_FG,
            padx=8,
            pady=6,
            relief=tk.GROOVE,
            borderwidth=1,
        )
        self.cpa_frame.grid(row=4, column=0, columnspan=4, sticky=tk.EW, pady=(6, 2))
        self.cpa_frame.grid_columnconfigure(1, weight=1, minsize=240)
        self.cpa_frame.grid_columnconfigure(3, weight=1, minsize=240)

        self.cpa_auto_add_var = tk.BooleanVar(value=bool(config.get("cpa_auto_add", False)))
        tk_checkbutton(
            self.cpa_frame,
            text="开启后注册成功会将 SSO 转为 CPA auth 并入库（不勾选则只保存 SSO）",
            variable=self.cpa_auto_add_var,
        ).grid(row=0, column=0, columnspan=4, sticky=tk.W, pady=3)

        self._cpa_detail_widgets = []
        def c_label(row, col, text):
            w = tk_label(self.cpa_frame, text=text, bg=UI_PANEL_BG)
            w.grid(row=row, column=col, sticky=tk.W, padx=(0, 6), pady=3)
            self._cpa_detail_widgets.append(w)
            return w

        def c_field(widget, row, col, columnspan=1, sticky=tk.EW):
            widget.grid(row=row, column=col, columnspan=columnspan, sticky=sticky, padx=(0, 14), pady=3)
            self._cpa_detail_widgets.append(widget)
            return widget

        self.cpa_auth_dir_var = tk.StringVar(value=str(config.get("cpa_auth_dir", "")))
        self.cpa_remote_url_var = tk.StringVar(value=str(config.get("cpa_remote_url", "")))
        self.cpa_management_key_var = tk.StringVar(value=str(config.get("cpa_management_key", "")))
        c_label(1, 0, "auth 目录:")
        c_field(tk_entry(self.cpa_frame, textvariable=self.cpa_auth_dir_var, width=52), 1, 1, columnspan=3)
        c_label(2, 0, "远程地址:")
        c_field(tk_entry(self.cpa_frame, textvariable=self.cpa_remote_url_var, width=34), 2, 1)
        c_label(2, 2, "管理密钥:")
        c_field(tk_entry(self.cpa_frame, textvariable=self.cpa_management_key_var, width=28), 2, 3)

        self.email_provider_var.trace_add("write", lambda *_: self._refresh_provider_fields())
        self.cpa_auto_add_var.trace_add("write", lambda *_: self._refresh_cpa_fields())
        self._refresh_provider_fields()
        self._refresh_cpa_fields()

        btn_frame = tk.Frame(main_frame, bg=UI_BG)
        btn_frame.grid(row=1, column=0, sticky=tk.EW, pady=(0, 6))
        self.start_btn = tk_button(btn_frame, text="开始注册", command=self.start_registration)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = tk_button(btn_frame, text="停止", command=self.stop_registration, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        self.close_browser_on_stop_var = tk.BooleanVar(
            value=bool(config.get("close_browser_on_stop", False))
        )
        self.close_browser_on_stop_check = tk_checkbutton(
            btn_frame,
            text="停止时关闭浏览器",
            variable=self.close_browser_on_stop_var,
        )
        self.close_browser_on_stop_check.pack(side=tk.LEFT, padx=(2, 8))
        self.check_btn = tk_button(btn_frame, text="连通性检查", command=self.run_connectivity_check)
        self.check_btn.pack(side=tk.LEFT, padx=5)
        self.sso_convert_btn = tk_button(
            btn_frame,
            text="补转缺失 SSO",
            command=self.start_sso_recovery,
        )
        self.sso_convert_btn.pack(side=tk.LEFT, padx=5)
        self.clear_btn = tk_button(btn_frame, text="清空日志", command=self.clear_log)
        self.clear_btn.pack(side=tk.LEFT, padx=5)

        status_frame = tk.Frame(main_frame, bg=UI_BG)
        status_frame.grid(row=2, column=0, sticky=tk.EW, pady=(0, 6))
        self.status_var = tk.StringVar(value="就绪")
        tk_label(status_frame, text="状态: ").pack(side=tk.LEFT)
        self.status_label = tk.Label(status_frame, textvariable=self.status_var, bg=UI_BG, fg="green")
        self.status_label.pack(side=tk.LEFT)
        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_bar = ttk.Progressbar(
            status_frame, variable=self.progress_var, maximum=100, length=180, mode="determinate"
        )
        self.progress_bar.pack(side=tk.LEFT, padx=(16, 8))
        self.eta_var = tk.StringVar(value="进度 0/0 | ETA --")
        tk.Label(status_frame, textvariable=self.eta_var, bg=UI_BG, fg=UI_MUTED_FG).pack(side=tk.LEFT)
        self.stats_var = tk.StringVar(value="成功: 0 | 失败: 0")
        tk.Label(status_frame, textvariable=self.stats_var, bg=UI_BG, fg=UI_FG).pack(side=tk.RIGHT)
        log_frame = tk.LabelFrame(
            main_frame,
            text="日志",
            bg=UI_PANEL_BG,
            fg=UI_FG,
            padx=5,
            pady=5,
            relief=tk.GROOVE,
            borderwidth=1,
        )
        log_frame.grid(row=3, column=0, sticky=tk.NSEW)
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(0, weight=1)
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=18,
            width=60,
            bg="#111111",
            fg="#f5f5f5",
            insertbackground="#f5f5f5",
            selectbackground="#345a8a",
            selectforeground="#ffffff",
            relief=tk.SOLID,
            borderwidth=1,
            highlightthickness=1,
            highlightbackground="#555555",
        )
        self.log_text.grid(row=0, column=0, sticky=tk.NSEW)
        self.log("[*] GUI 已就绪，配置已加载")
        self.log(f"[*] 当前邮箱服务商: {self.email_provider_var.get()} | 注册数量: {self.count_var.get()}")

    def _refresh_provider_fields(self):
        """按当前邮箱服务商只显示相关配置项。"""
        provider = (self.email_provider_var.get() or "cloudflare").strip().lower()
        titles = {
            "duckmail": "DuckMail / Mail.tm 配置",
            "cloudflare": "Cloudflare 配置",
            "yyds": "YYDS 配置",
            "mailnest": "MailNest 配置",
            "cloudmail": "CloudMail 配置",
        }
        self.provider_frame.configure(text=titles.get(provider, "邮箱服务商配置"))
        for widgets in self._provider_widget_groups.values():
            for widget in widgets:
                widget.grid_remove()
        for widget in self._provider_widget_groups.get(provider, self._cloudflare_widgets):
            # grid_remove 后无参 grid() 会恢复原行列
            widget.grid()

    def _refresh_cpa_fields(self):
        """未开启 SSO→auth 时隐藏 CPA 目录/远程配置。"""
        enabled = bool(self.cpa_auto_add_var.get())
        for widget in getattr(self, "_cpa_detail_widgets", []):
            if enabled:
                widget.grid()
            else:
                widget.grid_remove()

    def log(self, message):
        if not should_emit_log(message):
            return
        if self._queue_ui_call(self.log, message):
            return
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        line = f"[{timestamp}] {message}"
        append_session_log(line)
        print(line, flush=True)
        self.log_text.insert(tk.END, f"{line}\n")
        self.log_text.see(tk.END)

    def clear_log(self):
        self.log_text.delete(1.0, tk.END)

    def update_stats(self):
        if self._queue_ui_call(self.update_stats):
            return
        fail_detail = format_fail_stats(getattr(self, "fail_stats", {}) or {})
        if self.fail_count:
            self.stats_var.set(
                f"成功: {self.success_count} | 失败: {self.fail_count}（{fail_detail}）"
            )
        else:
            self.stats_var.set(f"成功: {self.success_count} | 失败: 0")
        self._update_progress()

    def _update_progress(self):
        total = max(int(getattr(self, "batch_count", 0) or 0), 1)
        done = int(self.success_count) + int(self.fail_count)
        pct = min(100.0, 100.0 * done / total)
        if hasattr(self, "progress_var"):
            self.progress_var.set(pct)
        # ETA
        started = getattr(self, "_batch_started_at", None)
        eta_text = "ETA --"
        if started and done > 0:
            elapsed = max(time.time() - started, 0.1)
            rate = done / elapsed
            remain = max(total - done, 0)
            if rate > 0:
                sec = int(remain / rate)
                if sec < 60:
                    eta_text = f"ETA {sec}s"
                else:
                    eta_text = f"ETA {sec // 60}m{sec % 60:02d}s"
        if hasattr(self, "eta_var"):
            self.eta_var.set(f"进度 {done}/{total} | {eta_text}")

    def run_connectivity_check(self):
        """一键测：代理 / 邮箱 API / CPA。"""
        if self.sso_convert_running:
            self.log("[!] SSO 补转正在运行，请结束后再检查连通性")
            return
        # 先把当前 GUI 关键字段写回内存配置（不强制保存文件）
        try:
            config["email_provider"] = self.email_provider_var.get().strip() or "cloudflare"
            config["proxy"] = self.proxy_var.get().strip()
            config["duckmail_api_key"] = self.api_key_var.get().strip()
            config["duckmail_api_base"] = self.duckmail_api_base_var.get().strip()
            config["cloudflare_api_base"] = self.cloudflare_api_base_var.get().strip()
            config["cloudflare_api_key"] = self.cloudflare_api_key_var.get().strip()
            config["cloudflare_auth_mode"] = self.cloudflare_auth_mode_var.get().strip() or "none"
            config["defaultDomains"] = self.default_domains_var.get().strip()
            config["cloudflare_custom_auth"] = self.cloudflare_custom_auth_var.get().strip()
            config["cloudflare_random_subdomain"] = bool(self.cloudflare_random_subdomain_var.get())
            config["yyds_api_key"] = self.yyds_api_key_var.get().strip()
            config["yyds_jwt"] = self.yyds_jwt_var.get().strip()
            config["mailnest_api_key"] = self.mailnest_api_key_var.get().strip()
            config["cloudmail_url"] = self.cloudmail_url_var.get().strip()
            config["cloudmail_admin_email"] = self.cloudmail_admin_email_var.get().strip()
            config["cloudmail_password"] = self.cloudmail_password_var.get()
            config["cpa_auto_add"] = bool(self.cpa_auto_add_var.get())
            config["cpa_auth_dir"] = self.cpa_auth_dir_var.get().strip()
            config["cpa_remote_url"] = self.cpa_remote_url_var.get().strip()
            config["cpa_management_key"] = self.cpa_management_key_var.get().strip()
        except Exception:
            pass
        self.log("[*] 开始连通性检查...")
        self.check_btn.config(state=tk.DISABLED)

        def _job():
            try:
                results = _conn.run_connectivity_checks(config, http_get, http_post)
                text = _conn.format_check_results(results)
                all_ok = all(ok for _, ok, _ in results)
                self.ui_queue.put((self._on_check_done, (text, all_ok)))
            except Exception as exc:
                self.ui_queue.put((self._on_check_done, (f"检查异常: {exc}", False)))

        threading.Thread(target=_job, daemon=True).start()

    def _on_check_done(self, text, all_ok):
        self.check_btn.config(state=tk.DISABLED if self.sso_convert_running else tk.NORMAL)
        for line in str(text).splitlines():
            self.log(f"[检查] {line}")
        self.status_var.set("检查通过" if all_ok else "检查有失败项")
        self.status_label.config(foreground="green" if all_ok else "orange")

    def start_sso_recovery(self):
        if self.is_running:
            self.log("[!] 注册任务正在运行，请结束后再补转 SSO")
            return
        if self.sso_convert_running:
            self.log("[!] SSO 补转已经在运行")
            return

        config["proxy"] = self.proxy_var.get().strip()
        config["cpa_auth_dir"] = self.cpa_auth_dir_var.get().strip()
        config["cpa_remote_url"] = self.cpa_remote_url_var.get().strip()
        config["cpa_management_key"] = self.cpa_management_key_var.get().strip()
        if not config["cpa_auth_dir"] and not config["cpa_remote_url"]:
            self.log("[!] 请先配置 CPA auth 目录或远程地址")
            return
        if config["cpa_remote_url"] and not config["cpa_management_key"]:
            self.log("[!] 已配置 CPA 远程地址，但缺少管理密钥")
            return
        save_config()

        self.sso_convert_running = True
        self.sso_convert_stop_requested = False
        self.start_btn.config(state=tk.DISABLED)
        self.sso_convert_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.check_btn.config(state=tk.DISABLED)
        self.status_var.set("SSO 补转中...")
        self.status_label.config(foreground="blue")
        self.log("[*] 开始扫描 accounts_*.txt 和 sso_pending.txt，补转缺失 SSO...")

        def _job():
            result = None
            error = ""
            try:
                entries, files = _s2cpa.scan_sso_entries(APP_DIR)
                self.log(
                    f"[补转] 扫描到 {len(files)} 个 TXT，"
                    f"去重后 {len(entries)} 个 SSO"
                )
                if not entries:
                    result = {"total": 0, "ok": 0, "skipped": 0, "fail": 0, "stopped": False}
                    self.log("[补转] [!] 未找到可转换的 SSO")
                else:
                    try:
                        workers = int(self.workers_var.get() or 1)
                    except Exception:
                        workers = int(config.get("register_workers", 1) or 1)
                    workers = max(1, min(workers, 8))
                    self.log(f"[补转] 并发分片 workers={workers}")
                    result = _s2cpa.convert_sso_entries(
                        entries,
                        cpa_auth_dir=config["cpa_auth_dir"] or None,
                        cpa_remote_url=config["cpa_remote_url"] or None,
                        cpa_management_key=config["cpa_management_key"] or None,
                        proxy=config["proxy"],
                        workers=workers,
                        log=lambda message: self.log(f"[补转] {str(message).strip()}"),
                        should_stop=lambda: self.sso_convert_stop_requested,
                    )
            except Exception as exc:
                error = str(exc)
            self.ui_queue.put((self._on_sso_recovery_done, (result, error)))

        threading.Thread(target=_job, daemon=True).start()

    def _on_sso_recovery_done(self, result, error):
        self.sso_convert_running = False
        self.sso_convert_stop_requested = False
        self.start_btn.config(state=tk.DISABLED if self.is_running else tk.NORMAL)
        self.sso_convert_btn.config(state=tk.DISABLED if self.is_running else tk.NORMAL)
        self.stop_btn.config(state=tk.NORMAL if self.is_running else tk.DISABLED)
        self.check_btn.config(state=tk.NORMAL)
        if error:
            self.log(f"[补转] [-] 任务异常: {error}")
            self.status_var.set("SSO 补转失败")
            self.status_label.config(foreground="red")
            return

        result = result or {}
        if result.get("stopped"):
            self.status_var.set("SSO 补转已停止")
            self.status_label.config(foreground="orange")
        elif result.get("fail"):
            self.status_var.set("SSO 补转有失败项")
            self.status_label.config(foreground="orange")
        else:
            self.status_var.set("SSO 补转完成")
            self.status_label.config(foreground="green")

    def _record_failure(self, exc):
        kind = classify_failure(exc)
        lock = getattr(self, "_stats_lock", None)
        if lock:
            with lock:
                self.fail_count += 1
                if not hasattr(self, "fail_stats") or self.fail_stats is None:
                    self.fail_stats = empty_fail_stats()
                self.fail_stats[kind] = self.fail_stats.get(kind, 0) + 1
        else:
            self.fail_count += 1
            if not hasattr(self, "fail_stats") or self.fail_stats is None:
                self.fail_stats = empty_fail_stats()
            self.fail_stats[kind] = self.fail_stats.get(kind, 0) + 1
        return kind

    def _record_success(self):
        lock = getattr(self, "_stats_lock", None)
        if lock:
            with lock:
                self.success_count += 1
        else:
            self.success_count += 1

    def _set_running_ui(self, running):
        if self._queue_ui_call(self._set_running_ui, running):
            return
        self.is_running = running
        busy = running or self.sso_convert_running
        self.start_btn.config(state=tk.DISABLED if busy else tk.NORMAL)
        self.sso_convert_btn.config(state=tk.DISABLED if busy else tk.NORMAL)
        self.stop_btn.config(state=tk.NORMAL if busy else tk.DISABLED)
        self.status_var.set("运行中..." if running else "就绪")
        self.status_label.config(foreground="blue" if running else "green")

    def should_stop(self):
        return self.stop_requested or not self.is_running

    def _get_nsfw_retry_worker(self):
        worker = getattr(self, "nsfw_retry_worker", None)
        if worker is None:
            worker = create_nsfw_retry_worker(
                log_callback=self.log,
                cancel_callback=self.should_stop,
            )
            self.nsfw_retry_worker = worker
        return worker

    def _submit_nsfw(self, email, sso, log_callback=None):
        log_callback = log_callback or self.log
        try:
            queued = self._get_nsfw_retry_worker().submit(email, sso)
        except Exception as exc:
            log_callback(f"[NSFW] [!] 加入本批队列失败，账号仍继续入库: {exc}")
            return False
        if queued:
            log_callback("[*] 6. NSFW 已进入本批后台队列")
        else:
            log_callback("[NSFW] [!] 未加入本批队列，已保留 pending")
        return queued

    def _finish_nsfw_batch(self):
        worker = getattr(self, "nsfw_retry_worker", None)
        if worker is None:
            return None
        try:
            if self.stop_requested:
                summary = worker.cancel(wait=True, timeout=NSFW_CANCEL_TIMEOUT)
            else:
                pending = worker.pending_tasks()
                if pending:
                    self.log(f"[NSFW] 注册账号已处理完，等待本批 NSFW 完成（剩余 {pending}）")
                summary = worker.finish()
            submitted = int(summary.get("submitted", 0))
            if submitted:
                self.log(
                    f"[NSFW] 本批结束：成功 {summary.get('succeeded', 0)} | "
                    f"失败 {summary.get('failed', 0)} | "
                    f"未尝试 {summary.get('cancelled', 0)}"
                )
            if not summary.get("worker_stopped", True):
                self.log("[NSFW] [!] 停止等待已超时，后台清理仍会继续")
            return summary
        finally:
            self.nsfw_retry_worker = None

    def _on_close(self):
        if self._closing:
            return
        self._closing = True
        self.stop_requested = True
        config["close_browser_on_stop"] = True
        worker = getattr(self, "nsfw_retry_worker", None)
        if worker is not None:
            worker.cancel(wait=True, timeout=5.0)
        try:
            self.root.destroy()
        except tk.TclError:
            pass

    def start_registration(self):
        if self.is_running:
            self.log("[!] 当前已有任务在运行")
            return
        if self.sso_convert_running:
            self.log("[!] SSO 补转正在运行，请结束后再开始注册")
            return

        config["email_provider"] = self.email_provider_var.get().strip() or "cloudflare"
        config["enable_nsfw"] = bool(self.nsfw_var.get())
        config["close_browser_on_stop"] = bool(self.close_browser_on_stop_var.get())
        config["log_level"] = (self.log_level_var.get().strip() or "info").lower()
        config["proxy"] = self.proxy_var.get().strip()
        config["duckmail_api_key"] = self.api_key_var.get().strip()
        config["duckmail_api_base"] = self.duckmail_api_base_var.get().strip() or DUCKMAIL_API_BASE_DEFAULT
        config["cloudflare_api_base"] = self.cloudflare_api_base_var.get().strip()
        config["cloudflare_api_key"] = self.cloudflare_api_key_var.get().strip()
        config["cloudflare_auth_mode"] = self.cloudflare_auth_mode_var.get().strip() or "none"
        config["defaultDomains"] = self.default_domains_var.get().strip()
        config["cloudflare_custom_auth"] = self.cloudflare_custom_auth_var.get().strip()
        config["cloudflare_random_subdomain"] = bool(self.cloudflare_random_subdomain_var.get())
        config["yyds_api_key"] = self.yyds_api_key_var.get().strip()
        config["yyds_jwt"] = self.yyds_jwt_var.get().strip()
        config["mailnest_api_key"] = self.mailnest_api_key_var.get().strip()
        config["mailnest_project_code"] = (
            self.mailnest_project_code_var.get().strip() or MAILNEST_DEFAULT_PROJECT_CODE
        )
        config["yyds_default_domain"] = self.yyds_default_domain_var.get().strip()
        config["cloudmail_url"] = self.cloudmail_url_var.get().strip()
        config["cloudmail_admin_email"] = self.cloudmail_admin_email_var.get().strip()
        config["cloudmail_password"] = self.cloudmail_password_var.get()
        config["cpa_auto_add"] = bool(self.cpa_auto_add_var.get())
        config["cpa_auth_dir"] = self.cpa_auth_dir_var.get().strip()
        config["cpa_remote_url"] = self.cpa_remote_url_var.get().strip()
        config["cpa_management_key"] = self.cpa_management_key_var.get().strip()
        raw_paths = [x.strip() for x in self.cloudflare_paths_var.get().split(",") if x.strip()]
        if len(raw_paths) >= 4:
            config["cloudflare_path_domains"] = raw_paths[0] if raw_paths[0].startswith("/") else ("/" + raw_paths[0])
            config["cloudflare_path_accounts"] = raw_paths[1] if raw_paths[1].startswith("/") else ("/" + raw_paths[1])
            config["cloudflare_path_token"] = raw_paths[2] if raw_paths[2].startswith("/") else ("/" + raw_paths[2])
            config["cloudflare_path_messages"] = raw_paths[3] if raw_paths[3].startswith("/") else ("/" + raw_paths[3])
        save_config()
        if config["email_provider"] == "cloudflare" and not config["cloudflare_api_base"]:
            self.log("[!] Cloudflare 模式需要先填写 Cloudflare API Base")
            return
        if config["email_provider"] == "mailnest" and not config["mailnest_api_key"]:
            self.log("[!] MailNest 模式需要先填写 MailNest API Key")
            return
        if config["email_provider"] == "cloudmail":
            missing = []
            if not get_cloudmail_url():
                missing.append("CloudMail URL")
            if not get_cloudmail_admin_email():
                missing.append("CloudMail 管理员邮箱")
            if not get_cloudmail_password():
                missing.append("CloudMail 管理员密码")
            if not config["defaultDomains"]:
                missing.append("默认收信域名")
            if missing:
                self.log(f"[!] CloudMail 模式缺少配置: {', '.join(missing)}")
                return
        if config.get("cpa_auto_add") and not config.get("cpa_auth_dir") and not config.get("cpa_remote_url"):
            self.log("[!] 已开启 SSO→auth，但未配置 auth 目录或远程地址")
            return
        try:
            count = int(self.count_var.get())
        except Exception:
            self.log("[!] 注册数量无效")
            return
        try:
            workers = int(self.workers_var.get())
        except Exception:
            workers = 1
        workers = max(1, min(workers, 8, count))
        config["register_count"] = count
        config["register_workers"] = workers
        save_config()
        self.stop_requested = False
        self.success_count = 0
        self.fail_count = 0
        self.fail_stats = empty_fail_stats()
        self.results = []
        now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.accounts_output_file = os.path.join(
            os.path.dirname(__file__), f"accounts_{now}.txt"
        )
        self.batch_count = count
        self._batch_started_at = time.time()
        self.progress_var.set(0)
        self.eta_var.set(f"进度 0/{count} | ETA --")
        self.update_stats()
        self._set_running_ui(True)
        self._stats_lock = threading.Lock()
        self._accounts_lock = threading.Lock()
        if config.get("enable_nsfw", True):
            self.nsfw_retry_worker = create_nsfw_retry_worker(
                log_callback=self.log,
                cancel_callback=self.should_stop,
            )
        else:
            self.nsfw_retry_worker = None
        # 启动前快速连通性检查（失败仍可继续，只警告）
        try:
            checks = _conn.run_connectivity_checks(config, http_get, http_post)
            for name, ok, detail in checks:
                self.log(f"[检查] [{'OK' if ok else 'FAIL'}] {name}: {detail}")
            if not all(ok for _, ok, _ in checks):
                self.log("[!] 连通性检查存在失败项，仍继续注册（可先点「连通性检查」排查）")
        except Exception as exc:
            self.log(f"[!] 连通性检查异常: {exc}")
        self.log(
            f"[*] 配置已保存，开始执行。目标数量: {count} | 并发: {workers}"
        )
        if int(self.workers_var.get() or 1) > count:
            self.log(f"[*] 并发已自动调整为 {workers}（不超过注册数量）")
        self.log(f"[*] SSO→auth: {'开' if config.get('cpa_auto_add') else '关（仅保存 SSO）'}")
        self.log(f"[*] 成功账号将实时保存到: {self.accounts_output_file}")
        threading.Thread(
            target=self._run_registration_entry,
            args=(count, workers),
            daemon=True,
        ).start()

    def stop_registration(self):
        if self.sso_convert_running and not self.is_running:
            if self.sso_convert_stop_requested:
                return
            self.sso_convert_stop_requested = True
            self.stop_btn.config(state=tk.DISABLED)
            self.status_var.set("正在停止 SSO 补转...")
            self.status_label.config(foreground="orange")
            self.log("[!] 用户停止 SSO 补转（当前账号完成后停止）")
            return
        if self.stop_requested:
            return
        self.stop_requested = True
        worker = getattr(self, "nsfw_retry_worker", None)
        if worker is not None:
            worker.cancel(wait=False)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("正在停止...")
        self.status_label.config(foreground="orange")
        # 即时写入，worker finally 能读到最新勾选状态
        config["close_browser_on_stop"] = bool(self.close_browser_on_stop_var.get())
        keep = not config.get("close_browser_on_stop", False)
        self.log("[!] 用户停止注册" + ("（将保留浏览器）" if keep else "（将关闭浏览器）"))

    def _run_registration_entry(self, count, workers):
        # 并发数不超过任务数，避免空 worker 白开浏览器
        workers = max(1, min(int(workers or 1), 8, int(count or 1)))
        try:
            if use_protocol_pipeline(count, workers):
                self.run_protocol_pipeline_registration(count, workers)
            elif workers <= 1:
                self.run_registration(count, worker_id=0, workers=1)
            else:
                base, rem = divmod(count, workers)
                chunks = [base + (1 if i < rem else 0) for i in range(workers)]
                # 去掉 0 任务分片，重新编号
                chunks = [n for n in chunks if n > 0]
                self.log(f"[*] 实际并发 worker={len(chunks)}，分片={chunks}")
                threads = []
                for wid, n in enumerate(chunks):
                    if self.should_stop():
                        break
                    t = threading.Thread(
                        target=self.run_registration,
                        args=(n, wid, len(chunks)),
                        daemon=True,
                    )
                    t.start()
                    threads.append(t)
                    # 错开启动，降低同时拉起 Chrome 端口/用户目录冲突
                    try:
                        sleep_with_cancel(2.0, self.should_stop)
                    except RegistrationCancelled:
                        break
                for t in threads:
                    while t.is_alive():
                        t.join(timeout=0.2)
        finally:
            # 协调线程自身无浏览器；各 worker 线程 finally 已各自 stop
            try:
                self._finish_nsfw_batch()
            except Exception as exc:
                self.log(f"[NSFW] [!] 本批收尾异常: {exc}")
            self._set_running_ui(False)
            self.log(
                f"[*] 任务结束。成功 {self.success_count} | 失败 {self.fail_count}"
                + (f" | {format_fail_stats(self.fail_stats)}" if self.fail_count else "")
            )

    def run_protocol_pipeline_registration(self, count, workers=1):
        """GUI 批量协议注册：S/P/C/O 流水线，O 阶段写账号 + NSFW + CPA。"""
        self.log("[*] 协议注册模式：S/P/C/O 流水线（不启动注册页浏览器）")

        def on_account(email, password, sso, profile):
            if not profile:
                profile = {"password": password}
            elif password and not profile.get("password"):
                profile["password"] = password
            try:
                line = f"{email}----{profile.get('password','') or password}----{sso}\n"
                alock = getattr(self, "_accounts_lock", None)
                if alock:
                    with alock:
                        with open(self.accounts_output_file, "a", encoding="utf-8") as f:
                            f.write(line)
                else:
                    with open(self.accounts_output_file, "a", encoding="utf-8") as f:
                        f.write(line)
            except Exception as file_exc:
                self.log(f"[!] 保存账号文件失败: {file_exc}")
                _append_sso_pending(email, sso, log_callback=self.log)
                raise RuntimeError(f"保存账号文件失败: {file_exc}") from file_exc
            lock = getattr(self, "_stats_lock", None)
            if lock:
                with lock:
                    self.results.append({"email": email, "sso": sso, "profile": profile})
            else:
                self.results.append({"email": email, "sso": sso, "profile": profile})
            if config.get("enable_nsfw", True):
                self._submit_nsfw(email, sso, log_callback=self.log)
            cpa_ok = add_sso_to_cpa(
                sso,
                email=email,
                log_callback=self.log,
                should_stop=self.should_stop,
            )
            self._record_success()
            self.update_stats()
            if cpa_ok:
                self.log(f"[+] 注册成功: {email}")
            else:
                self.log(f"[+] 注册成功（SSO 已保存，CPA 入库失败）: {email}")

        try:
            stats = run_protocol_pipeline_batch(
                count,
                log_callback=self.log,
                should_stop=self.should_stop,
                on_account=on_account,
                register_workers=workers,
            )
            if stats.fail and self.fail_count < stats.fail:
                delta = stats.fail - self.fail_count
                for _ in range(delta):
                    self._record_failure(RuntimeError("pipeline stage fail"))
                self.update_stats()
        except RegistrationCancelled:
            self.log("[!] 注册被用户停止")
        except Exception as exc:
            self.log(f"[!] 流水线异常: {exc}")
            self._record_failure(exc)
            self.update_stats()

    def run_registration(self, count, worker_id=0, workers=1):
        prefix = f"[W{worker_id + 1}] " if workers > 1 else ""

        def wlog(message):
            text = str(message)
            if prefix and not text.startswith(prefix):
                self.log(prefix + text)
            else:
                self.log(text)

        try:
            protocol = use_protocol_register()
            if not protocol:
                try:
                    start_browser(
                        log_callback=wlog,
                        cancel_callback=self.should_stop,
                    )
                except Exception as boot_exc:
                    streak = get_start_fail_streak()
                    wlog(f"[-] 浏览器启动失败 (连续失败 {streak}): {boot_exc}")
                    if workers > 1 and streak >= 3:
                        wlog("[!] 连续启动失败较多，建议降低并发后重试")
                    for _ in range(max(int(count or 0), 0)):
                        self._record_failure(boot_exc)
                    self.update_stats()
                    return
                wlog("[*] 浏览器已启动")
            else:
                wlog("[*] 协议注册模式：不启动注册页浏览器")
            i = 0
            retry_count_for_slot = 0
            max_slot_retry = 3
            while i < count:
                if self.should_stop():
                    break
                wlog(f"--- 开始第 {i + 1}/{count} 个账号 ---")
                try:
                    email, password, sso, profile = register_account_once(
                        log_callback=wlog,
                        cancel_callback=self.should_stop,
                    )
                    if not profile:
                        profile = {"password": password}
                    elif password and not profile.get("password"):
                        profile["password"] = password
                    try:
                        line = f"{email}----{profile.get('password','') or password}----{sso}\n"
                        alock = getattr(self, "_accounts_lock", None)
                        if alock:
                            with alock:
                                with open(self.accounts_output_file, "a", encoding="utf-8") as f:
                                    f.write(line)
                        else:
                            with open(self.accounts_output_file, "a", encoding="utf-8") as f:
                                f.write(line)
                    except Exception as file_exc:
                        wlog(f"[!] 保存账号文件失败，当前账号不计为成功: {file_exc}")
                        _append_sso_pending(email, sso, log_callback=wlog)
                        raise RuntimeError(f"保存账号文件失败: {file_exc}") from file_exc
                    lock = getattr(self, "_stats_lock", None)
                    if lock:
                        with lock:
                            self.results.append({"email": email, "sso": sso, "profile": profile})
                    else:
                        self.results.append({"email": email, "sso": sso, "profile": profile})
                    if config.get("enable_nsfw", True):
                        self._submit_nsfw(email, sso, log_callback=wlog)
                    cpa_ok = add_sso_to_cpa(
                        sso,
                        email=email,
                        log_callback=wlog,
                        should_stop=self.should_stop,
                    )
                    self._record_success()
                    retry_count_for_slot = 0
                    i += 1
                    if cpa_ok:
                        wlog(f"[+] 注册成功: {email}")
                    else:
                        wlog(f"[+] 注册成功（SSO 已保存，CPA 入库失败）: {email}")
                    if (
                        self.success_count > 0
                        and self.success_count % MEMORY_CLEANUP_INTERVAL == 0
                        and i < count
                        and workers <= 1
                    ):
                        cleanup_runtime_memory(
                            log_callback=wlog,
                            reason=f"已成功 {self.success_count} 个账号，执行定期清理",
                        )
                except RegistrationCancelled:
                    wlog("[!] 注册被用户停止")
                    break
                except EmailDomainRejected as exc:
                    kind = self._record_failure(exc)
                    retry_count_for_slot = 0
                    i += 1
                    wlog(f"[-] 邮箱域名被 xAI 拒绝 [{FAIL_LABELS.get(kind, kind)}]: {exc}")
                    wlog("[!] 请更换邮箱提供商或域名（如 Cloudflare 自建域 / MailNest），公共临时域常被拉黑")
                except AccountRetryNeeded as exc:
                    retry_count_for_slot += 1
                    if retry_count_for_slot <= max_slot_retry:
                        wlog(
                            f"[!] 当前账号流程卡住，重试第 {retry_count_for_slot}/{max_slot_retry} 次: {exc}"
                        )
                    else:
                        kind = self._record_failure(exc)
                        wlog(
                            f"[-] 当前账号已达到最大重试次数，跳过 [{FAIL_LABELS.get(kind, kind)}]: {exc}"
                        )
                        retry_count_for_slot = 0
                        i += 1
                except Exception as exc:
                    kind = self._record_failure(exc)
                    retry_count_for_slot = 0
                    i += 1
                    wlog(f"[-] 注册失败 [{FAIL_LABELS.get(kind, kind)}]: {exc}")
                finally:
                    self.update_stats()
                    if self.should_stop():
                        break
                    # 浏览器模式：每轮结束只关浏览器；协议模式无常驻浏览器。
                    # 下一轮 open_signup_page 会按需启动并导航到官网，避免空浏览器残留。
                    if i >= count or protocol:
                        continue
                    try:
                        stop_browser()
                        time.sleep(0.5)
                    except Exception as close_exc:
                        if self.should_stop():
                            break
                        wlog(f"[Debug] 轮次关闭浏览器失败: {close_exc}")
        except RegistrationCancelled:
            wlog("[!] 注册被用户停止")
        except Exception as exc:
            wlog(f"[!] 任务异常: {exc}")
        finally:
            try:
                maybe_stop_browser(user_stopped=bool(self.stop_requested), log_callback=wlog)
            except BaseException:
                pass
            # 收尾 UI / 汇总只由 _run_registration_entry 负责，避免打印两次


class CliStopController:
    def __init__(self):
        self._stop_event = threading.Event()

    def should_stop(self):
        return self._stop_event.is_set()

    def stop(self):
        self._stop_event.set()


def cli_log(message):
    if not should_emit_log(message):
        return
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    line = f"[{timestamp}] {message}"
    append_session_log(line)
    print(line, flush=True)


def run_registration_cli(count):
    controller = CliStopController()
    nsfw_worker = None
    sigint_received = False
    sigint_notice_logged = False

    # 一次 Ctrl+C 可靠置停：SIGINT 处理器直接设停止标志，不依赖异常在
    # curl_cffi C 回调里向上传播（那里 KeyboardInterrupt 会被吞掉，导致
    # 第一次 Ctrl+C 无效、循环继续跑下一个账号）。连按两次 Ctrl+C 时第二次
    # 恢复默认行为强制中断。
    _prev_sigint = signal.getsignal(signal.SIGINT)

    def _on_sigint(signum, frame):
        nonlocal sigint_received
        if controller.should_stop():
            # 第二次：恢复默认并重新抛出，强制中断
            signal.signal(signal.SIGINT, _prev_sigint)
            raise KeyboardInterrupt
        controller.stop()
        sigint_received = True

    signal.signal(signal.SIGINT, _on_sigint)
    success_count = 0
    fail_count = 0
    fail_stats = empty_fail_stats()
    retry_count_for_slot = 0
    max_slot_retry = 3
    accounts_output_file = os.path.join(
        os.path.dirname(__file__),
        f"accounts_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
    )
    workers = max(1, min(int(config.get("register_workers", 1) or 1), 8, int(count or 1)))
    cli_log(f"[*] 终端模式启动，目标数量: {count} | 并发: {workers}")
    cli_log(f"[*] SSO→auth: {'开' if config.get('cpa_auto_add') else '关（仅保存 SSO）'}")
    cli_log(f"[*] 成功账号将实时保存到: {accounts_output_file}")
    if config.get("enable_nsfw", True):
        nsfw_worker = create_nsfw_retry_worker(
            log_callback=cli_log,
            cancel_callback=controller.should_stop,
        )

    def _emit_sigint_notice():
        nonlocal sigint_notice_logged
        if sigint_received and not sigint_notice_logged:
            sigint_notice_logged = True
            cli_log("[!] 收到 Ctrl+C，正在停止（再按一次强制中断）")

    def _submit_cli_nsfw(email, sso, prefix=""):
        if nsfw_worker is None:
            return False
        try:
            queued = nsfw_worker.submit(email, sso)
        except Exception as exc:
            cli_log(f"{prefix}[NSFW] [!] 加入本批队列失败，账号仍继续入库: {exc}")
            return False
        if queued:
            cli_log(f"{prefix}[*] NSFW 已进入本批后台队列")
        else:
            cli_log(f"{prefix}[NSFW] [!] 未加入本批队列，已保留 pending")
        return queued

    def _finish_cli_nsfw():
        nonlocal nsfw_worker
        _emit_sigint_notice()
        worker = nsfw_worker
        if worker is None:
            return None
        try:
            if controller.should_stop():
                summary = worker.cancel(wait=True, timeout=NSFW_CANCEL_TIMEOUT)
            else:
                pending = worker.pending_tasks()
                if pending:
                    cli_log(f"[NSFW] 注册账号已处理完，等待本批 NSFW 完成（剩余 {pending}）")
                summary = worker.finish()
            submitted = int(summary.get("submitted", 0))
            if submitted:
                cli_log(
                    f"[NSFW] 本批结束：成功 {summary.get('succeeded', 0)} | "
                    f"失败 {summary.get('failed', 0)} | "
                    f"未尝试 {summary.get('cancelled', 0)}"
                )
            if not summary.get("worker_stopped", True):
                cli_log("[NSFW] [!] 停止等待已超时，后台清理仍会继续")
            return summary
        finally:
            nsfw_worker = None

    def _cli_record_failure(exc):
        nonlocal fail_count
        kind = classify_failure(exc)
        fail_count += 1
        fail_stats[kind] = fail_stats.get(kind, 0) + 1
        return kind

    if use_protocol_pipeline(count, workers):
        # 协议批量：S/P/C/O 流水线（O 阶段写账号/NSFW/CPA）
        stats_lock = threading.Lock()

        def on_account(email, password, sso, profile):
            nonlocal success_count
            if not profile:
                profile = {"password": password}
            elif password and not profile.get("password"):
                profile["password"] = password
            try:
                line = f"{email}----{profile.get('password','') or password}----{sso}\n"
                with stats_lock:
                    with open(accounts_output_file, "a", encoding="utf-8") as f:
                        f.write(line)
            except Exception as file_exc:
                cli_log(f"[!] 保存账号文件失败: {file_exc}")
                _append_sso_pending(email, sso, log_callback=cli_log)
                raise RuntimeError(f"保存账号文件失败: {file_exc}") from file_exc
            _submit_cli_nsfw(email, sso)
            cpa_ok = add_sso_to_cpa(
                sso,
                email=email,
                log_callback=cli_log,
                should_stop=controller.should_stop,
            )
            with stats_lock:
                success_count += 1
                sc = success_count
            if cpa_ok:
                cli_log(f"[+] 注册成功: {email}")
            else:
                cli_log(f"[+] 注册成功（SSO 已保存，CPA 入库失败）: {email}")
            cli_log(f"[*] 当前统计: 成功 {sc} | 失败 {fail_count}")

        try:
            pipe_stats = run_protocol_pipeline_batch(
                count,
                log_callback=cli_log,
                should_stop=controller.should_stop,
                on_account=on_account,
                register_workers=workers,
            )
            if pipe_stats.fail:
                fail_count = max(fail_count, int(pipe_stats.fail))
                fail_stats[FAIL_OTHER] = fail_stats.get(FAIL_OTHER, 0) + int(
                    pipe_stats.fail
                )
        except RegistrationCancelled:
            cli_log("[!] 注册被停止")
        except Exception as exc:
            kind = _cli_record_failure(exc)
            cli_log(f"[-] 流水线异常 [{FAIL_LABELS.get(kind, kind)}]: {exc}")
        _finish_cli_nsfw()
        cli_log(
            f"[*] 任务结束。成功 {success_count} | 失败 {fail_count}"
            + (f" | {format_fail_stats(fail_stats)}" if fail_count else "")
        )
        try:
            signal.signal(signal.SIGINT, _prev_sigint)
        except Exception:
            pass
        return

    if workers > 1:
        # CLI 并发：多线程，每线程独立浏览器（thread-local）
        stats_lock = threading.Lock()
        accounts_lock = threading.Lock()
        base, rem = divmod(count, workers)
        chunks = [base + (1 if i < rem else 0) for i in range(workers)]
        threads = []
        shared = {"success": 0, "fail": 0, "fail_stats": empty_fail_stats()}

        def worker(n, wid):
            local_success = 0
            local_fail = 0
            local_fail_stats = empty_fail_stats()
            try:
                protocol = use_protocol_register()
                if not protocol:
                    try:
                        start_browser(
                            log_callback=lambda m: cli_log(f"[W{wid+1}] {m}"),
                            cancel_callback=controller.should_stop,
                        )
                    except Exception as boot_exc:
                        local_fail = n
                        local_fail_stats[FAIL_BROWSER] = local_fail_stats.get(FAIL_BROWSER, 0) + n
                        cli_log(f"[W{wid+1}] [-] 浏览器启动失败，{n} 个任务均记为失败: {boot_exc}")
                        return
                i = 0
                retry = 0
                while i < n and not controller.should_stop():
                    try:
                        email, password, sso, profile = register_account_once(
                            log_callback=lambda m: cli_log(f"[W{wid+1}] {m}"),
                            cancel_callback=controller.should_stop,
                        )
                        if not profile:
                            profile = {"password": password}
                        elif password and not profile.get("password"):
                            profile["password"] = password
                        line = f"{email}----{profile.get('password','') or password}----{sso}\n"
                        try:
                            with accounts_lock:
                                with open(accounts_output_file, "a", encoding="utf-8") as f:
                                    f.write(line)
                        except Exception as file_exc:
                            cli_log(
                                f"[W{wid+1}] [!] 保存账号文件失败，当前账号不计为成功: {file_exc}"
                            )
                            _append_sso_pending(
                                email,
                                sso,
                                log_callback=lambda m: cli_log(f"[W{wid+1}] {m}"),
                            )
                            raise RuntimeError(f"保存账号文件失败: {file_exc}") from file_exc
                        _submit_cli_nsfw(email, sso, prefix=f"[W{wid+1}] ")
                        cpa_ok = add_sso_to_cpa(
                            sso,
                            email=email,
                            log_callback=lambda m: cli_log(f"[W{wid+1}] {m}"),
                            should_stop=controller.should_stop,
                        )
                        local_success += 1
                        i += 1
                        retry = 0
                        if cpa_ok:
                            cli_log(f"[W{wid+1}] [+] 注册成功: {email}")
                        else:
                            cli_log(f"[W{wid+1}] [+] 注册成功（SSO 已保存，CPA 入库失败）: {email}")
                    except RegistrationCancelled:
                        break
                    except EmailDomainRejected as exc:
                        kind = classify_failure(exc)
                        local_fail_stats[kind] = local_fail_stats.get(kind, 0) + 1
                        local_fail += 1
                        i += 1
                        retry = 0
                        cli_log(f"[W{wid+1}] [-] 域名拒绝: {exc}")
                    except AccountRetryNeeded as exc:
                        retry += 1
                        if retry > max_slot_retry:
                            kind = classify_failure(exc)
                            local_fail_stats[kind] = local_fail_stats.get(kind, 0) + 1
                            local_fail += 1
                            i += 1
                            retry = 0
                            cli_log(f"[W{wid+1}] [-] 卡住跳过: {exc}")
                    except Exception as exc:
                        kind = classify_failure(exc)
                        local_fail_stats[kind] = local_fail_stats.get(kind, 0) + 1
                        local_fail += 1
                        i += 1
                        retry = 0
                        cli_log(f"[W{wid+1}] [-] 失败 [{FAIL_LABELS.get(kind, kind)}]: {exc}")
                    finally:
                        if i < n and not controller.should_stop():
                            try:
                                stop_browser()
                                time.sleep(0.3)
                            except Exception:
                                pass
            finally:
                try:
                    maybe_stop_browser(
                        user_stopped=bool(controller.should_stop()),
                        log_callback=lambda m: cli_log(f"[W{wid+1}] {m}"),
                    )
                except Exception:
                    pass
                with stats_lock:
                    shared["success"] += local_success
                    shared["fail"] += local_fail
                    for k, v in local_fail_stats.items():
                        shared["fail_stats"][k] = shared["fail_stats"].get(k, 0) + v

        for wid, n in enumerate(chunks):
            if n <= 0:
                continue
            t = threading.Thread(target=worker, args=(n, wid), daemon=True)
            t.start()
            threads.append(t)
        try:
            while any(t.is_alive() for t in threads):
                for t in threads:
                    t.join(timeout=0.2)
        except KeyboardInterrupt:
            controller.stop()
            cli_log("[!] 强制中断多并发任务")
            _finish_cli_nsfw()
            try:
                signal.signal(signal.SIGINT, _prev_sigint)
            except Exception:
                pass
            return
        success_count = shared["success"]
        fail_count = shared["fail"]
        fail_stats = shared["fail_stats"]
        _finish_cli_nsfw()
        cli_log(
            f"[*] 任务结束。成功 {success_count} | 失败 {fail_count}"
            + (f" | {format_fail_stats(fail_stats)}" if fail_count else "")
        )
        try:
            signal.signal(signal.SIGINT, _prev_sigint)
        except Exception:
            pass
        return

    try:
        protocol = use_protocol_register()
        if not protocol:
            try:
                start_browser(
                    log_callback=cli_log,
                    cancel_callback=controller.should_stop,
                )
            except Exception as boot_exc:
                fail_count += count
                fail_stats[FAIL_BROWSER] = fail_stats.get(FAIL_BROWSER, 0) + count
                cli_log(f"[-] 浏览器启动失败，{count} 个任务均记为失败: {boot_exc}")
                return
            cli_log("[*] 浏览器已启动")
        else:
            cli_log("[*] 协议注册模式：不启动注册页浏览器")
        i = 0
        while i < count:
            if controller.should_stop():
                break
            cli_log(f"--- 开始第 {i + 1}/{count} 个账号 ---")
            try:
                email, password, sso, profile = register_account_once(
                    log_callback=cli_log,
                    cancel_callback=controller.should_stop,
                )
                if not profile:
                    profile = {"password": password}
                elif password and not profile.get("password"):
                    profile["password"] = password
                try:
                    line = f"{email}----{profile.get('password','') or password}----{sso}\n"
                    with open(accounts_output_file, "a", encoding="utf-8") as f:
                        f.write(line)
                except Exception as file_exc:
                    cli_log(f"[!] 保存账号文件失败，当前账号不计为成功: {file_exc}")
                    _append_sso_pending(email, sso, log_callback=cli_log)
                    raise RuntimeError(f"保存账号文件失败: {file_exc}") from file_exc
                _submit_cli_nsfw(email, sso)
                cpa_ok = add_sso_to_cpa(
                    sso,
                    email=email,
                    log_callback=cli_log,
                    should_stop=controller.should_stop,
                )
                success_count += 1
                retry_count_for_slot = 0
                i += 1
                if cpa_ok:
                    cli_log(f"[+] 注册成功: {email}")
                else:
                    cli_log(f"[+] 注册成功（SSO 已保存，CPA 入库失败）: {email}")
                cli_log(f"[*] 当前统计: 成功 {success_count} | 失败 {fail_count}")
                if success_count > 0 and success_count % MEMORY_CLEANUP_INTERVAL == 0 and i < count:
                    cleanup_runtime_memory(
                        log_callback=cli_log,
                        reason=f"已成功 {success_count} 个账号，执行定期清理",
                    )
            except RegistrationCancelled:
                cli_log("[!] 注册被停止")
                break
            except EmailDomainRejected as exc:
                kind = _cli_record_failure(exc)
                retry_count_for_slot = 0
                i += 1
                cli_log(f"[-] 邮箱域名被 xAI 拒绝 [{FAIL_LABELS.get(kind, kind)}]: {exc}")
                cli_log("[!] 请更换邮箱提供商或域名（如 Cloudflare 自建域 / MailNest），公共临时域常被拉黑")
            except AccountRetryNeeded as exc:
                retry_count_for_slot += 1
                if retry_count_for_slot <= max_slot_retry:
                    cli_log(
                        f"[!] 当前账号流程卡住，重试第 {retry_count_for_slot}/{max_slot_retry} 次: {exc}"
                    )
                else:
                    kind = _cli_record_failure(exc)
                    retry_count_for_slot = 0
                    i += 1
                    cli_log(f"[-] 当前账号已达到最大重试次数，跳过 [{FAIL_LABELS.get(kind, kind)}]: {exc}")
            except Exception as exc:
                kind = _cli_record_failure(exc)
                retry_count_for_slot = 0
                i += 1
                cli_log(f"[-] 注册失败 [{FAIL_LABELS.get(kind, kind)}]: {exc}")
            finally:
                if controller.should_stop():
                    break
                # 每轮结束只关浏览器，不立刻再开。
                # 下一轮 open_signup_page 会按需启动并导航到官网，避免空浏览器残留。
                if i >= count:
                    continue
                try:
                    stop_browser()
                    time.sleep(0.5)
                except KeyboardInterrupt:
                    controller.stop()
                    cli_log("[!] 收到 Ctrl+C，正在停止（再按一次强制中断）")
                    break
                except RegistrationCancelled:
                    break
                except Exception as close_exc:
                    if controller.should_stop():
                        break
                    cli_log(f"[Debug] 轮次关闭浏览器失败: {close_exc}")
    except KeyboardInterrupt:
        controller.stop()
        cli_log("[!] 收到 Ctrl+C，正在停止并清理")
    except RegistrationCancelled:
        cli_log("[!] 注册被停止")
    except Exception as exc:
        cli_log(f"[!] 任务异常: {exc}")
    finally:
        try:
            _finish_cli_nsfw()
        except BaseException as exc:
            cli_log(f"[NSFW] [!] 本批收尾异常: {exc}")
        try:
            signal.signal(signal.SIGINT, signal.SIG_IGN)
        except Exception:
            pass
        try:
            user_stopped = bool(controller.should_stop())
            if user_stopped and not should_close_browser_after_run(True):
                maybe_stop_browser(user_stopped=True, log_callback=cli_log)
            else:
                cleanup_runtime_memory(log_callback=cli_log, reason="任务结束")
        except BaseException:
            pass
        try:
            cli_log(
                f"[*] 任务结束。成功 {success_count} | 失败 {fail_count}"
                + (f" | {format_fail_stats(fail_stats)}" if fail_count else "")
            )
        except BaseException:
            pass
        try:
            signal.signal(signal.SIGINT, _prev_sigint)
        except Exception:
            pass


def main_cli(auto_start: bool = False, headless: bool | None = None):
    load_config()
    # 默认不用真 headless（CF 会拦），而是后台置底有界面浏览器
    if headless is None:
        headless = False
    _wire_runtime_modules(gui_mode=False, headless=headless)
    count = int(config.get("register_count", 1) or 1)
    cli_log("[*] CLI 已加载配置")
    cli_log(
        f"[*] 当前邮箱服务商: {config.get('email_provider', 'duckmail')} | "
        f"注册数量: {count} | headless={bool(headless)} | "
        f"background={bool(not headless)}"
    )
    if not auto_start:
        cli_log("[*] 输入 start 后开始；按 Ctrl+C 可强制停止")
        try:
            command = input("> ").strip().lower()
        except KeyboardInterrupt:
            cli_log("[!] 已取消")
            return
        if command != "start":
            cli_log("[!] 未输入 start，已退出")
            return
    try:
        run_registration_cli(count)
    except KeyboardInterrupt:
        # 清理阶段仍可能漏出，保证 CLI 干净退出
        cli_log("[!] 已停止")


def main():
    try:
        initialize_session_log()
    except OSError as exc:
        print(f"[日志] 无法创建日志文件: {exc}", flush=True)
    load_config()
    argv = [a.strip().lower() for a in sys.argv[1:]]
    headless_flag = None
    if "--headless" in argv or "headless" in argv:
        headless_flag = True
    if "--no-headless" in argv or "--show-browser" in argv:
        headless_flag = False
    auto_start = any(a in ("start", "--start", "auto") for a in argv)
    if any(a in ("start", "cli", "--cli", "--start", "auto") for a in argv):
        main_cli(
            auto_start=auto_start or "start" in argv or "--start" in argv or "auto" in argv,
            headless=headless_flag if headless_flag is not None else False,
        )
        return
    _wire_runtime_modules(gui_mode=True, headless=headless_flag)
    root = tk.Tk()
    setup_light_theme(root)
    app = GrokRegisterGUI(root)
    root.mainloop()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
