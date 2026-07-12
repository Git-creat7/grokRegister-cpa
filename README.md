<div align="center">

[![Grok Register — 注册即入库 CLIProxyAPI](assets/banner.png)](https://github.com/Git-creat7/grokRegister-cpa)

批量注册 Grok 账号，注册成功后自动把 OAuth 凭证写入 [CLIProxyAPI (CPA)](https://github.com/router-for-me/CLIProxyAPI)：支持本地 auth 目录热加载，也支持 Management API 远程上传。

<p>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/Python-3.9%2B-3776AB.svg" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/Interface-GUI%20%2B%20CLI-success.svg" alt="GUI + CLI">
  <img src="https://img.shields.io/badge/Output-CLIProxyAPI-orange.svg" alt="CLIProxyAPI">
</p>

</div>

---

> 仅用于自动化流程研究、测试环境验证和个人学习。请遵守目标网站服务条款、当地法律法规与第三方服务限制。

## 核心流程

```text
打开注册页 → 创建临时邮箱 → 收验证码 → 填资料 / 过人机验证
   → 拿到 SSO cookie → 授权码流程换 OAuth token（带 referrer=grok-build）
   → 本地写入 cpa_auth_dir  和/或  POST 远程 CPA Management API
   → CPA 热加载，立即可用
```

## 功能

- 注册成功后自动入库 CPA（本地目录 / 远程 Management API，可同时开）
- GUI + CLI 两种运行方式（CLI 仍会打开浏览器完成注册页）
- Chromium/Chrome 自动处理 Turnstile
- DuckMail / YYDS / Cloudflare 临时邮箱
- 注册后可选开启 NSFW
- 页面卡住重试、验证码失败换邮箱、浏览器重启与内存清理
- CLI：一次 `Ctrl+C` 安全停止，清理阶段不刷 traceback；再按一次强制中断

## 环境要求

- Python 3.9+
- Google Chrome 或 Chromium
- 可用的 [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)
- 能访问注册页、临时邮箱 API、`auth.x.ai` 的网络（授权码流程换 token 需要）

## 安装

```bash
git clone https://github.com/Git-creat7/grokRegister-cpa.git
cd grokRegister-cpa
pip install -r requirements.txt
cp config.example.json config.json
```

编辑 `config.json` 后运行。

## 配置

| 配置项 | 说明 |
| --- | --- |
| `cpa_auto_add` | 是否开启 CPA 自动入库 |
| `cpa_auth_dir` | 本地 CPA auth 目录；写入 `xai-<email>.json`，可留空 |
| `cpa_remote_url` | 远程 CPA 地址，如 `http://你的CPA地址:8317` |
| `cpa_management_key` | 远程 CPA 管理密钥（`remote-management.secret-key` 明文） |
| `email_provider` | `duckmail` / `yyds` / `cloudflare` |
| `register_count` | 目标注册数量 |
| `proxy` | 代理；换 token 的 OAuth 请求也走此代理 |
| `enable_nsfw` | 注册后是否尝试开启 NSFW |
| `cloudflare_api_base` | Cloudflare 临时邮箱 API 根地址 |
| `cloudflare_api_key` | 默认匿名模式留空；admin 模式填 `ADMIN_PASSWORD` |
| `cloudflare_auth_mode` | `none` / `bearer` / `x-api-key` / `x-admin-auth` / `query-key` |
| `cloudflare_custom_auth` | Worker 全局密码（`PASSWORDS`），注入 `x-custom-auth` |
| `cloudflare_path_*` | domains / accounts / token / messages 路径 |
| `defaultDomains` | Cloudflare 默认收信域名 |

### Cloudflare 邮箱（默认匿名）

```json
{
  "email_provider": "cloudflare",
  "cloudflare_api_base": "https://你的-worker-api-域名",
  "cloudflare_api_key": "",
  "cloudflare_auth_mode": "none",
  "cloudflare_path_domains": "/api/domains",
  "cloudflare_path_accounts": "/api/new_address",
  "cloudflare_path_token": "/api/token",
  "cloudflare_path_messages": "/api/mails",
  "defaultDomains": "你的收信域名.com"
}
```

匿名创建失败（例如 Turnstile）时可改 admin 创建：

```json
{
  "cloudflare_api_key": "你的 ADMIN_PASSWORD",
  "cloudflare_auth_mode": "x-admin-auth",
  "cloudflare_path_accounts": "/admin/new_address"
}
```

调试创建接口：

```bash
python cf_mail_debug.py \
  --api-base "https://你的-worker-api-域名" \
  --auth-mode x-admin-auth \
  --api-key "你的 ADMIN_PASSWORD" \
  --create-path /admin/new_address \
  --domain "你的收信域名.com"
```

Worker 若配置了全局 `PASSWORDS`，再加：

```json
{ "cloudflare_custom_auth": "你的全局访问密码" }
```

## CPA 自动入库

SSO 不是 CPA 凭据。程序会：

1. 用 SSO 走授权码流程（`referrer=grok-build`）向 `auth.x.ai` 换 `access_token` / `refresh_token`
2. 组装 `type=xai` 扁平 auth（`cli-chat-proxy.grok.com`）
3. 本地：`cpa_auth_dir` → `xai-<email>.json`（CPA 热加载）
4. 远程：`POST {cpa_remote_url}/v0/management/auth-files?name=...`（需管理密钥）

### 本地目录

```json
{
  "cpa_auto_add": true,
  "cpa_auth_dir": "你的CPA auth目录"
}
```

`cpa_auth_dir` 填 CPA 实际监听的 auth 目录路径即可。

### 远程 Management API

```json
{
  "cpa_auto_add": true,
  "cpa_auth_dir": "",
  "cpa_remote_url": "http://你的CPA地址:8317",
  "cpa_management_key": "你的管理密钥明文"
}
```

要求 CPA：`remote-management.allow-remote` 按访问方式配置；密钥为配置里的明文（启动后配置文件可能被写成 bcrypt，上传仍用明文）。

本地与远程可同时开启。日志前缀：`[CPA]`。

### 独立转换

已有 SSO 时可脱离注册流程：

```bash
# 写本地目录
python sso_to_auth_json.py --sso sso_list.txt --cpa-auth-dir /path/to/auths

# 上传远程 CPA
python sso_to_auth_json.py --sso sso_list.txt \
  --cpa-remote-url http://你的CPA地址:8317 \
  --cpa-management-key '你的管理密钥'

# 单个 cookie + 代理
python sso_to_auth_json.py --sso-cookie 'eyJ...' \
  --cpa-auth-dir ./auths \
  --proxy http://127.0.0.1:7890
```

`sso_list.txt`：一行一个 SSO，或 `邮箱----密码----sso`。

### 为什么必须用授权码流程

这是本项目区别于普通 SSO→token 脚本的关键，踩过坑后固化下来：

- **SSO 不能直接喂给 CPA。** CPA 走 OAuth，需要 `access_token` / `refresh_token`，SSO cookie 只是换 token 的入场券。
- **必须带 `referrer=grok-build`。** xAI 后端要求 access_token 携带 `referrer=grok-build` claim，否则 grok build 通道（`cli-chat-proxy.grok.com`）拒绝，调用 chat 时报 `permission-denied / Access to the chat endpoint is denied`。早期用 device flow 换的 token **不带**这个 claim，会全部失效。
- **解法：授权码流程（Authorization Code + PKCE）。** 在 `/oauth2/authorize` 和 consent 提交两处注入 `referrer=grok-build`，换出的 token 才带此 claim。程序换完会自动校验，日志显示 `access_token 已带 referrer=grok-build`。
- **base_url 必须是 `cli-chat-proxy.grok.com/v1`。** 写入的 auth 记录 `base_url` 指向 grok build 免费通道；若为空，CPA 会回退到计费通道 `api.x.ai/v1`，同样触发 `permission-denied`。

如果 CPA 里已有旧的失效号（`base_url=api.x.ai/v1` 或 `referrer=None`），用本节的独立转换脚本以相同邮箱重新生成一遍覆盖即可（文件名按 `xai-<email>.json` 命名，会原地覆盖）。

## 运行

### CLI

```bash
python grok_register_ttk.py cli
```

提示后输入 `start`。  
`Ctrl+C` 一次：当前账号收尾后停止；清理浏览器时不会因二次中断刷 traceback。再按一次强制退出。

### GUI

```bash
python grok_register_ttk.py
```

可在界面里改 CPA 开关、auth 目录、远程地址与管理密钥。

## 输出文件

| 文件 | 内容 |
| --- | --- |
| `accounts_*.txt` | 邮箱、密码、SSO |
| `mail_credentials.txt` | 临时邮箱凭证 |

均含敏感信息，已在 `.gitignore` 中忽略。`config.json` 也不提交，请用 `config.example.json` 复制。

## 稳定性

- 每账号结束后重启浏览器
- 每成功 5 个账号做一次内存清理
- 邮箱提交后确认页面前进，避免空等验证码
- 未收到验证码时换邮箱重试
- 最终页卡住时重试当前账号

## 常见问题

**CPA 没出现新账号**  
检查 `cpa_auto_add`、`cpa_auth_dir` 或 `cpa_remote_url` + `cpa_management_key`；看 `[CPA]` 日志是否换 token / 上传成功；本机/服务器能否访问 `auth.x.ai`。

**远程上传失败**  
确认 CPA 管理 API 已启用、密钥明文正确；远程访问需 `allow-remote: true`。可用：

```bash
curl -H "Authorization: Bearer <管理密钥>" \
  http://你的CPA地址:8317/v0/management/auth-files
```

`cpa_remote_url` 填 CPA 实例根地址，不要附带 OpenAI 兼容接口的 `/v1`。程序会自动追加 `/v0/management/auth-files`。

**创建 Cloudflare 邮箱时 curl 超时**

如果当前网络需要代理访问 `workers.dev`，请在 GUI 的“代理”字段或 `config.json` 的 `proxy` 中显式填写代理地址。不要只依赖终端的 `HTTP_PROXY` / `HTTPS_PROXY`，从桌面启动 GUI 时可能不会继承这些环境变量。

**开启 NSFW 时返回 403**

设置出生日期可能被 `grok.com` 的 Cloudflare 防护拦截。该步骤失败不会影响账号保存和 CPA 入库；不需要敏感内容时可关闭“注册后开启 NSFW”。

**CLI 为什么还开浏览器**  
CLI 只是不启动 Tk；注册页、Turnstile、SSO 仍依赖真实浏览器。

**NSFW 失败**  
常见为 Cloudflare 拦截。账号仍会保存并入库 CPA。

**国内服务器调模型超时**  
入库成功只说明凭证到了 CPA；调用上游 `cli-chat-proxy.grok.com` 还需服务器出网可达（或配置 CPA `proxy-url`）。

## 目录结构

```text
.
├── grok_register_ttk.py      # 主程序（GUI / CLI + CPA 入库）
├── sso_to_auth_json.py       # SSO → CPA 转换（可独立运行）
├── cf_mail_debug.py          # Cloudflare 邮箱调试
├── config.example.json
├── requirements.txt
├── tests/
└── assets/banner.png
```

## License

[MIT](LICENSE)

## Acknowledgments

Thanks to [linux.do](https://linux.do) and [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI).
