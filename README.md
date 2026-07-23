<div align="center">

[![Grok Register — 注册即入库 CLIProxyAPI](assets/banner.png)](https://github.com/Git-creat7/grokRegister-cpa)

批量注册 Grok 账号，注册成功后自动把 OAuth 凭证写入 [CLIProxyAPI (CPA)](https://github.com/router-for-me/CLIProxyAPI)：支持本地 auth 目录热加载，也支持 Management API 远程上传。

<p>
  <a href="https://github.com/Git-creat7/grokRegister-cpa/stargazers"><img src="https://img.shields.io/github/stars/Git-creat7/grokRegister-cpa?style=flat&logo=github" alt="GitHub stars"></a>
  <a href="https://github.com/Git-creat7/grokRegister-cpa/network/members"><img src="https://img.shields.io/github/forks/Git-creat7/grokRegister-cpa?style=flat&logo=github" alt="GitHub forks"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/Python-3.9%2B-3776AB.svg" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/Interface-GUI%20%2B%20CLI-success.svg" alt="GUI + CLI">
  <img src="https://img.shields.io/badge/Output-CLIProxyAPI-orange.svg" alt="CLIProxyAPI">
</p>

</div>

---

> 仅用于自动化流程研究、测试环境验证和个人学习。请遵守目标网站服务条款、当地法律法规与第三方服务限制。

## 核心流程

**默认：协议 HTTP 注册**（`register_mode=protocol`，不打开注册页）：

```text
Fetch signup config（进程内缓存）
   → Turnstile mint（屏外 headed Chrome）∥ 建邮 + 发码 + 等码
   → VerifyEmailCode → SignupServerAction → SSO
   → Device Authorization Flow 换 OAuth（无 referrer / 无 bot_flag）
   → 本地 cpa_auth_dir 和/或 远程 CPA Management API
   → probe cli-chat-proxy.grok.com 测活
```

批量（`count≥2`）走 **S/P/C/O 流水线**：S 预 mint、P 建邮等码、C 注册出 SSO、O 做 CPA/写盘；阶段重叠提高吞吐。

可选：`register_mode=browser` 回退旧 UI 注册页（易带 `bot_flag_source`，测活可能 402）。

## 功能

- **协议 HTTP 注册**（默认）：无注册页浏览器；Turnstile 仅屏外 mint；健康 JWT（无 `referrer` / 无 `bot_flag`）
- 批量 **S/P/C/O 流水线** + 进程内 signup config 缓存 + 单号 Turnstile∥建邮并行
- 注册成功后自动入库 CPA（本地目录 / 远程 Management API，可同时开）
- GUI + CLI；Device Flow 换 token（不再强制 `referrer=grok-build`）
- DuckMail / YYDS / Cloudflare / MailNest（Outlook）/ CloudMail 临时邮箱
- 可选 NSFW：批内**纯 HTTP 后台队列**（不冷启浏览器、不抢 Turnstile 代理）；失败进 `nsfw_pending.txt`，可用 `cmd/retry_pending_nsfw.py` 离线补开
- 页面卡住重试、验证码失败换邮箱；browser 模式仍支持浏览器重启与内存清理
- CLI：一次 `Ctrl+C` 安全停止，清理阶段不刷 traceback；再按一次强制中断

## 环境要求

- Python 3.9+
- Google Chrome 或 Chromium（协议模式仅用于 Turnstile mint；NSFW 批内默认不开浏览器）
- 可用的 [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)
- 能访问 `accounts.x.ai`、临时邮箱 API、`auth.x.ai` / `cli-chat-proxy.grok.com` 的网络

## 安装

```bash
git clone https://github.com/Git-creat7/grokRegister-cpa.git
cd grokRegister-cpa
pip install -r requirements.txt
cp config.example.json config.json
```

编辑 `config.json` 后运行。

### Windows 一键启动

1. 按 [DEPLOYMENT.md](DEPLOYMENT.md) 用 Python 3.13 创建 `.venv` 并安装依赖
2. 双击 `start-gui.cmd` 开图形界面，或 `start-cli.cmd` 开命令行（输入 `start` 开始）

### macOS 一键启动

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp config.example.json config.json
```

双击 `start-gui.command` 开图形界面，或 `start-cli.command` 开命令行（输入 `start` 开始）。若通过压缩包下载后丢失可执行权限，先运行 `chmod +x start-*.command`。

## 配置

| 配置项 | 说明 |
| --- | --- |
| `register_mode` | `protocol`（默认，HTTP 协议注册）/ `browser`（旧 UI 注册页） |
| `cpa_auto_add` | 是否注册后 SSO→CPA auth（关则只保存 SSO） |
| `register_workers` | 并发度上限（协议流水线会映射到 P/C/O 等）；browser 模式为浏览器数，默认 1，最大 8 |
| `log_level` | `info`（默认，隐藏 `[Debug]`）/ `debug`（全量日志） |
| `cpa_auth_dir` | 本地 CPA auth 目录；写入 `xai-<email>.json`，可留空 |
| `cpa_remote_url` | 远程 CPA 地址，如 `http://你的CPA地址:8317` |
| `cpa_management_key` | 远程 CPA 管理密钥（`remote-management.secret-key` 明文） |
| `email_provider` | `duckmail` / `yyds` / `cloudflare` / `mailnest` / `cloudmail` / `outlook` |
| `outlook_accounts_file` | Outlook OAuth2 账号文件路径，支持 TXT/JSON；默认 `outlook_accounts.json` |
| `duckmail_api_base` | DuckMail/Mail.tm API 根地址，默认 `https://api.duckmail.sbs`；Mail.tm 填 `https://api.mail.tm` |
| `duckmail_api_key` | DuckMail API Key（`dk_...`）；Mail.tm 公共接口可不填 |
| `mailnest_api_key` | MailNest（迈巢 Outlook）API Key |
| `mailnest_project_code` | MailNest 项目代码，默认 `x-ai001` |
| `yyds_default_domain` | YYDS 固定收信域名；留空则自动选择已验证域名 |
| `cloudmail_url` | CloudMail 站点根地址，不要附加 `/api` |
| `cloudmail_admin_email` | CloudMail 管理员邮箱；也可用环境变量 `CLOUDMAIL_ADMIN_EMAIL` |
| `cloudmail_password` | CloudMail 管理员密码；也可用环境变量 `CLOUDMAIL_PASSWORD` |
| `register_count` | 目标注册数量 |
| `proxy` | 代理；换 token 的 OAuth 请求也走此代理 |
| `enable_nsfw` | 是否在注册过程中后台开启 NSFW，并在批次结束前等待本批结果 |
| `cloudflare_api_base` | Cloudflare 临时邮箱 API 根地址 |
| `cloudflare_api_key` | 默认匿名模式留空；admin 模式填 `ADMIN_PASSWORD` |
| `cloudflare_auth_mode` | `none` / `bearer` / `x-api-key` / `x-admin-auth` / `query-key` |
| `cloudflare_custom_auth` | Worker 全局密码（`PASSWORDS`），注入 `x-custom-auth` |
| `cloudflare_path_*` | domains / accounts / token / messages 路径 |
| `cloudflare_random_subdomain` | 是否创建 `user@随机子域.主域`（需 Worker `RANDOM_SUBDOMAIN_DOMAINS` 包含该主域） |
| `defaultDomains` | Cloudflare / CloudMail 默认收信域名，多个用逗号分隔 |

### 注册模式 / 并发 / NSFW

**`register_mode`**

- `protocol`（默认）：HTTP 协议注册；不打开注册页；Turnstile 仅屏外 mint
- `browser`：旧 UI 注册页（易打上 `bot_flag_source`，probe 可能 402）
- 环境变量覆盖：`GROK_REGISTER_MODE=protocol|browser`

**协议批量流水线（S/P/C/O）**

- `count≥2` 且 `register_mode=protocol` 时默认启用；`count=1` 走单号并行（Turnstile ∥ 建邮等码）
- `GROK_PROTOCOL_PIPELINE=0` 强制关闭流水线；`=1` 时单号也可进流水线
- signup config 进程内缓存，TTL 默认 1200s（`GROK_SIGNUP_CFG_TTL`）

**并发 `register_workers`**

- 协议模式：映射到流水线 P/C/O 等 worker 上限，Turnstile mint 默认 phys=1
- browser 模式：每个 worker 独立 Chrome 用户目录；实际并发不超过注册数量

**连通性检查**

- GUI「连通性检查」或开始注册前自动跑
- 检查项：代理 TCP/出站、邮箱 API、CPA 本地目录/远程 Management API
- 失败默认只警告，不强制拦截开跑

**NSFW**

- SSO 保存后进入单后台队列，不阻塞 CPA 与后续注册
- **批内默认纯 HTTP**（`set_tos` → `set_birth` → `update_nsfw`），不冷启浏览器，避免与 Turnstile 抢代理
- 失败保留 `nsfw_pending.txt`；离线补开：`python cmd/retry_pending_nsfw.py`（可开浏览器）
- 追求最快注册且不需要敏感内容时，可关 `enable_nsfw`

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

### MailNest（Outlook 临时邮箱）

[迈巢 MailNest](https://mailnest.top/) 采用项目制。配置 API Key 与项目代码（默认 `x-ai001`）：

```json
{
  "email_provider": "mailnest",
  "mailnest_api_key": "你的 API Key",
  "mailnest_project_code": "x-ai001"
}
```

- API Key：https://mailnest.top/account  
- 项目代码：https://mailnest.top/buy-email（默认可直接用 `x-ai001`）

### YYDS 邮箱固定域名

默认自动选择已验证域名。若要固定收信域名：

```json
{
  "email_provider": "yyds",
  "yyds_default_domain": "你的收信域名.com"
}
```

GUI「YYDS 收信域名」可填；留空则自动选择。

### CloudMail 邮箱

支持自建 [maillab/cloud-mail](https://github.com/maillab/cloud-mail)。程序用管理员接口创建随机地址，公开接口收信，结束后删除地址：

```json
{
  "email_provider": "cloudmail",
  "cloudmail_url": "https://mail.example.com",
  "cloudmail_admin_email": "admin@example.com",
  "cloudmail_password": "你的管理员密码",
  "defaultDomains": "example.com"
}
```

`cloudmail_url` 填站点根地址，不要附加 `/api`。也可用环境变量 `CLOUDMAIL_URL` / `CLOUDMAIL_ADMIN_EMAIL` / `CLOUDMAIL_PASSWORD`（优先于 config）。

### Outlook OAuth2（Microsoft Graph）

使用自有 Outlook OAuth2 账号接收验证码。程序用 `client_id` 和 `refresh_token` 换取 Microsoft Graph access token，再读取当前账号的新邮件；每个注册任务持有独立账号租约，并发时不会串号。

TXT 每行一个账号：

```text
email----password----client_id----refresh_token
```

`password` 仅兼容原始 auth 格式，解析后会被丢弃，不参与 Graph 收信，也不会写入导出的 JSON。账号也可使用 `outlook_oauth2.example.json` 所示的 JSON 格式。

**GUI 用法**

1. 邮箱服务商选择 `outlook`
2. 点击「粘贴账号」直接粘贴多行 auth，或点击「选择 TXT/JSON」导入文件
3. 可先点击「测试 Outlook 连接」，再设置注册数量和并发数开始注册

粘贴导入会生成不含密码的 `outlook_accounts.json`；该文件包含 refresh token，已默认加入 `.gitignore`。

**CLI 用法**

在 `config.json` 中指定 TXT 或 JSON 账号文件：

```json
{
  "email_provider": "outlook",
  "outlook_accounts_file": "outlook_accounts.txt",
  "register_count": 5,
  "register_workers": 5
}
```

运行 `start-cli.command`（macOS）或 `start-cli.cmd`（Windows），输入 `start`。GUI 和 CLI 都使用 `register_workers` 控制并发，实际并发不超过注册数量和项目上限 8；注册数量不能超过导入的有效 Outlook 账号数。成功取得 SSO 后继续使用原项目的 NSFW 与 CPA 入库流程。

## CPA 自动入库

SSO 不是 CPA 凭据。程序会：

1. 用 SSO 走 **Device Authorization Flow** 向 `auth.x.ai` 换 `access_token` / `refresh_token`（**不**注入 `referrer` / `plan`，健康号 JWT 无这些 claim）
2. 组装 `type=xai` 扁平 auth（`cli-chat-proxy.grok.com`）
3. 本地：`cpa_auth_dir` → `xai-<email>.json`（CPA 热加载）
4. 远程：`POST {cpa_remote_url}/v0/management/auth-files?name=...`（需管理密钥）
5. 可选 probe：`cli-chat-proxy.grok.com/v1/responses` 测活（HTTP 200 为健康）

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

#### GUI 补转

注册任务停止时，点击主界面的 **补转缺失 SSO**。程序会在仓库目录扫描全部 `accounts_*.txt` 和 `sso_pending.txt`，按邮箱去重，再与远程 CPA 的已有邮箱比较，只转换远程缺失的账号。转换在后台线程运行，不会卡住界面；点击“停止”会在当前账号完成后停止补转。

#### Python 自动扫描

在仓库目录直接运行，无需指定 TXT：

```bash
python sso_to_auth_json.py
```

程序会自动读取当前目录的 `config.json`，扫描 `accounts_*.txt` 与 `sso_pending.txt`。也可指定其他目录和配置：

```bash
python sso_to_auth_json.py --scan-dir /path/to/register-output \
  --config /path/to/register-output/config.json
```

只扫描上述账号文件，不会读取 `requirements.txt`、`mail_credentials.txt` 或其他无关 TXT。

#### 显式指定文件

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

`sso_list.txt`：一行一个 SSO、`邮箱----sso`，或 `邮箱----密码----sso`。

配置了远程 CPA 时，批量转换以远程 Management API 返回的邮箱为唯一判重来源：本地 TXT 有、远程 CPA 没有的账号才会转换。没有配置远程 CPA 时，才回退到本地有效 auth JSON 判重。TXT 内重复邮箱也会先去重。

### 为什么用 Device Flow（健康号）

当前默认与测活策略（相对旧版授权码 + `referrer=grok-build`）：

- **SSO 不能直接喂给 CPA。** 需要 `access_token` / `refresh_token`；SSO 只是换 token 的入场券。
- **健康号 JWT 无 `referrer`、无 `bot_flag_source`。** UI 注册页路径容易打上 `bot_flag_source=1`，probe 常 402；协议注册 + Device Flow 出号更稳。
- **不再强制 `referrer=grok-build`。** 旧说明要求授权码注入该 claim；现网健康样式为 `referrer=None`，日志会打印 `access_token 无 referrer（健康样式）`。
- **base_url 仍用 `cli-chat-proxy.grok.com/v1`。** 指向 grok build 免费通道；勿写成空或误指 `api.x.ai/v1`。
- **协议注册避免 bot flag。** `register_mode=protocol` 不走注册页浏览器，降低被标 bot 的概率。

若 CPA 里仍是旧失效号（错误 `base_url`、异常 claim），用独立转换脚本同邮箱重转覆盖 `xai-<email>.json` 即可。

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

可在界面里改：邮箱服务商、代理、Cloudflare（API Base / 鉴权 / 收信域名 / 全局密码）、CPA 开关、auth 目录、远程地址与管理密钥。点击「开始注册」时会写回 `config.json`。

## 输出文件

| 文件 | 内容 |
| --- | --- |
| `accounts_*.txt` | 邮箱、密码、SSO |
| `mail_credentials.txt` | 临时邮箱凭证 |
| `nsfw_pending.txt` | NSFW 未成功的邮箱----SSO（可离线补开） |
| `sso_pending.txt` | CPA 入库失败待重转的 SSO |
| `log/app_*.log` | 每次运行的应用日志 |

均含敏感信息，已在 `.gitignore` 中忽略。`config.json` 也不提交，请用 `config.example.json` 复制。

## 稳定性

- 协议模式：config 缓存、Turnstile 失败重试、curl_cffi TLS impersonate 降级
- browser 模式：每账号后可重启浏览器；每成功 5 个做内存清理
- 未收到验证码时换邮箱重试；流水线 Q/token 有 TTL，过期丢弃重取
- Device Flow 限流（HTTP 429 `slow_down`）时 SSO 仍写入 accounts / `sso_pending.txt`，可稍后补转

## 常见问题

**CPA 没出现新账号**  
检查 `cpa_auto_add`、`cpa_auth_dir` 或 `cpa_remote_url` + `cpa_management_key`；看 `[CPA]` 日志是否 Device Flow 换 token / 上传成功；本机/服务器能否访问 `auth.x.ai`。

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

`set_birth_date` 可能被 `grok.com` Cloudflare 拦截。批内只走 HTTP，失败进 `nsfw_pending.txt`，**不影响**账号保存与 CPA。离线补开：`python cmd/retry_pending_nsfw.py`。不需要敏感内容可关 `enable_nsfw`。

**协议模式还会开浏览器吗**  
会短暂开 **屏外 headed Chrome** 做 Turnstile mint（真 headless 易被 CF 拦）。注册页本身不打开。批内 NSFW 默认不再开浏览器。

**NSFW 失败**  
常见为 Cloudflare 拦 `set_birth_date`。账号仍会保存并入库 CPA，失败保留到 `nsfw_pending.txt`。

**国内服务器调模型超时**  
入库成功只说明凭证到了 CPA；调用上游 `cli-chat-proxy.grok.com` 还需服务器出网可达（或配置 CPA `proxy-url`）。

**CPA 返回 `503 auth_unavailable: no auth available`**  
不是网络超时，而是 CPA 当前没有可用的 xAI auth。检查：auth 是否写入并被热加载、probe 是否 200、账号是否 403/429。free 号走 `cli-chat-proxy` build 通道，额度由上游控制。

**chat 报 `permission-denied` 或 probe 402**  
常见原因：UI 路径带 `bot_flag_source`、错误 `base_url`（应指向 `cli-chat-proxy.grok.com`）、或旧 claim 组合。优先用 **协议注册 + Device Flow** 重注册/重转覆盖 `xai-<email>.json`。

**Device Flow 报 `slow_down` / 429**  
短时间 device code 请求过多。SSO 已在 accounts / pending，稍后 `python sso_to_auth_json.py` 补转即可；适当降低并发或错开 O 阶段。

## 目录结构

```text
.
├── grok_register_ttk.py      # 主程序（GUI / CLI + CPA 入库）
├── protocol_signup.py        # 协议 HTTP 注册 / config 缓存 / mint∥建邮
├── protocol_pipeline.py      # 批量 S/P/C/O 流水线
├── scripts/turnstile_mint.py # Turnstile 屏外 mint
├── browser_session.py        # 浏览器启停 / cf_clearance
├── register_flow.py          # browser 模式注册页填表 / 验证码 / SSO
├── connectivity.py           # 启动前连通性检查
├── nsfw_retry.py             # NSFW pending 队列
├── cmd/retry_pending_nsfw.py # 离线补开 NSFW
├── email_providers/
│   ├── common.py
│   ├── duckmail.py
│   ├── cloudflare.py
│   ├── yyds.py
│   ├── mailnest.py
│   └── cloudmail.py
├── sso_to_auth_json.py       # SSO → CPA（Device Flow，可独立运行）
├── cf_mail_debug.py
├── config.example.json
├── requirements.txt
├── start-gui.cmd
├── start-cli.cmd
├── start-gui.command
├── start-cli.command
├── DEPLOYMENT.md
├── tests/
└── assets/banner.png
```

## Star History

<a href="https://www.star-history.com/?type=date&repos=Git-creat7%2FgrokRegister-cpa">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=Git-creat7/grokRegister-cpa&type=date&theme=dark&legend=top-left&sealed_token=nLCws8QCmosQswlx1hTjASUcz8r72ZEKXOP1C8WmTFqosF65NL66q77qlMIbBZ6Kqic0cOqA5VisinVcERXNFlwMZqx0ET8872ALY3-k8rvCyvNqa-RxzMLV_oOrrAV54D0E6Pfv4WWTmaA6WYQBr2U5dizobLbasNLXpKTnZZJI7-uRL0zomGISzIGq" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=Git-creat7/grokRegister-cpa&type=date&legend=top-left&sealed_token=nLCws8QCmosQswlx1hTjASUcz8r72ZEKXOP1C8WmTFqosF65NL66q77qlMIbBZ6Kqic0cOqA5VisinVcERXNFlwMZqx0ET8872ALY3-k8rvCyvNqa-RxzMLV_oOrrAV54D0E6Pfv4WWTmaA6WYQBr2U5dizobLbasNLXpKTnZZJI7-uRL0zomGISzIGq" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=Git-creat7/grokRegister-cpa&type=date&legend=top-left&sealed_token=nLCws8QCmosQswlx1hTjASUcz8r72ZEKXOP1C8WmTFqosF65NL66q77qlMIbBZ6Kqic0cOqA5VisinVcERXNFlwMZqx0ET8872ALY3-k8rvCyvNqa-RxzMLV_oOrrAV54D0E6Pfv4WWTmaA6WYQBr2U5dizobLbasNLXpKTnZZJI7-uRL0zomGISzIGq" />
 </picture>
</a>

## License

[MIT](LICENSE)

## Acknowledgments

Thanks to [linux.do](https://linux.do) and [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI).
