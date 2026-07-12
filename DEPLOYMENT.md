# 本机部署

以下步骤使用 Python 3.13 在仓库内创建 `.venv` 隔离环境。

## 启动

- 图形界面：双击 `start-gui.cmd`
- 命令行：双击 `start-cli.cmd`，输入 `start` 后开始任务

## 首次使用前配置

编辑 `config.json`，至少填写可用的临时邮箱配置：

- Cloudflare：`cloudflare_api_base`、`defaultDomains`，必要时填写认证配置
- DuckMail：将 `email_provider` 改为 `duckmail` 并填写 `duckmail_api_key`
- YYDS：将 `email_provider` 改为 `yyds` 并填写 `yyds_api_key` 或 `yyds_jwt`

如需自动写入 CLIProxyAPI，再配置 `cpa_auto_add` 及本地 auth 目录或远程 Management API 参数。

## 重新安装依赖

```powershell
uv python install 3.13
uv venv --python 3.13 .venv
uv pip install --python .venv\Scripts\python.exe -r requirements.txt
```

运行环境还需要安装 Chrome 或 Chromium。
