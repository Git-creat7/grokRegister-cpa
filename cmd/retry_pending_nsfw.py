#!/usr/bin/env python3
"""自用：串行补开 nsfw_pending.txt 中的账号。"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import grok_register_ttk as app  # noqa: E402
from nsfw_retry import load_pending_entries  # noqa: E402


def main() -> int:
    app.load_config()
    app._wire_runtime_modules(gui_mode=False)
    # 离线补开允许浏览器；注册批内默认 allow_browser=False 避免抢代理
    worker = app.create_nsfw_retry_worker(
        log_callback=print, idle_timeout=1.0, allow_browser=True
    )
    total = worker.start_existing()
    print(f"[NSFW] pending={total} file={app.NSFW_PENDING_FILE}", flush=True)
    if not total:
        return 0
    try:
        summary = worker.finish()
    except KeyboardInterrupt:
        summary = worker.cancel(wait=True, timeout=app.NSFW_CANCEL_TIMEOUT)
        print("[NSFW] 用户停止，未完成账号仍保留在 pending", flush=True)
        return 130

    remaining = load_pending_entries(app.NSFW_PENDING_FILE)
    print(
        f"[NSFW] 成功={summary['succeeded']} 失败={summary['failed']} "
        f"未尝试={summary['cancelled']} 剩余={len(remaining)}",
        flush=True,
    )
    return 0 if not remaining else 1


if __name__ == "__main__":
    raise SystemExit(main())
