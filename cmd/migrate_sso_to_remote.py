#!/usr/bin/env python3
"""SSO -> auth-code flow -> remote CPA (same path as post-register import)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sso_to_auth_json import (  # noqa: E402
    convert_sso_entries,
    load_conversion_config,
    scan_sso_entries,
)


def main() -> int:
    scan_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT
    workers = 6
    if len(sys.argv) > 2:
        try:
            workers = max(1, min(int(sys.argv[2]), 8))
        except Exception:
            workers = 6
    entries, files = scan_sso_entries(scan_dir)
    cfg = load_conversion_config(scan_dir / "config.json")
    print(f"entries={len(entries)} files={len(files)} workers={workers}")
    print(
        f"remote={cfg.get('cpa_remote_url')!r} proxy={cfg.get('proxy')!r}",
        flush=True,
    )
    result = convert_sso_entries(
        entries,
        cpa_auth_dir=None,
        cpa_remote_url=str(cfg.get("cpa_remote_url") or ""),
        cpa_management_key=str(cfg.get("cpa_management_key") or ""),
        proxy=str(cfg.get("proxy") or ""),
        delay=0,
        workers=workers,
    )
    print("RESULT", result, flush=True)
    return 0 if result.get("fail", 0) == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
