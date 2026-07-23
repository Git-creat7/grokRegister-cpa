#!/usr/bin/env python3
"""Mint Cloudflare Turnstile token via Playwright + CloakBrowser binary.

Same inject/click/poll path as grok_register/register.py (original project):
  playwright.chromium.launch(executable_path=find_chrome(), ...)

Usage:
  turnstile_mint.py --site-key KEY [--url URL] [--proxy URL] [--chrome PATH]
                    [--cookie 'a=b; c=d'] [--ua UA] [--timeout 90]

Prints only the token to stdout on success; errors to stderr, exit 1.
"""
from __future__ import annotations

import argparse
import asyncio
import glob
import os
import sys
import time


def find_chrome() -> str:
    env = (os.environ.get("CHROME_PATH") or "").strip()
    if env and os.path.exists(env):
        return env
    homes = []
    h = os.path.expanduser("~")
    if h:
        homes.append(h)
    homes.extend(["/root", "/home/charles"])
    matches: list[str] = []
    for home in homes:
        base = os.path.join(home, ".cloakbrowser")
        matches.extend(glob.glob(os.path.join(base, "chromium-*/chrome")))
        matches.extend(
            glob.glob(
                os.path.join(
                    base,
                    "chromium-*/Chromium.app/Contents/MacOS/Chromium",
                )
            )
        )
    if matches:
        return sorted(matches)[-1]
    # Windows Chrome / Edge
    localapp = os.environ.get("LOCALAPPDATA") or ""
    pf = os.environ.get("PROGRAMFILES") or r"C:\Program Files"
    pf86 = os.environ.get("PROGRAMFILES(X86)") or r"C:\Program Files (x86)"
    for p in (
        os.path.join(pf, "Google", "Chrome", "Application", "chrome.exe"),
        os.path.join(pf86, "Google", "Chrome", "Application", "chrome.exe"),
        os.path.join(localapp, "Google", "Chrome", "Application", "chrome.exe") if localapp else "",
        os.path.join(pf, "Microsoft", "Edge", "Application", "msedge.exe"),
    ):
        if p and os.path.exists(p):
            return p
    for p in (
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    ):
        if os.path.exists(p):
            return p
    return ""


def parse_cookie_header(raw: str) -> list[dict]:
    out: list[dict] = []
    for part in (raw or "").split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, val = part.split("=", 1)
        name, val = name.strip(), val.strip()
        if not name or name.lower() in {"sso", "sso-rw"}:
            continue
        out.append(
            {
                "name": name,
                "value": val,
                "domain": ".x.ai",
                "path": "/",
            }
        )
    return out


async def mint(
    site_key: str,
    page_url: str,
    proxy: str,
    chrome: str,
    cookies: list[dict],
    timeout: float,
    ua: str,
    headless: bool = False,
) -> str:
    from playwright.async_api import async_playwright

    # 真 headless 易被 CF 拦；默认有界面但屏外/最小化
    env_headless = (os.environ.get("GROK_TURNSTILE_HEADLESS") or "").strip().lower()
    if env_headless in ("1", "true", "yes", "on"):
        headless = True
    elif env_headless in ("0", "false", "no", "off"):
        headless = False
    args = [
        "--no-sandbox",
        "--disable-blink-features=AutomationControlled",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-infobars",
        "--disable-dev-shm-usage",
    ]
    if not headless:
        args.extend(
            [
                "--window-position=-32000,-32000",
                "--window-size=800,600",
                "--start-minimized",
            ]
        )
    launch: dict = {
        "executable_path": chrome,
        "headless": bool(headless),
        "args": args,
    }
    if proxy:
        # Playwright accepts {"server": "http://..."}
        launch["proxy"] = {"server": proxy}

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(**launch)
        try:
            ctx_kwargs: dict = {"viewport": {"width": 800, "height": 600}}
            if ua:
                ctx_kwargs["user_agent"] = ua
            context = await browser.new_context(**ctx_kwargs)
            await context.add_init_script(
                'Object.defineProperty(navigator,"webdriver",{get:()=>undefined})'
            )
            if cookies:
                for c in cookies:
                    try:
                        await context.add_cookies(
                            [
                                {
                                    "name": c["name"],
                                    "value": c["value"],
                                    "domain": c.get("domain") or ".x.ai",
                                    "path": c.get("path") or "/",
                                }
                            ]
                        )
                    except Exception:
                        try:
                            await context.add_cookies(
                                [
                                    {
                                        "name": c["name"],
                                        "value": c["value"],
                                        "url": "https://accounts.x.ai/",
                                        "path": "/",
                                    }
                                ]
                            )
                        except Exception:
                            pass

            page = await context.new_page()
            await page.goto(page_url, timeout=45000, wait_until="domcontentloaded")
            await page.wait_for_timeout(1500)

            # Exact inject from grok_register/register.py _inject_turnstile_widget
            inject = (
                "var d=document.createElement('div');"
                "d.className='cf-turnstile';"
                f"d.setAttribute('data-sitekey','{site_key}');"
                "d.style.cssText='position:fixed;top:10px;left:10px;z-index:99999;"
                "background:white;padding:12px;border:2px solid red;border-radius:6px;"
                "width:300px;height:70px';"
                "document.body.appendChild(d);"
                "function __r(){"
                "window.turnstile&&window.turnstile.render(d,{"
                f"sitekey:'{site_key}',"
                "callback:function(t){"
                'var i=document.querySelector(\'input[name="cf-turnstile-response"]\');'
                "if(!i){i=document.createElement('input');i.type='hidden';"
                "i.name='cf-turnstile-response';document.body.appendChild(i);}"
                "i.value=t;"
                "}})}"
                "if(window.turnstile){__r()}"
                "else{var s=document.createElement('script');"
                "s.src='https://challenges.cloudflare.com/turnstile/v0/api.js';"
                "s.onload=function(){setTimeout(__r,1000)};"
                "document.head.appendChild(s);}"
            )
            await page.evaluate(inject)

            initial_ms = int(os.environ.get("SOLVER_INITIAL_WAIT_MS", "500") or "500")
            await page.wait_for_timeout(max(0, initial_ms))

            async def read_token() -> str:
                try:
                    return await page.evaluate(
                        'document.querySelector(\'input[name="cf-turnstile-response"]\')?.value||""'
                    )
                except Exception:
                    return ""

            for _ in range(2):
                t = await read_token()
                if t and len(t) > 10:
                    return t
                await page.wait_for_timeout(800)

            async def click_center() -> None:
                box = await page.evaluate(
                    """() => {
                    const e = document.querySelector('.cf-turnstile');
                    if (!e) return null;
                    const r = e.getBoundingClientRect();
                    return {x: r.left + r.width / 2, y: r.top + r.height / 2};
                }"""
                )
                if not box:
                    return
                x, y = float(box["x"]), float(box["y"])
                await page.mouse.move(max(0, x - 25), max(0, y - 8))
                await page.mouse.move(x, y, steps=8)
                await page.mouse.down()
                await asyncio.sleep(0.05)
                await page.mouse.up()

            retries = int(os.environ.get("SOLVER_MOUSE_CLICK_RETRIES", "3") or "3")
            interval = int(os.environ.get("SOLVER_MOUSE_CLICK_INTERVAL_MS", "600") or "600")
            for i in range(max(0, retries)):
                t = await read_token()
                if t and len(t) > 10:
                    return t
                try:
                    await click_center()
                except Exception:
                    pass
                if i + 1 < retries:
                    await page.wait_for_timeout(max(50, interval))

            poll_ms = int(os.environ.get("SOLVER_POLL_INTERVAL_MS", "500") or "500")
            attempts = int(os.environ.get("SOLVER_POLL_ATTEMPTS", "100") or "100")
            deadline = time.time() + timeout
            for i in range(max(1, attempts)):
                if time.time() > deadline:
                    break
                await page.wait_for_timeout(max(50, poll_ms))
                t = await read_token()
                if t and len(t) > 10:
                    return t
                if i > 0 and i % 20 == 0:
                    try:
                        await click_center()
                    except Exception:
                        pass

            try:
                diag = await page.evaluate(
                    """() => {
                    const ifr=[...document.querySelectorAll('iframe')].filter(f=>{
                      const s=f.src||'';
                      return s.includes('turnstile')||s.includes('challenges.cloudflare.com');
                    }).length;
                    return {
                      iframes: ifr,
                      all_ifr: document.querySelectorAll('iframe').length,
                      widget: !!document.querySelector('.cf-turnstile'),
                      turnstile: !!window.turnstile,
                      title: document.title||'',
                    };
                }"""
                )
                print(f"diag={diag}", file=sys.stderr)
            except Exception:
                pass
            raise RuntimeError("turnstile timeout (no token)")
        finally:
            await browser.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--site-key", required=True)
    ap.add_argument("--url", default="https://accounts.x.ai/sign-up")
    ap.add_argument("--proxy", default="")
    ap.add_argument("--chrome", default="")
    ap.add_argument("--cookie", default="")
    ap.add_argument("--ua", default="")
    ap.add_argument("--timeout", type=float, default=90)
    ap.add_argument("--headless", action="store_true", default=False)
    ap.add_argument("--no-headless", action="store_true", default=False)
    args = ap.parse_args()

    chrome = args.chrome.strip() or find_chrome()
    if not chrome:
        print("chrome not found", file=sys.stderr)
        return 1
    cookies = parse_cookie_header(args.cookie)
    headless = bool(args.headless) and not bool(args.no_headless)
    try:
        token = asyncio.run(
            mint(
                site_key=args.site_key,
                page_url=args.url,
                proxy=args.proxy.strip(),
                chrome=chrome,
                cookies=cookies,
                timeout=args.timeout,
                ua=args.ua.strip(),
                headless=headless,
            )
        )
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    if not token or len(token) <= 10:
        print("empty token", file=sys.stderr)
        return 1
    sys.stdout.write(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
