"""
Screenshot service for individual findings.
Reuses Playwright infrastructure already present in the codebase.
Stores screenshots on disk keyed by (scan_id, finding_hash).
"""
import asyncio
import hashlib
import os
from pathlib import Path
from typing import Optional

from playwright.async_api import async_playwright

# Portable path
_PROJECT_ROOT = Path(os.environ.get('APP_ROOT', Path(__file__).resolve().parent.parent))
FINDING_SHOTS_DIR = Path(os.environ.get('FINDING_SHOTS_DIR', _PROJECT_ROOT / 'finding_screenshots'))
FINDING_SHOTS_DIR.mkdir(parents=True, exist_ok=True)


def finding_screenshot_path(scan_id: str, finding: dict) -> Path:
    h = hashlib.md5(
        f'{finding.get("type")}|{finding.get("url")}|{finding.get("param")}|{finding.get("payload","")[:50]}'.encode()
    ).hexdigest()[:16]
    return FINDING_SHOTS_DIR / f'{scan_id}_{h}.png'


async def capture_finding_screenshot(url: str, out_path: Path,
                                     timeout_ms: int = 15000,
                                     highlight_param: Optional[str] = None) -> bool:
    """Captures a screenshot of the vulnerable URL. Returns True on success."""
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-dev-shm-usage', '--disable-web-security'],
            )
            ctx = await browser.new_context(
                viewport={'width': 1440, 'height': 900},
                user_agent='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
                           '(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
                ignore_https_errors=True,
            )
            page = await ctx.new_page()
            try:
                await page.goto(url, timeout=timeout_ms, wait_until='domcontentloaded')
                await page.wait_for_timeout(1500)
                if highlight_param:
                    # Inject a red overlay banner at top so the screenshot clearly shows
                    # this URL was the vulnerable one.
                    await page.evaluate("""(param) => {
                      const div = document.createElement('div');
                      div.textContent = '⚠ CyberScope: vulnerable parameter = ' + param;
                      div.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:2147483647;' +
                        'background:#dc2626;color:#fff;padding:8px 16px;font:bold 14px monospace;' +
                        'text-align:center;box-shadow:0 2px 8px rgba(0,0,0,.4);';
                      document.body.prepend(div);
                    }""", highlight_param)
                    await page.wait_for_timeout(300)
                await page.screenshot(path=str(out_path), full_page=False, type='png')
                return True
            finally:
                await ctx.close()
                await browser.close()
    except Exception:
        return False


async def capture_findings_batch(scan_id: str, findings: list,
                                 max_screenshots: int = 20) -> dict:
    """
    Capture screenshots for the top findings (by severity/verified).
    Returns dict mapping finding_hash → path.
    """
    # Sort: verified first, then by severity
    sev_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
    sorted_findings = sorted(
        findings,
        key=lambda f: (0 if f.get('verified') else 1,
                       -sev_order.get((f.get('severity') or 'info'), 0))
    )[:max_screenshots]

    results = {}
    sem = asyncio.Semaphore(3)  # limit concurrency

    async def _grab(f):
        async with sem:
            url = f.get('url')
            if not url or not url.startswith(('http://', 'https://')):
                return
            path = finding_screenshot_path(scan_id, f)
            if path.exists():
                results[path.stem] = str(path)
                return
            ok = await capture_finding_screenshot(url, path,
                                                   highlight_param=f.get('param'))
            if ok:
                results[path.stem] = str(path)

    await asyncio.gather(*[_grab(f) for f in sorted_findings], return_exceptions=True)
    return results
