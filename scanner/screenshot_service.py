"""
Screenshot service — captures screenshots of live subdomains using Playwright.
"""
import asyncio
import base64
import hashlib
import os
from pathlib import Path
from typing import Optional


# Portable — env var overrides, else two levels up from this file (scanner/ -> project root)
_PROJECT_ROOT = Path(os.environ.get('APP_ROOT', Path(__file__).resolve().parent.parent))
SCREENSHOTS_DIR = Path(os.environ.get('SCREENSHOTS_DIR', _PROJECT_ROOT / 'scan_screenshots'))
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)


async def take_screenshot(url: str, output_path: Optional[str] = None,
                          timeout: int = 20, viewport_w: int = 1280,
                          viewport_h: int = 720) -> Optional[str]:
    """
    Take screenshot of URL and return path.
    Returns None if playwright unavailable or timeout.
    """
    try:
        from playwright.async_api import async_playwright  # type: ignore
    except ImportError:
        return None

    if not output_path:
        h = hashlib.sha1(url.encode()).hexdigest()[:16]
        output_path = str(SCREENSHOTS_DIR / f'{h}.png')

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True,
                args=['--no-sandbox', '--disable-dev-shm-usage'])
            ctx = await browser.new_context(
                viewport={'width': viewport_w, 'height': viewport_h},
                ignore_https_errors=True,
                user_agent='Mozilla/5.0 TakeoverScanner/5.0',
            )
            page = await ctx.new_page()
            try:
                await page.goto(url, wait_until='domcontentloaded', timeout=timeout * 1000)
                await page.wait_for_timeout(1500)
                await page.screenshot(path=output_path, full_page=False, quality=40, type='jpeg' if output_path.endswith('.jpg') or output_path.endswith('.jpeg') else None)
            except Exception:
                # Try again with less strict wait
                try:
                    await page.screenshot(path=output_path, full_page=False)
                except Exception:
                    return None
            finally:
                await ctx.close()
                await browser.close()
        return output_path if os.path.exists(output_path) else None
    except Exception:
        return None


def take_screenshot_sync(url: str, output_path: Optional[str] = None, timeout: int = 20) -> Optional[str]:
    """Synchronous wrapper."""
    try:
        return asyncio.run(take_screenshot(url, output_path, timeout))
    except RuntimeError:
        # Event loop already running (called from async context)
        return None


def get_screenshot_url(scan_id: str, subdomain: str, api_base: str = '/api') -> str:
    return f'{api_base}/scans/{scan_id}/screenshots/{subdomain}'


def screenshot_path_for(scan_id: str, subdomain: str) -> Path:
    h = hashlib.sha1(f'{scan_id}:{subdomain}'.encode()).hexdigest()[:16]
    return SCREENSHOTS_DIR / f'{scan_id}_{h}.png'
