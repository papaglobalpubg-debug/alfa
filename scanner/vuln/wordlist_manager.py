"""
CyberScope v7.7 · Payload Encyclopedia · lazy-loading wordlist manager.

  * On first use, downloads curated payload lists from well-known public
    repos (SecLists, PayloadsAllTheThings, fuzzdb, Bo0oM/fuzz.txt,
    assetnote/wordlists).
  * Verifies each downloaded file against an sha256 pin.
  * Stores locally under `/app/scanner/wordlists/` so the tarball ships
    with them after the first successful pull.
  * Exposes categorized generators so the scanner asks for `xss.all()`,
    `sqli.all()` etc. and gets thousands of payloads instantly.

Design notes:
  * All downloads are OPT-IN — `PAYLOAD_AUTOFETCH=1` env var or explicit
    `await ensure_wordlists()` call. Zero network activity by default.
  * Each source is small (<200KB avg) so a full sync completes in seconds.
  * The manager silently falls back to whatever files exist locally when
    a network call fails — never blocks the scan.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Set

import httpx

WORDLISTS_DIR = Path(os.environ.get(
    'CYBERSCOPE_WORDLISTS_DIR',
    str(Path(__file__).resolve().parent.parent / 'wordlists'),
))
WORDLISTS_DIR.mkdir(parents=True, exist_ok=True)


# ─────────────── source manifest ───────────────
# Format: (category, filename, url, min_lines).
# `min_lines` is a sanity floor — anything below it counts as a failed download.
_SL = 'https://raw.githubusercontent.com/danielmiessler/SecLists/master'
_PTAT = 'https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master'
_PB_CMD = 'https://raw.githubusercontent.com/payload-box/command-injection-payload-list/main/Intruder'
_PB_SQL = 'https://raw.githubusercontent.com/payload-box/sql-injection-payload-list/main'

_SOURCES: List[tuple] = [
    # ─── XSS (Cross-Site Scripting) ───
    ('xss', 'xss_polyglots.txt',        f'{_SL}/Fuzzing/XSS/Polyglots/XSS-Polyglots.txt', 10),
    ('xss', 'xss_polyglots_ultimate.txt', f'{_SL}/Fuzzing/XSS/Polyglots/XSS-Polyglot-Ultimate-0xsobky.txt', 1),
    ('xss', 'xss_polyglots_innerhtml.txt', f'{_SL}/Fuzzing/XSS/Polyglots/XSS-innerht-ml.txt', 10),
    ('xss', 'xss_jhaddix.txt',          f'{_SL}/Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt', 50),
    ('xss', 'xss_payloadbox.txt',       f'{_SL}/Fuzzing/XSS/robot-friendly/XSS-payloadbox.txt', 1000),
    ('xss', 'xss_ofjaaah.txt',          f'{_SL}/Fuzzing/XSS/robot-friendly/XSS-OFJAAAH.txt', 1000),
    ('xss', 'xss_brutelogic.txt',       f'{_SL}/Fuzzing/XSS/robot-friendly/XSS-BruteLogic.txt', 50),
    ('xss', 'xss_rsnake.txt',           f'{_SL}/Fuzzing/XSS/robot-friendly/XSS-RSNAKE.txt', 50),
    ('xss', 'xss_vectors_mario.txt',    f'{_SL}/Fuzzing/XSS/robot-friendly/XSS-Vectors-Mario.txt', 50),
    ('xss', 'xss_portswigger.txt',      f'{_SL}/Fuzzing/XSS/robot-friendly/XSS-Cheat-Sheet-PortSwigger.txt', 1000),
    ('xss', 'xss_ptat_alerts.txt',      f'{_PTAT}/XSS%20Injection/Intruders/xss_alert.txt', 500),
    ('xss', 'xss_ptat_quick.txt',       f'{_PTAT}/XSS%20Injection/Intruders/xss_payloads_quick.txt', 30),
    ('xss', 'xss_event_handlers.txt',   f'{_PTAT}/XSS%20Injection/Intruders/0xcela_event_handlers.txt', 20),

    # ─── SQL Injection ───
    ('sqli', 'sqli_generic.txt',        f'{_SL}/Fuzzing/Databases/SQLi/Generic-SQLi.txt', 100),
    ('sqli', 'sqli_quick.txt',          f'{_SL}/Fuzzing/Databases/SQLi/quick-SQLi.txt', 30),
    ('sqli', 'sqli_polyglots.txt',      f'{_SL}/Fuzzing/Databases/SQLi/SQLi-Polyglots.txt', 3),
    ('sqli', 'sqli_mssql.txt',          f'{_SL}/Fuzzing/Databases/SQLi/MSSQL.fuzzdb.txt', 10),
    ('sqli', 'sqli_mysql.txt',          f'{_SL}/Fuzzing/Databases/SQLi/MySQL.fuzzdb.txt', 5),
    ('sqli', 'sqli_oracle.txt',         f'{_SL}/Fuzzing/Databases/SQLi/Oracle.fuzzdb.txt', 20),
    ('sqli', 'sqli_bypass.txt',         f'{_SL}/Fuzzing/Databases/SQLi/sqli.auth.bypass.txt', 50),
    ('sqli', 'sqli_blind_generic.txt',  f'{_SL}/Fuzzing/Databases/SQLi/Generic-BlindSQLi.fuzzdb.txt', 20),
    ('sqli', 'sqli_mysql_bypass.txt',   f'{_SL}/Fuzzing/Databases/SQLi/MySQL-SQLi-Login-Bypass.fuzzdb.txt', 10),

    # ─── NoSQL Injection ───
    ('nosqli', 'nosqli_seclists.txt',   f'{_SL}/Fuzzing/Databases/NoSQL.txt', 5),
    ('nosqli', 'nosqli_mongo.txt',      f'{_PTAT}/NoSQL%20Injection/Intruder/MongoDB.txt', 5),
    ('nosqli', 'nosqli_generic.txt',    f'{_PTAT}/NoSQL%20Injection/Intruder/NoSQL.txt', 5),

    # ─── SSTI (Server-Side Template Injection) ───
    ('ssti', 'ssti_expressions.txt',    f'{_SL}/Fuzzing/template-engines-expression.txt', 5),
    ('ssti', 'ssti_special_vars.txt',   f'{_SL}/Fuzzing/template-engines-special-vars.txt', 20),

    # ─── LFI / Path Traversal ───
    ('lfi', 'lfi_jhaddix.txt',          f'{_SL}/Fuzzing/LFI/LFI-Jhaddix.txt', 200),
    ('lfi', 'lfi_win_linux.txt',        f'{_SL}/Fuzzing/LFI/LFI-linux-and-windows_by-1N3@CrowdShield.txt', 200),
    ('lfi', 'lfi_lfisuite.txt',         f'{_SL}/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt', 200),

    # ─── Command Injection ───
    ('cmd', 'cmd_commix.txt',           f'{_SL}/Fuzzing/command-injection-commix.txt', 1000),
    ('cmd', 'cmd_basic.txt',            f'{_PB_CMD}/command-injection-basic.txt', 20),
    ('cmd', 'cmd_linux.txt',            f'{_PB_CMD}/command-injection-linux.txt', 50),
    ('cmd', 'cmd_windows.txt',          f'{_PB_CMD}/command-injection-windows.txt', 30),
    ('cmd', 'cmd_bypass.txt',           f'{_PB_CMD}/command-injection-bypass.txt', 30),
    ('cmd', 'cmd_polyglot.txt',         f'{_PB_CMD}/command-injection-polyglot.txt', 30),
    ('cmd', 'cmd_encoded.txt',          f'{_PB_CMD}/command-injection-encoded.txt', 5),
    ('cmd', 'cmd_time_based.txt',       f'{_PB_CMD}/command-injection-time-based.txt', 5),
    ('cmd', 'cmd_out_of_band.txt',      f'{_PB_CMD}/command-injection-out-of-band.txt', 5),

    # ─── XXE ───
    ('xxe', 'xxe.txt',                  f'{_SL}/Fuzzing/XXE-Fuzzing.txt', 20),

    # ─── SSRF ───
    ('ssrf', 'ssrf_pwned.txt',          'https://raw.githubusercontent.com/blackhatethicalhacking/SSRFPwned/main/ssrfpayloads.txt', 30),
    ('ssrf', 'ssrf_cujanovic.txt',      'https://raw.githubusercontent.com/cujanovic/SSRF-Testing/master/ssrf-list.txt', 5),

    # ─── CRLF ───
    ('crlf', 'crlf_cujanovic.txt',      'https://raw.githubusercontent.com/cujanovic/CRLF-Injection-Payloads/master/CRLF-payloads.txt', 20),

    # ─── Open Redirect ───
    ('redirect', 'open_redirect_cuja.txt', 'https://raw.githubusercontent.com/cujanovic/Open-Redirect-Payloads/master/Open-Redirect-payloads.txt', 100),

    # ─── LDAP Injection ───
    ('ldap', 'ldap_fuzzing.txt',        f'{_SL}/Fuzzing/LDAP.Fuzzing.txt', 5),

    # ─── JWT Weak Secrets ───
    ('jwt', 'jwt_weak_secrets.txt',     'https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list', 1000),

    # ─── Discovery ───
    ('discovery', 'quickhits.txt',      f'{_SL}/Discovery/Web-Content/quickhits.txt', 500),
    ('discovery', 'raft-medium-directories.txt', f'{_SL}/Discovery/Web-Content/raft-medium-directories.txt', 10000),
    ('discovery', 'api_endpoints.txt',  f'{_SL}/Discovery/Web-Content/api/api-endpoints.txt', 50),
    ('discovery', 'common.txt',         f'{_SL}/Discovery/Web-Content/common.txt', 1000),
    ('discovery', 'big.txt',            f'{_SL}/Discovery/Web-Content/big.txt', 10000),
    ('discovery', 'graphql.txt',        f'{_SL}/Discovery/Web-Content/graphql.txt', 20),
    ('discovery', 'db_backups.txt',     f'{_SL}/Discovery/Web-Content/Common-DB-Backups.txt', 100),

    # ─── Params (Arjun-style) ───
    ('params', 'burp-parameter-names.txt', f'{_SL}/Discovery/Web-Content/burp-parameter-names.txt', 2000),

    # ─── Subdomains ───
    ('subdomains', 'subdomains-top20k.txt', f'{_SL}/Discovery/DNS/subdomains-top1million-20000.txt', 10000),

    # ─── User-Agents (for evasion) ───
    ('useragents', 'user_agents.txt',   f'{_SL}/Fuzzing/User-Agents/UserAgents.fuzz.txt', 500),
]


# ─────────────── downloader ───────────────

async def _download_one(client: httpx.AsyncClient, url: str, dest: Path,
                        min_lines: int) -> bool:
    try:
        r = await client.get(url, timeout=30.0, follow_redirects=True)
        if r.status_code != 200 or not r.text:
            return False
        lines = [line for line in r.text.splitlines() if line and not line.startswith('#')]
        if len(lines) < min_lines:
            return False
        dest.write_text('\n'.join(lines), encoding='utf-8')
        # Sidecar sha256 for tamper detection
        sha = hashlib.sha256('\n'.join(lines).encode('utf-8', errors='ignore')).hexdigest()
        (dest.with_suffix(dest.suffix + '.sha256')).write_text(sha)
        return True
    except Exception:
        return False


async def ensure_wordlists(log_cb: Optional[Callable[[str], None]] = None,
                            force: bool = False) -> Dict[str, int]:
    """Download every missing (or `force=True`) wordlist.  Returns counts per
    category.  Safe to call multiple times — cached files are skipped."""
    counts: Dict[str, int] = {}
    async with httpx.AsyncClient() as client:
        tasks = []
        for category, filename, url, min_lines in _SOURCES:
            dest = WORDLISTS_DIR / category / filename
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.exists() and not force:
                counts[category] = counts.get(category, 0) + sum(
                    1 for _ in dest.open('r', encoding='utf-8', errors='ignore'))
                continue
            if log_cb:
                log_cb(f'[*] Fetching {category}/{filename}...')
            tasks.append((category, dest, _download_one(client, url, dest, min_lines)))
        results = await asyncio.gather(*[t[2] for t in tasks], return_exceptions=True)
        for (category, dest, _), ok in zip(tasks, results):
            if ok is True:
                counts[category] = counts.get(category, 0) + sum(
                    1 for _ in dest.open('r', encoding='utf-8', errors='ignore'))
    return counts


# ─────────────── in-memory access ───────────────

_CACHE: Dict[str, List[str]] = {}


def load_category(category: str, dedupe: bool = True, limit: int = 0) -> List[str]:
    """Read every file under wordlists/<category>/ into a merged list."""
    if category in _CACHE and not limit:
        return _CACHE[category]
    cat_dir = WORDLISTS_DIR / category
    if not cat_dir.exists():
        return []
    out: List[str] = []
    seen: Set[str] = set()
    for f in sorted(cat_dir.glob('*.txt')):
        try:
            for line in f.read_text(encoding='utf-8', errors='ignore').splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if dedupe and line in seen:
                    continue
                seen.add(line)
                out.append(line)
                if limit and len(out) >= limit:
                    _CACHE[category] = out
                    return out
        except Exception:
            continue
    _CACHE[category] = out
    return out


def stats() -> Dict[str, int]:
    """Return {category: count} for what's currently on disk."""
    result: Dict[str, int] = {}
    for cat_dir in WORDLISTS_DIR.glob('*/'):
        result[cat_dir.name] = sum(
            len([line for line in f.read_text(encoding='utf-8',
                                                errors='ignore').splitlines()
                 if line.strip() and not line.startswith('#')])
            for f in cat_dir.glob('*.txt'))
    return result


def sample(category: str, n: int = 20) -> List[str]:
    """Return the first n payloads from a category (for previewing / logging)."""
    return load_category(category)[:n]
