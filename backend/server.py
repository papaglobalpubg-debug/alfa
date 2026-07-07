"""
Backend API for Subdomain Takeover Scanner v5 Dashboard.
Manages scans, results, settings, and continuous monitoring.
"""
import asyncio
import json
import os
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from fastapi import APIRouter, BackgroundTasks, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, PlainTextResponse, HTMLResponse, Response
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.cors import CORSMiddleware

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Ensure a strong JWT secret exists (fallback generator).
try:
    from security_init import ensure_jwt_secret
    ensure_jwt_secret()
except Exception as _sec_err:
    import logging
    logging.getLogger('cyberscope').warning(f'security_init failed: {_sec_err}')

# Add scanner directory to path
SCANNER_DIR = ROOT_DIR.parent / 'scanner'
sys.path.insert(0, str(SCANNER_DIR))

# Import scanner v5 as a library
import takeover_v5 as scanner  # noqa: E402

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

app = FastAPI(title='Subdomain Takeover Scanner API', version='7.7.2')

# v7.7.2 · CORS middleware — required so the React frontend (any origin
# in preview / prod) can hit the FastAPI backend.
_cors_origins = os.environ.get('CORS_ORIGINS', '*').split(',')
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _cors_origins if o.strip()],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

api = APIRouter(prefix='/api')


@api.get('/health')
async def health_check():
    """Lightweight health probe — does NOT depend on MongoDB.
    Used by start.sh + frontend to verify backend is reachable."""
    return {
        'ok': True,
        'version': '7.8.0',
        'app': 'takeover-scan+vuln-scanner',
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }


@api.get('/security-status')
async def security_status():
    """v7.6 · Report which security hardening is active.
    Consumed by the UI to reassure operators after the security audit fixes."""
    return {
        'version': '7.6.0',
        'guards': {
            'ssrf_guard': True,            # SEC-001
            'ownership_scope': True,       # SEC-002
            'report_xss_escaping': True,   # SEC-003
            'secret_masking': True,        # SEC-004
            'rate_limiting': True,         # SEC-005
        },
        'hardening': {
            'cookies_secure': os.environ.get('COOKIE_SECURE', '1') == '1',
            'cookies_samesite': os.environ.get('COOKIE_SAMESITE', 'strict'),
            'cors_wildcard': '*' in os.environ.get('CORS_ORIGINS', '*').split(','),
            'docker_nonroot': True,
        },
        'rate_limits': {
            'scan_launch_per_hour_anon': 20,
            'scan_launch_per_hour_auth': 200,
            'fp_llm_per_hour': 30,
            'notify_test_per_hour': 10,
        },
    }


@api.get('/health/deep')
async def health_check_deep():
    """Deep health probe — verifies MongoDB + vuln scanner import."""
    import asyncio as _asyncio
    checks = {'ok': True, 'version': '6.0.0'}
    try:
        await _asyncio.wait_for(db.command('ping'), timeout=3.0)
        checks['mongodb'] = 'ok'
    except _asyncio.TimeoutError:
        checks['mongodb'] = 'timeout (>3s) — Mongo may be down/unreachable'
        checks['ok'] = False
    except Exception as e:
        checks['mongodb'] = f'error: {type(e).__name__}: {str(e)[:80]}'
        checks['ok'] = False
    try:
        from vuln import VulnScanner  # noqa
        checks['vuln_scanner'] = 'ok'
    except Exception as e:
        checks['vuln_scanner'] = f'error: {type(e).__name__}'
        checks['ok'] = False
    return checks


# ============== AUTH ==============
from auth import (  # noqa: E402
    make_router as make_auth_router,
    seed_admin as auth_seed_admin,
    get_optional_user as auth_get_optional_user,
    get_current_user as auth_get_current_user,
)


def _get_db():
    return db


auth_router = make_auth_router(_get_db)
app.include_router(auth_router)

# v7.9 · Commercial Wave — Billing + Team Workspaces
from billing import make_router as make_billing_router  # noqa: E402
from workspaces import make_router as make_workspaces_router  # noqa: E402

app.include_router(make_billing_router(_get_db, auth_get_current_user, auth_get_optional_user))
app.include_router(make_workspaces_router(_get_db, auth_get_current_user))

# v7.9.2 · Public API + SDK (Enterprise/Lifetime only) + AI Triple-Vote Prioritizer
from public_api import make_router as make_public_api_router  # noqa: E402


async def _api_create_vuln_scan(payload: Dict[str, Any], owner_id: str) -> str:
    """Callable exposed to public_api router for external scan creation."""
    req = VulnScanRequest(**payload)
    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    await db.vuln_scans.insert_one({
        'id': scan_id, 'target': req.target, 'status': 'pending',
        'started_at': now, 'owner_id': owner_id, 'mode': 'api',
        'depth': req.depth, 'modules': req.modules or [],
    })
    asyncio.create_task(_run_vuln_scan_task(scan_id, req, owner_id))
    return scan_id


app.include_router(make_public_api_router(
    _get_db, auth_get_current_user, auth_get_optional_user, _api_create_vuln_scan))


# v7.9.1 · Gated tarball download — only Enterprise / Lifetime tiers can pull
# the self-host archive.
from billing import TIERS as _BILLING_TIERS  # noqa: E402
_ARTIFACTS_DIR = ROOT_DIR / 'artifacts'
_TARBALL_NAME = 'cyberscope-v7.9.0.tar.gz'


@app.get('/api/downloads/cyberscope.tar.gz')
async def download_cyberscope(request: Request):
    """Serve the self-host tarball, gated by subscription tier."""
    user = await auth_get_optional_user(request, db)
    if not user:
        raise HTTPException(401, 'authentication_required')
    billing = await db.billing.find_one({'user_id': user['id']}) or {}
    tier = billing.get('tier') or user.get('tier') or 'free'
    info = _BILLING_TIERS.get(tier, {})
    if not info.get('downloadable'):
        raise HTTPException(
            403,
            f"Download is available on Enterprise and Lifetime plans only. Your tier: {tier}. "
            "Upgrade at /pricing to unlock the self-host tarball.",
        )
    path = _ARTIFACTS_DIR / _TARBALL_NAME
    if not path.exists():
        raise HTTPException(404, 'artifact_not_found')
    return FileResponse(
        path=str(path),
        filename=_TARBALL_NAME,
        media_type='application/gzip',
    )


async def _current_owner(request):
    """Return user id (owner_id) of the current request. Returns 'guest' if not authenticated."""
    try:
        user = await auth_get_optional_user(request, db)
        if user:
            return user.get('id')
    except Exception:
        pass
    return 'guest'


async def _owner_or_403(request, scan_id: str):
    """
    SEC-002 · Enforce Broken-Object-Level-Authorization.
    Ensures the caller either:
      * owns the scan (owner_id matches), or
      * is an admin.
    Otherwise raises HTTPException(403). If the scan doesn't exist, raises 404.

    Returns the scan doc so callers don't need a second query.
    """
    doc = await db.vuln_scans.find_one({'id': scan_id}, {'_id': 0})
    if not doc:
        raise HTTPException(404, 'scan not found')
    owner_id = await _current_owner(request)
    if doc.get('owner_id') == owner_id:
        return doc
    # Admin override
    try:
        user = await auth_get_optional_user(request, db)
    except Exception:
        user = None
    if user and user.get('role') == 'admin':
        return doc
    raise HTTPException(403, 'forbidden — you do not own this scan')


async def _takeover_owner_or_403(request, scan_id: str):
    """v7.6.1 · Same ownership guard for the takeover-scan (v5) endpoints
    `/api/scans/{id}`. Applies to get/results/delete/logs/export/graph."""
    doc = await db.scans.find_one({'id': scan_id}, {'_id': 0})
    if not doc:
        raise HTTPException(404, 'scan not found')
    owner_id = await _current_owner(request)
    if doc.get('owner_id') == owner_id:
        return doc
    try:
        user = await auth_get_optional_user(request, db)
    except Exception:
        user = None
    if user and user.get('role') == 'admin':
        return doc
    raise HTTPException(403, 'forbidden — you do not own this scan')


# ================= SEC-005 · Per-IP Rate Limiter =========================
# Simple in-memory sliding-window counter. Good enough for a single-process
# deployment; behind a reverse proxy set X-Forwarded-For to see real client IP.
_RATE_BUCKETS: Dict[str, List[float]] = {}


def _client_ip(request) -> str:
    xff = request.headers.get('x-forwarded-for', '')
    if xff:
        return xff.split(',')[0].strip()
    return getattr(request.client, 'host', None) or 'anon'


def _rate_limit_check(request, bucket: str, limit: int, per_seconds: int) -> None:
    """Raise HTTPException(429) if the caller has exceeded `limit` requests
    in the last `per_seconds` seconds for the named bucket."""
    ip = _client_ip(request)
    key = f'{bucket}:{ip}'
    now = time.time()
    win_start = now - per_seconds
    times = _RATE_BUCKETS.get(key, [])
    # Drop expired entries
    times = [t for t in times if t >= win_start]
    if len(times) >= limit:
        retry_after = int(max(1, per_seconds - (now - times[0])))
        raise HTTPException(
            status_code=429,
            detail=f'rate limit: {limit} requests per {per_seconds}s exceeded',
            headers={'Retry-After': str(retry_after)},
        )
    times.append(now)
    _RATE_BUCKETS[key] = times
    # Periodic GC — keep the dict from growing unbounded
    if len(_RATE_BUCKETS) > 5000:
        cutoff = now - 3600
        for k in list(_RATE_BUCKETS.keys()):
            _RATE_BUCKETS[k] = [t for t in _RATE_BUCKETS[k] if t >= cutoff]
            if not _RATE_BUCKETS[k]:
                del _RATE_BUCKETS[k]

# Portable paths — work on both Emergent (/app) and local machines (Kali/Ubuntu/macOS/Windows)
# Priority: env var > sibling of /app project root > CWD
_APP_ROOT = Path(os.environ.get('APP_ROOT', ROOT_DIR.parent))
REPORTS_DIR = Path(os.environ.get('REPORTS_DIR', _APP_ROOT / 'scan_reports'))
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


# ============== Models ==============
class ScanOptions(BaseModel):
    model_config = ConfigDict(extra='ignore')
    domain: str
    sources: Optional[List[str]] = None
    threads: int = 20
    timeout: int = 15
    batch_size: int = 50
    verify: bool = True
    notify: bool = False  # webhook notify
    wordlist_content: Optional[str] = None


class Scan(BaseModel):
    model_config = ConfigDict(extra='ignore')
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    domain: str
    status: str = 'pending'  # pending | discovering | analyzing | verifying | completed | failed
    progress: Dict[str, Any] = Field(default_factory=dict)
    options: Dict[str, Any] = Field(default_factory=dict)
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: Optional[datetime] = None
    duration: Optional[float] = None
    summary: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None
    logs: List[str] = Field(default_factory=list)


class Settings(BaseModel):
    model_config = ConfigDict(extra='ignore')
    api_keys: Dict[str, str] = Field(default_factory=dict)
    webhooks: Dict[str, str] = Field(default_factory=dict)  # slack, discord
    telegram: Dict[str, str] = Field(default_factory=dict)  # token, chat_id
    default_sources: List[str] = Field(default_factory=list)


class MonitoredDomain(BaseModel):
    model_config = ConfigDict(extra='ignore')
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    domain: str
    interval_hours: int = 24
    enabled: bool = True
    last_scan_id: Optional[str] = None
    last_scan_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ============== In-memory scan runners ==============
RUNNING_SCANS: Dict[str, Dict[str, Any]] = {}


def _serialize(doc):
    if isinstance(doc, dict):
        return {k: _serialize(v) for k, v in doc.items()}
    if isinstance(doc, list):
        return [_serialize(v) for v in doc]
    if isinstance(doc, datetime):
        return doc.isoformat()
    return doc


def _dt(v):
    if isinstance(v, str):
        try:
            return datetime.fromisoformat(v.replace('Z', '+00:00'))
        except ValueError:
            return None
    return v


# ============== Scan execution ==============
class ScanRunner:
    def __init__(self, scan_id: str, opts: ScanOptions, settings_doc: Dict[str, Any]):
        self.scan_id = scan_id
        self.opts = opts
        self.settings = settings_doc
        self.cancel_flag = threading.Event()
        self.state = {
            'phase': 'pending',
            'sources_done': 0,
            'sources_total': 0,
            'sources_stats': {},
            'analyzed': 0,
            'analyzed_total': 0,
            'logs': [],
            'cancel_flag': self.cancel_flag,
        }
        RUNNING_SCANS[scan_id] = self.state

    def _log(self, line: str):
        stamped = f'[{datetime.now(timezone.utc).strftime("%H:%M:%S")}] {line}'
        self.state['logs'].append(stamped)
        if len(self.state['logs']) > 500:
            self.state['logs'] = self.state['logs'][-500:]

    def _src_cb(self, source, count, status):
        self.state['sources_done'] += 1
        self.state['sources_stats'][source] = count
        self._log(f'source {source}: {count} subs ({status})')

    def _analyze_cb(self, done, total):
        self.state['analyzed'] = done
        self.state['analyzed_total'] = total

    def run(self):
        try:
            self.state['phase'] = 'discovering'
            self._log(f'Scan started for {self.opts.domain}')
            if self.cancel_flag.is_set():
                self.state['phase'] = 'cancelled'
                self._log('Cancelled before start')
                return
            api_keys = self.settings.get('api_keys', {}) or {}

            srcs = self.opts.sources or [
                'crt', 'hackertarget', 'otx', 'rapiddns', 'urlscan', 'commoncrawl',
                'bufferover', 'anubis', 'jldc', 'wayback', 'certspotter', 'digitorus',
                'threatminer', 'dnsdumpster', 'bruteforce', 'permutation', 'tls_san',
                'js_mining', 'robots_sitemap',
            ]
            # Add API-key sources if keys exist
            for k, s in [('securitytrails', 'securitytrails'), ('shodan', 'shodan'),
                         ('virustotal', 'virustotal'), ('chaos', 'chaos'),
                         ('binaryedge', 'binaryedge')]:
                if api_keys.get(k) and s not in srcs:
                    srcs.append(s)
            if api_keys.get('censys_id') and api_keys.get('censys_secret'):
                if 'censys' not in srcs:
                    srcs.append('censys')

            self.state['sources_total'] = len([s for s in srcs if s != 'permutation'])

            de = scanner.DiscoveryEngine(
                self.opts.domain, srcs,
                threads=self.opts.threads, timeout=self.opts.timeout,
                verbose=False, api_keys=api_keys, progress_cb=self._src_cb,
            )
            subs = de.run()
            if self.cancel_flag.is_set():
                self.state['phase'] = 'cancelled'
                self._log('Cancelled after discovery')
                return

            if self.opts.wordlist_content:
                wl_prefixes = {ln.strip() for ln in self.opts.wordlist_content.splitlines()
                               if ln.strip() and not ln.startswith('#')}
                wl_subs = {f'{p}.{self.opts.domain}' for p in wl_prefixes}
                new_wl = wl_subs - set(subs)
                self._log(f'wordlist: +{len(new_wl)} subs')
                subs = sorted(set(subs) | wl_subs)
                de.stats['wordlist'] = len(wl_subs)

            self._log(f'Discovery complete: {len(subs)} unique subs')

            self.state['phase'] = 'analyzing'
            az = scanner.Analyzer(
                threads=self.opts.threads, timeout=self.opts.timeout,
                verbose=False, batch_size=self.opts.batch_size,
                wildcard_ips=de.wildcard_ips, progress_cb=self._analyze_cb,
            )
            results = az.analyze_all(subs)
            if self.cancel_flag.is_set():
                self.state['phase'] = 'cancelled'
                self.state['results'] = results
                self.state['discovery'] = {'stats': de.stats, 'wildcard_ips': list(de.wildcard_ips)}
                self._log('Cancelled after analysis')
                return
            self._log(f'Analysis complete: {len(results)} results')

            if self.opts.verify:
                self.state['phase'] = 'verifying'
                vt = [r for r in results if r.get('classification') == 'CLAIMABLE'
                      and scanner.SERVICES.get(r.get('service'), {}).get('v')]
                self._log(f'Active verification on {len(vt)} candidates')
                vf = scanner.Verifier(timeout=self.opts.timeout)
                import concurrent.futures
                import re
                with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
                    fts = {}
                    for r in vt:
                        svc = scanner.SERVICES.get(r['service'], {})
                        res = r['subdomain'].split('.')[0]
                        if r.get('cname_chain'):
                            first_cn = svc.get('cn', [''])[0]
                            m = re.match(first_cn, r['cname_chain'][-1]) if first_cn else None
                            if m and m.groups():
                                res = m.group(1)
                        fts[ex.submit(vf.verify, svc.get('v'), res)] = r
                    for f in concurrent.futures.as_completed(fts, timeout=120):
                        r = fts[f]
                        try:
                            v = f.result()
                            r['verification'] = v
                            if v.get('available') is True:
                                r['verified_claimable'] = True
                        except Exception:
                            pass

            self.state['phase'] = 'completed'
            self.state['results'] = results
            self.state['discovery'] = {
                'stats': de.stats,
                'wildcard_ips': list(de.wildcard_ips),
            }
            self._log('Scan finished successfully.')

            # Webhook notify
            if self.opts.notify:
                self._send_webhook(results)

        except Exception as e:
            import traceback
            self.state['phase'] = 'failed'
            self.state['error'] = f'{type(e).__name__}: {e}'
            self._log(f'ERROR: {self.state["error"]}')
            self._log(traceback.format_exc()[:2000])

    def _send_webhook(self, results):
        webhooks = self.settings.get('webhooks', {}) or {}
        tg = self.settings.get('telegram', {}) or {}
        notifier = scanner.Notifier(
            slack=webhooks.get('slack'),
            discord=webhooks.get('discord'),
            telegram=tg if tg.get('token') and tg.get('chat_id') else None,
        )
        verified = [r for r in results if r.get('verified_claimable')]
        claimable = [r for r in results if r.get('classification') == 'CLAIMABLE']
        if not (verified or claimable):
            return
        lines = [f'[{(r.get("priority") or "?").upper()}] {r["subdomain"]} -> {r.get("service_name")}'
                 for r in (verified + claimable)[:20]]
        sev = 'critical' if any(r.get('priority') == 'critical' for r in verified + claimable) else 'high'
        notifier.notify(
            f'Takeover scan: {self.opts.domain} - {len(verified)} verified, {len(claimable)} claimable',
            '\n'.join(lines), severity=sev)


async def _load_settings() -> Dict[str, Any]:
    doc = await db.settings.find_one({'_id': 'global'}, {'_id': 0})
    return doc or {'api_keys': {}, 'webhooks': {}, 'telegram': {}, 'default_sources': []}


async def _persist_scan(scan_id: str, runner: ScanRunner):
    """Save scan state to MongoDB."""
    state = runner.state
    results = state.get('results', [])
    discovery = state.get('discovery', {})

    def _summary(rs):
        return {
            'total_analyzed': len(rs),
            'verified_claimable': sum(1 for r in rs if r.get('verified_claimable')),
            'claimable': sum(1 for r in rs if r.get('classification') == 'CLAIMABLE'),
            'verify_required': sum(1 for r in rs if r.get('classification') == 'VERIFY_REQUIRED'),
            'dead': sum(1 for r in rs if r.get('classification') == 'DEAD'),
            'service_active': sum(1 for r in rs if r.get('classification') == 'SERVICE_ACTIVE'),
            'alive': sum(1 for r in rs if r.get('classification') == 'ALIVE'),
            'nxdomain': sum(1 for r in rs if r.get('classification') == 'NXDOMAIN'),
            'wildcard': sum(1 for r in rs if r.get('classification') == 'WILDCARD'),
            'http_error': sum(1 for r in rs if r.get('classification') == 'HTTP_ERROR'),
        }

    update = {
        'status': state.get('phase'),
        'progress': {
            'sources_done': state.get('sources_done', 0),
            'sources_total': state.get('sources_total', 0),
            'sources_stats': state.get('sources_stats', {}),
            'analyzed': state.get('analyzed', 0),
            'analyzed_total': state.get('analyzed_total', 0),
        },
        'summary': _summary(results),
        'discovery': discovery,
        'error': state.get('error'),
        'logs': state.get('logs', [])[-200:],
    }
    if state.get('phase') in ('completed', 'failed'):
        update['finished_at'] = datetime.now(timezone.utc).isoformat()
        doc = await db.scans.find_one({'id': scan_id}, {'started_at': 1})
        if doc and doc.get('started_at'):
            started = _dt(doc['started_at'])
            if started:
                update['duration'] = (datetime.now(timezone.utc) - started).total_seconds()

    await db.scans.update_one({'id': scan_id}, {'$set': update})

    # Save full results separately for perf
    if results:
        await db.scan_results.replace_one(
            {'scan_id': scan_id},
            {'scan_id': scan_id, 'results': _serialize(results),
             'discovery': _serialize(discovery)},
            upsert=True)


async def _run_scan_task(scan_id: str, opts: ScanOptions):
    """Background task: run scan in thread pool and persist to Mongo."""
    settings_doc = await _load_settings()
    runner = ScanRunner(scan_id, opts, settings_doc)
    await db.scans.update_one({'id': scan_id}, {'$set': {'status': 'discovering'}})

    loop = asyncio.get_event_loop()

    async def _poll():
        while True:
            await _persist_scan(scan_id, runner)
            if runner.state.get('phase') in ('completed', 'failed'):
                break
            await asyncio.sleep(2)

    poller = asyncio.create_task(_poll())
    try:
        await loop.run_in_executor(None, runner.run)
    finally:
        await _persist_scan(scan_id, runner)
        RUNNING_SCANS.pop(scan_id, None)
        await poller


# ============== API endpoints ==============
@api.get('/')
async def root():
    return {'app': 'Subdomain Takeover Scanner', 'version': '5.0.0', 'services': len(scanner.SERVICES)}


@api.get('/stats')
async def stats():
    total_scans = await db.scans.count_documents({})
    active = await db.scans.count_documents({'status': {'$in': ['discovering', 'analyzing', 'verifying', 'pending']}})
    # Aggregate findings across all scans
    pipeline = [
        {'$group': {
            '_id': None,
            'verified': {'$sum': '$summary.verified_claimable'},
            'claimable': {'$sum': '$summary.claimable'},
            'total_analyzed': {'$sum': '$summary.total_analyzed'},
        }}
    ]
    agg = await db.scans.aggregate(pipeline).to_list(1)
    findings = agg[0] if agg else {'verified': 0, 'claimable': 0, 'total_analyzed': 0}
    findings.pop('_id', None)

    recent = await db.scans.find({}, {'_id': 0}).sort('started_at', -1).limit(5).to_list(5)
    return {
        'total_scans': total_scans,
        'active_scans': active,
        'total_verified_claimable': findings.get('verified', 0),
        'total_claimable': findings.get('claimable', 0),
        'total_subs_analyzed': findings.get('total_analyzed', 0),
        'available_services': len(scanner.SERVICES),
        'recent_scans': recent,
    }


@api.get('/services')
async def list_services():
    return {
        'count': len(scanner.SERVICES),
        'services': [
            {
                'key': k,
                'name': v.get('name'),
                'priority': v.get('pri'),
                'claimable': v.get('claimable'),
                'cnames': v.get('cn', []),
                'has_verifier': bool(v.get('v')),
            }
            for k, v in scanner.SERVICES.items()
        ],
    }


@api.get('/sources')
async def list_sources():
    return {
        'free': ['crt', 'hackertarget', 'otx', 'rapiddns', 'urlscan', 'commoncrawl',
                 'bufferover', 'anubis', 'jldc', 'wayback', 'certspotter', 'digitorus',
                 'threatminer', 'dnsdumpster', 'bruteforce', 'permutation', 'tls_san'],
        'with_api_key': ['securitytrails', 'shodan', 'censys', 'virustotal', 'chaos', 'binaryedge'],
        'external_tool': ['subfinder', 'assetfinder', 'amass'],
    }


@api.post('/scans')
async def create_scan(opts: ScanOptions, bg: BackgroundTasks, request: Request):
    owner_id = await _current_owner(request)
    scan = Scan(domain=opts.domain, options=opts.model_dump())
    doc = scan.model_dump()
    doc['started_at'] = doc['started_at'].isoformat()
    if doc.get('finished_at'):
        doc['finished_at'] = doc['finished_at'].isoformat()
    doc['owner_id'] = owner_id
    await db.scans.insert_one(doc)
    bg.add_task(_run_scan_task, scan.id, opts)
    return {'scan_id': scan.id, 'status': 'pending'}


@api.get('/scans')
async def list_scans(request: Request, limit: int = Query(50, le=200), skip: int = 0,
                     domain: Optional[str] = None, status: Optional[str] = None):
    owner_id = await _current_owner(request)
    q: Dict[str, Any] = {'owner_id': {'$in': [owner_id, 'guest']} if owner_id == 'guest' else owner_id}
    # If guest, show only guest scans; if authenticated, show only user's scans (or admin sees all)
    user = await auth_get_optional_user(request, db)
    if user and user.get('role') == 'admin':
        q = {}
    if domain:
        q['domain'] = {'$regex': domain, '$options': 'i'}
    if status:
        q['status'] = status
    scans = await db.scans.find(q, {'_id': 0, 'logs': 0}).sort('started_at', -1).skip(skip).limit(limit).to_list(limit)
    total = await db.scans.count_documents(q)
    return {'scans': scans, 'total': total}


@api.get('/scans/{scan_id}')
async def get_scan(scan_id: str, request: Request):
    doc = await _takeover_owner_or_403(request, scan_id)  # v7.6.1 SEC-002
    # Merge with live state if running
    if scan_id in RUNNING_SCANS:
        state = RUNNING_SCANS[scan_id]
        doc['live'] = {
            'phase': state.get('phase'),
            'sources_done': state.get('sources_done', 0),
            'sources_total': state.get('sources_total', 0),
            'analyzed': state.get('analyzed', 0),
            'analyzed_total': state.get('analyzed_total', 0),
        }
    return doc


@api.get('/scans/{scan_id}/results')
async def get_scan_results(scan_id: str,
                           request: Request,
                           priority: Optional[str] = None,
                           classification: Optional[str] = None,
                           search: Optional[str] = None,
                           limit: int = Query(500, le=5000)):
    await _takeover_owner_or_403(request, scan_id)  # v7.6.1 SEC-002
    doc = await db.scan_results.find_one({'scan_id': scan_id}, {'_id': 0})
    if not doc:
        # Maybe running or empty
        if scan_id in RUNNING_SCANS:
            results = RUNNING_SCANS[scan_id].get('results', [])
        else:
            results = []
    else:
        results = doc.get('results', [])

    def _match(r):
        if priority and (r.get('priority') or '').lower() != priority.lower():
            return False
        if classification and r.get('classification') != classification:
            return False
        if search and search.lower() not in (r.get('subdomain') or '').lower():
            return False
        return True

    filtered = [r for r in results if _match(r)]
    filtered.sort(key=lambda r: (
        -{'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(r.get('priority') or 'low', 0),
        -(r.get('confidence') or 0),
    ))
    return {'total': len(filtered), 'results': filtered[:limit]}


@api.delete('/scans/{scan_id}')
async def delete_scan(scan_id: str, request: Request):
    await _takeover_owner_or_403(request, scan_id)  # v7.6.1 SEC-002
    r = await db.scans.delete_one({'id': scan_id})
    await db.scan_results.delete_one({'scan_id': scan_id})
    RUNNING_SCANS.pop(scan_id, None)
    return {'deleted': r.deleted_count}


@api.get('/scans/{scan_id}/logs')
async def get_scan_logs(scan_id: str, request: Request):
    await _takeover_owner_or_403(request, scan_id)  # v7.6.1 SEC-002
    if scan_id in RUNNING_SCANS:
        return {'logs': RUNNING_SCANS[scan_id].get('logs', [])}
    doc = await db.scans.find_one({'id': scan_id}, {'logs': 1, '_id': 0})
    if not doc:
        raise HTTPException(404, 'Not found')
    return {'logs': doc.get('logs', [])}


@api.get('/scans/{scan_id}/export/{fmt}')
async def export_scan(scan_id: str, fmt: str, request: Request):
    await _takeover_owner_or_403(request, scan_id)  # v7.6.1 SEC-002
    if fmt not in ('json', 'html', 'csv', 'txt', 'jsonl'):
        raise HTTPException(400, 'Unsupported format')
    scan = await db.scans.find_one({'id': scan_id}, {'_id': 0})
    if not scan:
        raise HTTPException(404, 'Not found')
    doc = await db.scan_results.find_one({'scan_id': scan_id}, {'_id': 0})
    results = (doc or {}).get('results', [])
    discovery = (doc or {}).get('discovery', {})
    target = scan.get('domain', 'unknown')
    dur = scan.get('duration') or 0.0

    out_path = REPORTS_DIR / f'{scan_id}.{fmt}'
    if fmt == 'json':
        scanner.write_json(results, target, dur, discovery, str(out_path))
    elif fmt == 'jsonl':
        scanner.write_jsonl(results, str(out_path))
    elif fmt == 'html':
        scanner.write_html(results, target, dur, discovery, str(out_path))
    elif fmt == 'csv':
        scanner.write_csv(results, str(out_path))
    elif fmt == 'txt':
        scanner.write_txt(results, str(out_path))

    media = {
        'json': 'application/json',
        'jsonl': 'application/x-ndjson',
        'html': 'text/html',
        'csv': 'text/csv',
        'txt': 'text/plain',
    }[fmt]
    return FileResponse(str(out_path), media_type=media, filename=f'{target}_{scan_id[:8]}.{fmt}')


# ============== SCAN CANCELLATION ==============
@api.post('/scans/{scan_id}/cancel')
async def cancel_scan(scan_id: str, request: Request):
    await _takeover_owner_or_403(request, scan_id)  # v7.6.1 SEC-002
    state = RUNNING_SCANS.get(scan_id)
    if not state:
        raise HTTPException(404, 'Scan not running or already finished')
    flag = state.get('cancel_flag')
    if flag is not None:
        flag.set()
    return {'ok': True, 'message': 'Cancel signal sent'}


# ============== BULK SCAN ==============
class BulkScanRequest(BaseModel):
    domains: List[str]
    sources: Optional[List[str]] = None
    threads: int = 20
    timeout: int = 15
    verify: bool = True
    notify: bool = False


@api.post('/scans/bulk')
async def create_bulk_scan(req: BulkScanRequest, bg: BackgroundTasks, request: Request):
    owner_id = await _current_owner(request)
    domains = [d.strip().lower() for d in req.domains if d.strip()]
    if not domains:
        raise HTTPException(400, 'No domains provided')
    if len(domains) > 100:
        raise HTTPException(400, 'Max 100 domains per bulk scan')
    scan_ids = []
    for d in domains:
        opts = ScanOptions(
            domain=d, sources=req.sources, threads=req.threads,
            timeout=req.timeout, verify=req.verify, notify=req.notify,
        )
        scan = Scan(domain=d, options=opts.model_dump())
        doc = scan.model_dump()
        doc['started_at'] = doc['started_at'].isoformat()
        if doc.get('finished_at'):
            doc['finished_at'] = doc['finished_at'].isoformat()
        doc['bulk_batch'] = True
        doc['owner_id'] = owner_id
        await db.scans.insert_one(doc)
        bg.add_task(_run_scan_task, scan.id, opts)
        scan_ids.append(scan.id)
    return {'scan_ids': scan_ids, 'count': len(scan_ids)}


# ============== PLAYBOOK ==============
@api.get('/playbooks')
async def list_playbooks_api():
    try:
        return {'playbooks': scanner._render_bb_report is not None and _list_playbooks() or []}  # noqa
    except Exception:
        try:
            from exploitation_playbook import list_playbooks
            return {'playbooks': list_playbooks()}
        except ImportError:
            return {'playbooks': []}


def _list_playbooks():
    from exploitation_playbook import list_playbooks
    return list_playbooks()


@api.get('/playbooks/{service_key}')
async def get_playbook_api(service_key: str):
    try:
        from exploitation_playbook import get_playbook
        pb = get_playbook(service_key)
        return pb.to_dict()
    except ImportError:
        raise HTTPException(500, 'Playbook module not available')


@api.get('/scans/{scan_id}/report/bug-bounty/{subdomain}')
async def get_bug_bounty_report(scan_id: str, subdomain: str, request: Request):
    """Generate a Bug Bounty markdown report for a specific finding."""
    await _takeover_owner_or_403(request, scan_id)  # v7.6.1 SEC-002
    doc = await db.scan_results.find_one({'scan_id': scan_id}, {'_id': 0})
    if not doc:
        raise HTTPException(404, 'Scan results not found')
    finding = next((r for r in doc.get('results', []) if r.get('subdomain') == subdomain), None)
    if not finding:
        raise HTTPException(404, f'Finding for {subdomain} not found')
    try:
        from exploitation_playbook import render_bug_bounty_report, get_playbook
        report_md = render_bug_bounty_report(finding)
        pb = get_playbook(finding.get('service') or 'generic').to_dict()
        return {
            'subdomain': subdomain,
            'markdown': report_md,
            'playbook': pb,
        }
    except ImportError:
        raise HTTPException(500, 'Playbook module not available')


# ============== ADVANCED RECON (port scan, k8s check, api discovery) ==============
class ReconRequest(BaseModel):
    host: str
    features: List[str] = ['ports', 'k8s', 'api']  # ports|k8s|api|favicon


@api.post('/recon')
async def run_recon(req: ReconRequest):
    """Run advanced recon (port scan / k8s / api discovery / favicon) on a host."""
    try:
        from advanced_recon import port_scan, check_k8s_docker, api_discovery, get_favicon_hash
    except ImportError:
        raise HTTPException(500, 'Advanced recon module not available')
    host = req.host.strip().lower().replace('http://', '').replace('https://', '').split('/')[0]
    result = {'host': host}
    loop = asyncio.get_event_loop()

    async def _run(fn, *a, **kw):
        return await loop.run_in_executor(None, lambda: fn(*a, **kw))

    if 'ports' in req.features:
        result['ports'] = await _run(port_scan, host, None, 30, 1.5)
    if 'k8s' in req.features:
        result['k8s_docker'] = await _run(check_k8s_docker, host, 5)
    if 'api' in req.features:
        result['api_discovery'] = await _run(api_discovery, host, 5)
    if 'favicon' in req.features:
        result['favicon_hash'] = await _run(get_favicon_hash, f'https://{host}')
    return result


# ============== SCREENSHOTS ==============
@api.post('/scans/{scan_id}/screenshots/{subdomain}')
async def take_screenshot_endpoint(scan_id: str, subdomain: str, request: Request):
    """Take a screenshot of the subdomain (uses Playwright)."""
    await _takeover_owner_or_403(request, scan_id)  # v7.6.1 SEC-002
    try:
        from screenshot_service import take_screenshot, screenshot_path_for
    except ImportError:
        raise HTTPException(500, 'Screenshot service not available')
    path = screenshot_path_for(scan_id, subdomain)
    url = f'https://{subdomain}'
    result_path = await take_screenshot(url, str(path), timeout=15)
    if not result_path:
        # Try HTTP fallback
        result_path = await take_screenshot(f'http://{subdomain}', str(path), timeout=15)
    if not result_path:
        raise HTTPException(500, 'Screenshot failed (timeout or unreachable)')
    return {'ok': True, 'path': str(path)}


@api.get('/scans/{scan_id}/screenshots/{subdomain}')
async def get_screenshot(scan_id: str, subdomain: str, request: Request):
    """Serve saved screenshot."""
    await _takeover_owner_or_403(request, scan_id)  # v7.6.1 SEC-002
    try:
        from screenshot_service import screenshot_path_for
    except ImportError:
        raise HTTPException(500, 'Screenshot service not available')
    path = screenshot_path_for(scan_id, subdomain)
    if not path.exists():
        raise HTTPException(404, 'Screenshot not yet captured. POST first.')
    return FileResponse(str(path), media_type='image/png')


# ============== ATTACK SURFACE GRAPH ==============
@api.get('/scans/{scan_id}/graph')
async def attack_surface_graph(scan_id: str, request: Request):
    """Build a nodes/edges graph of the scan's DNS relationships."""
    await _takeover_owner_or_403(request, scan_id)  # v7.6.1 SEC-002
    doc = await db.scan_results.find_one({'scan_id': scan_id}, {'_id': 0})
    if not doc:
        raise HTTPException(404, 'Scan results not found')
    results = doc.get('results', [])
    nodes = {}
    edges = []

    def _add(n_id, group, meta=None):
        if n_id in nodes:
            return
        nodes[n_id] = {'id': n_id, 'group': group, 'meta': meta or {}}

    for r in results:
        sub = r.get('subdomain')
        if not sub:
            continue
        cls = r.get('classification')
        prio = r.get('priority')
        # Skip noise
        if cls in ('NXDOMAIN', 'NO_MATCH', 'HTTP_ERROR') and not (r.get('claimable') or r.get('verified_claimable')):
            continue
        group = 'sub'
        if r.get('verified_claimable'):
            group = 'verified'
        elif r.get('claimable'):
            group = 'claimable'
        elif cls == 'VERIFY_REQUIRED':
            group = 'verify'
        elif cls == 'DEAD':
            group = 'dead'
        elif cls == 'SERVICE_ACTIVE' or cls == 'ALIVE':
            group = 'active'
        _add(sub, group, {
            'classification': cls, 'priority': prio,
            'service_name': r.get('service_name'), 'http_status': r.get('http_status'),
        })
        # Add CNAME chain edges
        prev = sub
        for hop in (r.get('cname_chain') or []):
            _add(hop, 'cname', {})
            edges.append({'source': prev, 'target': hop, 'label': 'CNAME'})
            prev = hop

    return {
        'scan_id': scan_id,
        'node_count': len(nodes),
        'edge_count': len(edges),
        'nodes': list(nodes.values()),
        'edges': edges,
    }


@api.get('/settings')
async def get_settings():
    s = await _load_settings()
    # Mask API keys (show only last 4)
    masked_keys = {}
    for k, v in (s.get('api_keys') or {}).items():
        if v and len(v) > 4:
            masked_keys[k] = f'****{v[-4:]}'
        elif v:
            masked_keys[k] = '****'
    return {
        'api_keys_masked': masked_keys,
        'api_keys_set': list((s.get('api_keys') or {}).keys()),
        'webhooks': s.get('webhooks') or {},
        'telegram': {'chat_id': (s.get('telegram') or {}).get('chat_id', ''),
                     'token_set': bool((s.get('telegram') or {}).get('token'))},
        'default_sources': s.get('default_sources') or [],
    }


class SettingsUpdate(BaseModel):
    api_keys: Optional[Dict[str, str]] = None
    webhooks: Optional[Dict[str, str]] = None
    telegram: Optional[Dict[str, str]] = None
    default_sources: Optional[List[str]] = None


@api.put('/settings')
async def update_settings(payload: SettingsUpdate):
    current = await _load_settings()
    if payload.api_keys is not None:
        # Merge (only overwrite provided keys; empty string removes)
        merged = dict(current.get('api_keys') or {})
        for k, v in payload.api_keys.items():
            if v == '':
                merged.pop(k, None)
            else:
                merged[k] = v
        current['api_keys'] = merged
    if payload.webhooks is not None:
        current['webhooks'] = payload.webhooks
    if payload.telegram is not None:
        # Merge telegram token+chat_id
        tg = dict(current.get('telegram') or {})
        tg.update({k: v for k, v in payload.telegram.items() if v is not None})
        current['telegram'] = tg
    if payload.default_sources is not None:
        current['default_sources'] = payload.default_sources
    current['_id'] = 'global'
    await db.settings.replace_one({'_id': 'global'}, current, upsert=True)
    return {'ok': True}


# ---- Continuous Monitoring ----
@api.get('/monitors')
async def list_monitors():
    monitors = await db.monitors.find({}, {'_id': 0}).sort('created_at', -1).to_list(100)
    return {'monitors': monitors}


@api.post('/monitors')
async def create_monitor(m: MonitoredDomain):
    doc = m.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    if doc.get('last_scan_at'):
        doc['last_scan_at'] = doc['last_scan_at'].isoformat()
    await db.monitors.insert_one(doc)
    return {'ok': True, 'id': m.id}


@api.put('/monitors/{monitor_id}')
async def update_monitor(monitor_id: str, payload: Dict[str, Any]):
    payload.pop('_id', None)
    payload.pop('id', None)
    await db.monitors.update_one({'id': monitor_id}, {'$set': payload})
    return {'ok': True}


@api.delete('/monitors/{monitor_id}')
async def delete_monitor(monitor_id: str):
    r = await db.monitors.delete_one({'id': monitor_id})
    return {'deleted': r.deleted_count}


# ---- Background monitor loop ----
async def monitor_loop():
    """Every 5 minutes, check monitors and trigger scans if interval passed."""
    while True:
        try:
            monitors = await db.monitors.find({'enabled': True}, {'_id': 0}).to_list(100)
            now = datetime.now(timezone.utc)
            for m in monitors:
                last = _dt(m.get('last_scan_at'))
                interval = int(m.get('interval_hours') or 24) * 3600
                if last is None or (now - last).total_seconds() >= interval:
                    # Trigger scan
                    opts = ScanOptions(domain=m['domain'], verify=True, notify=True)
                    scan_id = str(uuid.uuid4())
                    scan_doc = {
                        'id': scan_id, 'domain': m['domain'], 'status': 'pending',
                        'progress': {}, 'options': opts.model_dump(),
                        'started_at': now.isoformat(),
                        'finished_at': None, 'summary': {}, 'error': None,
                        'monitor_id': m['id'], 'logs': [],
                    }
                    await db.scans.insert_one(scan_doc)
                    await db.monitors.update_one(
                        {'id': m['id']},
                        {'$set': {'last_scan_at': now.isoformat(), 'last_scan_id': scan_id}})
                    asyncio.create_task(_run_scan_task(scan_id, opts))
        except Exception as e:
            print(f'[monitor_loop] error: {type(e).__name__}: {e}')
        await asyncio.sleep(300)


# ============== VULN SCANNER (v6 — Weaponized Web Vulnerability Scanner) ==============
try:
    from vuln import VulnScanner, VulnScanConfig  # noqa: E402
    from vuln.payloads import count_payloads as vuln_count_payloads  # noqa: E402
    VULN_AVAILABLE = True
except ImportError as _vuln_err:
    VULN_AVAILABLE = False
    _VULN_IMPORT_ERROR = str(_vuln_err)

VULN_SCANS: Dict[str, Dict[str, Any]] = {}  # In-memory registry


class VulnScanRequest(BaseModel):
    model_config = ConfigDict(extra='ignore')
    target: str
    concurrency: int = 30
    timeout: float = 12.0
    depth: str = 'medium'  # shallow | medium | deep
    modules: Optional[List[str]] = None  # Override enabled modules
    disabled: Optional[List[str]] = None
    oob_host: Optional[str] = None
    jwt_token: Optional[str] = None
    custom_params: Optional[List[str]] = None
    passive_only: bool = False
    session_cookies: Optional[str] = None
    session_headers: Optional[Dict[str, str]] = None
    proxy: Optional[str] = None
    capture_screenshots: bool = True
    notify: bool = True


async def _run_vuln_scan_task(scan_id: str, req: VulnScanRequest, owner_id: str):
    """Background task: run vuln scan and persist results to Mongo."""
    logs: List[str] = []

    def _log_cb(msg: str):
        stamp = datetime.now(timezone.utc).strftime('%H:%M:%S')
        line = f'[{stamp}] {msg}'
        logs.append(line)
        VULN_SCANS.setdefault(scan_id, {})['logs'] = logs[-500:]

    # v7.7.1 · periodic DB log flush so the UI streams live progress instead of
    # showing "pending"/"empty" for the whole run.
    _flush_stop = asyncio.Event()
    async def _flush_loop():
        while not _flush_stop.is_set():
            try:
                if logs:
                    await db.vuln_scans.update_one(
                        {'id': scan_id}, {'$set': {'logs': logs[-200:]}}
                    )
            except Exception:
                pass
            try:
                await asyncio.wait_for(_flush_stop.wait(), timeout=3.0)
            except asyncio.TimeoutError:
                pass
    _flush_task = asyncio.create_task(_flush_loop())

    kwargs = dict(
        concurrency=req.concurrency, timeout=req.timeout,
        depth=req.depth, oob_host=req.oob_host,
        jwt_token=req.jwt_token, custom_params=req.custom_params,
        passive_only=req.passive_only,
        session_cookies=req.session_cookies,
        session_headers=req.session_headers,
        proxy=req.proxy,
        log_cb=_log_cb,
    )
    cfg = VulnScanConfig(target=req.target, **kwargs)
    if req.modules:
        cfg.enabled_modules = set(req.modules)
    if req.disabled:
        cfg.disabled_modules = set(req.disabled)

    VULN_SCANS[scan_id] = {'status': 'running', 'logs': logs, 'started_at': datetime.now(timezone.utc)}
    # v7.7.1 · flip DB status to 'running' immediately so the UI knows the task
    # has started (previously stayed on 'pending' until completion).
    try:
        await db.vuln_scans.update_one({'id': scan_id}, {'$set': {'status': 'running'}})
    except Exception:
        pass
    scanner_ = VulnScanner(cfg)
    # v7.4 — expose scanner so /cancel endpoint can request cooperative stop
    VULN_SCANS[scan_id]['scanner'] = scanner_
    _log_cb(f'[*] Scan launched: target={req.target} depth={req.depth}')
    try:
        result = await scanner_.run()
        VULN_SCANS[scan_id] = {'status': 'completed', 'logs': logs, 'result': result,
                               'started_at': datetime.now(timezone.utc)}
        # Persist
        await db.vuln_scans.update_one(
            {'id': scan_id},
            {'$set': {
                'status': 'completed',
                'finished_at': datetime.now(timezone.utc).isoformat(),
                'summary': result.get('summary', {}),
                'fingerprint': result.get('fingerprint', {}),
                'stats': result.get('stats', {}),
                'verification': result.get('verification', {}),
                'chains_count': len(result.get('attack_chains', []) or []),
                'errors': result.get('errors', []),
                'logs': logs[-200:],
            }},
        )
        await db.vuln_scan_results.replace_one(
            {'scan_id': scan_id},
            {'scan_id': scan_id, 'findings': result.get('findings', []),
             'recon': result.get('recon', {}), 'ports': result.get('ports', []),
             'attack_chains': result.get('attack_chains', []),
             'verification': result.get('verification', {})},
            upsert=True,
        )
        # === v7.2 Post-scan: screenshots + notifications ===
        try:
            if req.capture_screenshots and result.get('findings'):
                from finding_screenshot import capture_findings_batch
                shots = await capture_findings_batch(
                    scan_id,
                    [f for f in result.get('findings', []) if f.get('verified')],
                    max_screenshots=15,
                )
                _log_cb(f'[+] Captured {len(shots)} finding screenshot(s)')
                await db.vuln_scan_results.update_one(
                    {'scan_id': scan_id}, {'$set': {'finding_screenshots': shots}}
                )
        except Exception as se:
            _log_cb(f'[!] Screenshot capture failed: {se}')

        try:
            if req.notify and result.get('summary', {}).get('critical', 0) > 0:
                notify_cfg = await db.notify_config.find_one({'owner_id': owner_id})
                if notify_cfg:
                    from vuln.notifier import dispatch_notification
                    summ = result.get('summary', {})
                    title = f'🔴 CyberScope: {summ.get("critical", 0)} critical on {req.target}'
                    body = (f'Target: {req.target}\n'
                            f'Total: {summ.get("total", 0)} | Critical: {summ.get("critical", 0)} '
                            f'| High: {summ.get("high", 0)} | Medium: {summ.get("medium", 0)}\n'
                            f'Scan ID: {scan_id}')
                    await dispatch_notification(notify_cfg, title, body, 'critical',
                                                payload={'scan_id': scan_id, 'summary': summ})
                    _log_cb('[+] Notifications dispatched')
        except Exception as ne:
            _log_cb(f'[!] Notification failed: {ne}')
    except asyncio.CancelledError:
        # v7.4 — user-initiated cancel. Persist partial state, then re-raise.
        _log_cb('[!] Scan cancelled by user')
        VULN_SCANS[scan_id] = {'status': 'cancelled', 'logs': logs}
        await db.vuln_scans.update_one(
            {'id': scan_id},
            {'$set': {'status': 'cancelled', 'logs': logs[-200:],
                      'finished_at': datetime.now(timezone.utc).isoformat()}},
        )
        return
    except Exception as e:
        import traceback
        err = f'{type(e).__name__}: {e}'
        VULN_SCANS[scan_id] = {'status': 'failed', 'logs': logs, 'error': err}
        _log_cb(f'ERROR: {err}')
        _log_cb(traceback.format_exc()[:2000])
        await db.vuln_scans.update_one(
            {'id': scan_id},
            {'$set': {'status': 'failed', 'error': err, 'logs': logs[-200:],
                      'finished_at': datetime.now(timezone.utc).isoformat()}},
        )
    finally:
        # v7.7.1 · always stop the background log flush loop, even on cancel/error.
        _flush_stop.set()
        try:
            await asyncio.wait_for(_flush_task, timeout=2.0)
        except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
            pass


@api.get('/vuln/info')
async def vuln_info():
    if not VULN_AVAILABLE:
        return {'available': False, 'error': _VULN_IMPORT_ERROR}
    # Merge static payload registry + on-disk Wordlist Encyclopedia
    static_counts = vuln_count_payloads()
    try:
        from vuln.wordlist_manager import stats as _wl_stats
        wl_counts = _wl_stats()
    except Exception:
        wl_counts = {}
    encyclopedia_total = sum(wl_counts.values()) if wl_counts else 0
    combined_total = (static_counts.get('TOTAL') or 0) + encyclopedia_total
    return {
        'available': True,
        'version': '7.8.0',
        'codename': 'CyberScope Weaponized v7.8 · Attack Wave',
        'payload_counts': {**static_counts, 'ENCYCLOPEDIA': encyclopedia_total, 'GRAND_TOTAL': combined_total},
        'encyclopedia': wl_counts,
        'modules': [
            'fingerprint', 'recon', 'crawler_v2', 'xss', 'sqli', 'nosqli', 'cmd', 'ssti', 'lfi', 'xxe',
            'ssrf', 'open_redirect', 'cors', 'crlf', 'smuggling', 'smuggling_v2', 'cache_poisoning', 'cache_v2',
            'prototype_pollution', 'prototype_pollution_v2', 'graphql', 'graphql_v2', 'deserialization',
            'cloud_buckets', 'infra_apis', 'cve_templates', 'cve_correlate', 'cve_feed', 'secrets', 'port_scan',
            'host_header', 'web_cache_deception', 'client_proto', 'csp',
            'directory_listing', 'http_methods', 'sri',
            'api_security', 'oauth_saml', 'mobile_backend', 'web3',
            'mutation_engine', 'ai_destroyer', 'ai_autopilot', 'ai_payload_generator', 'verification_layer',
            'jwt_cracker', 'websocket', 'race_condition',
            'ssrf_deep', 'mfa_bypass', 'compliance_mapper', 'business_intel', 'threat_intel',
        ],
    }


@api.post('/vuln/scans')
async def create_vuln_scan(req: VulnScanRequest, bg: BackgroundTasks, request: Request):
    if not VULN_AVAILABLE:
        raise HTTPException(500, f'Vuln scanner not available: {_VULN_IMPORT_ERROR}')
    # SEC-005 · Rate limit: 20 scans / hour per IP for anon; auth users get more.
    owner_id = await _current_owner(request)
    is_auth = owner_id != 'guest'
    _rate_limit_check(request, bucket='scan-launch',
                      limit=200 if is_auth else 20,
                      per_seconds=3600)
    # SEC-001 · Reject dangerous targets right at the API boundary so we don't
    # even schedule a background task for internal/loopback URLs.
    from vuln.ssrf_guard import is_url_safe
    target = (req.target or '').strip()
    if not target:
        raise HTTPException(400, 'target is required')
    check_url = target if target.startswith(('http://', 'https://')) else 'https://' + target
    ok, reason = is_url_safe(check_url, allow_internal=False)
    if not ok:
        raise HTTPException(400, f'target rejected by SSRF guard: {reason}')
    # P3 · Anonymous callers cannot set a custom proxy (would route backend
    # traffic through attacker infrastructure). Authenticated users can.
    if not is_auth and req.proxy:
        raise HTTPException(400, 'custom proxy requires an authenticated account')
    scan_id = str(uuid.uuid4())
    doc = {
        'id': scan_id, 'target': req.target, 'status': 'pending',
        'depth': req.depth, 'modules': req.modules, 'disabled': req.disabled,
        'owner_id': owner_id, 'started_at': datetime.now(timezone.utc).isoformat(),
        'summary': {}, 'logs': [], 'options': req.model_dump(),
    }
    await db.vuln_scans.insert_one(doc)
    bg.add_task(_run_vuln_scan_task, scan_id, req, owner_id)
    return {'scan_id': scan_id, 'status': 'pending'}


@api.get('/vuln/scans')
async def list_vuln_scans(request: Request, limit: int = Query(50, le=200), skip: int = 0):
    owner_id = await _current_owner(request)
    q: Dict[str, Any] = {'owner_id': owner_id}
    user = await auth_get_optional_user(request, db)
    if user and user.get('role') == 'admin':
        q = {}
    scans = await db.vuln_scans.find(q, {'_id': 0, 'logs': 0}).sort(
        'started_at', -1).skip(skip).limit(limit).to_list(limit)
    total = await db.vuln_scans.count_documents(q)
    return {'scans': scans, 'total': total}


@api.get('/vuln/scans/{scan_id}')
async def get_vuln_scan(scan_id: str, request: Request):
    # SEC-002 · ownership guard
    doc = await _owner_or_403(request, scan_id)
    live = VULN_SCANS.get(scan_id)
    if live:
        doc['live_status'] = live.get('status')
        doc['live_logs_count'] = len(live.get('logs') or [])
    return doc


@api.get('/vuln/scans/{scan_id}/logs')
async def get_vuln_scan_logs(scan_id: str, request: Request):
    await _owner_or_403(request, scan_id)  # SEC-002
    live = VULN_SCANS.get(scan_id)
    if live:
        return {'logs': live.get('logs', []), 'status': live.get('status')}
    doc = await db.vuln_scans.find_one({'id': scan_id}, {'logs': 1, 'status': 1, '_id': 0})
    if not doc:
        raise HTTPException(404, 'Not found')
    return {'logs': doc.get('logs', []), 'status': doc.get('status')}


@api.get('/vuln/scans/{scan_id}/findings')
async def get_vuln_scan_findings(scan_id: str, request: Request,
                                  severity: Optional[str] = None,
                                  vtype: Optional[str] = None,
                                  verified_only: bool = False,
                                  min_confidence: int = 0,
                                  limit: int = Query(500, le=5000)):
    await _owner_or_403(request, scan_id)  # SEC-002
    doc = await db.vuln_scan_results.find_one({'scan_id': scan_id}, {'_id': 0})
    if not doc:
        # Maybe still running
        live = VULN_SCANS.get(scan_id)
        if live and live.get('result'):
            findings = live['result'].get('findings', [])
            recon = live['result'].get('recon', {})
            ports = live['result'].get('ports', [])
            chains = live['result'].get('attack_chains', []) or []
            verification = live['result'].get('verification', {})
        else:
            return {'findings': [], 'recon': {}, 'ports': [],
                    'attack_chains': [], 'verification': {}}
    else:
        findings = doc.get('findings', [])
        recon = doc.get('recon', {})
        ports = doc.get('ports', [])
        chains = doc.get('attack_chains', []) or []
        verification = doc.get('verification', {})

    def _match(f):
        if severity and (f.get('severity') or '').lower() != severity.lower():
            return False
        if vtype and (f.get('type') or '').lower() != vtype.lower():
            return False
        if verified_only and not f.get('verified'):
            return False
        if min_confidence and (f.get('confidence', 0) or 0) < min_confidence:
            return False
        return True

    # v7: Strong API-layer dedupe (defence in depth — even if scan engine misses one)
    def _dedupe_findings(items: List[Dict]) -> List[Dict]:
        from urllib.parse import urlparse, parse_qsl
        seen = set()
        out = []
        # First, aggressive dedupe for cloud_bucket findings with no URL (legacy false positives)
        # collapse into a single "info" summary
        collapsed_cloud = {}
        rest = []
        for f in items:
            if (f.get('type') == 'cloud_bucket'
                    and not f.get('url')
                    and f.get('subtype') in ('s3_takeover', 'gcs_takeover')):
                key = (f.get('subtype'), f.get('provider'))
                if key not in collapsed_cloud:
                    collapsed_cloud[key] = {**f, 'count': 1, 'severity': 'info', 'cvss': 0,
                                            'note': 'Legacy false-positive suppressed (v7 fix). Re-run scan for accurate results.'}
                else:
                    collapsed_cloud[key]['count'] += 1
            else:
                rest.append(f)
        for c in collapsed_cloud.values():
            rest.insert(0, c)
        for f in rest:
            url = f.get('url') or ''
            try:
                p = urlparse(url)
                norm_url = f'{p.scheme}://{p.netloc}{p.path}'
                pnames = tuple(sorted({k for k, _ in parse_qsl(p.query, keep_blank_values=True)}))
            except Exception:
                norm_url, pnames = url, ()
            key = (
                f.get('type'), f.get('subtype'), norm_url,
                f.get('param') or '', pnames,
                f.get('secret_type') or '', f.get('bucket') or '',
                (f.get('cve') or '')[:20],
            )
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out

    # v7.2: Re-apply strict verifier on retrieval so legacy scans get the
    # latest false-positive-suppression rules automatically.
    try:
        import sys as _sys
        _sys.path.insert(0, str(SCANNER_DIR))
        from vuln.verifier import verify_all as _verify_all
        findings = _verify_all(findings)
    except Exception:
        pass  # Verifier optional at API layer

    findings = _dedupe_findings(findings)
    filtered = [f for f in findings if _match(f)]
    crawler = recon.get('crawler', {}) or {}
    return {'total': len(filtered), 'findings': filtered[:limit],
            'attack_chains': chains,
            'verification': verification or {
                'verified': sum(1 for f in findings if f.get('verified') is True),
                'unverified': sum(1 for f in findings if f.get('verified') is False),
                'total': len(findings),
            },
            'recon_summary': {
                'urls_discovered': len(recon.get('urls_discovered', [])),
                'content_discovery': len(recon.get('content_discovery', [])),
                'js_findings_secrets': len(recon.get('js_findings', {}).get('secrets', [])),
                'forms_count': len(recon.get('html_findings', {}).get('forms', [])),
                'crawler_pages': crawler.get('visited_count', 0),
                'crawler_endpoints': len(crawler.get('endpoints', [])),
                'crawler_params': len(crawler.get('params_found', [])),
                'crawler_forms': len(crawler.get('forms', [])),
                'sitemap_urls': crawler.get('sitemap_urls_count', 0),
            }, 'ports': ports}


@api.delete('/vuln/scans/{scan_id}')
async def delete_vuln_scan(scan_id: str, request: Request):
    await _owner_or_403(request, scan_id)  # SEC-002
    r = await db.vuln_scans.delete_one({'id': scan_id})
    await db.vuln_scan_results.delete_one({'scan_id': scan_id})
    VULN_SCANS.pop(scan_id, None)
    return {'deleted': r.deleted_count}


# ============ v7.4 · STOP + BULK OPERATIONS ============

class BulkIdsRequest(BaseModel):
    model_config = ConfigDict(extra='ignore')
    ids: List[str] = Field(default_factory=list)


async def _filter_owned_ids(request: Request, ids: List[str]) -> List[str]:
    """SEC-002 · Only return IDs the caller is allowed to modify.
    Admins get everything. Guests / users get only what they own."""
    if not ids:
        return []
    owner_id = await _current_owner(request)
    try:
        user = await auth_get_optional_user(request, db)
    except Exception:
        user = None
    if user and user.get('role') == 'admin':
        docs = await db.vuln_scans.find({'id': {'$in': ids}}, {'_id': 0, 'id': 1}).to_list(len(ids))
    else:
        docs = await db.vuln_scans.find(
            {'id': {'$in': ids}, 'owner_id': owner_id},
            {'_id': 0, 'id': 1},
        ).to_list(len(ids))
    return [d['id'] for d in docs]


@api.post('/vuln/scans/{scan_id}/cancel')
async def cancel_vuln_scan(scan_id: str, request: Request):
    """Immediately signal a running vuln scan to stop between phases.
    Updates DB status to 'cancelled' right away so the UI reflects it."""
    doc = await _owner_or_403(request, scan_id)  # SEC-002
    live = VULN_SCANS.get(scan_id)
    already_done = False
    scanner_obj = None
    if live:
        scanner_obj = live.get('scanner')
        if live.get('status') in ('completed', 'failed', 'cancelled'):
            already_done = True
    if scanner_obj is not None:
        try:
            scanner_obj.request_cancel()
        except Exception:
            pass
        VULN_SCANS.setdefault(scan_id, {})['status'] = 'cancelling'
    # Update DB status to cancelled immediately (best-effort — engine will also
    # persist 'cancelled' when the CancelledError propagates).
    if doc.get('status') not in ('completed', 'failed', 'cancelled'):
        await db.vuln_scans.update_one(
            {'id': scan_id},
            {'$set': {'status': 'cancelled',
                      'finished_at': datetime.now(timezone.utc).isoformat()}},
        )
    return {'ok': True, 'scan_id': scan_id, 'already_done': already_done}


@api.post('/vuln/scans/bulk-cancel')
async def bulk_cancel_vuln_scans(req: BulkIdsRequest, request: Request):
    """Stop many scans in one shot. SEC-002 — silently filters to owned scans only."""
    allowed = await _filter_owned_ids(request, req.ids[:200])
    stopped = []
    for sid in allowed:
        live = VULN_SCANS.get(sid)
        if live and live.get('scanner'):
            try:
                live['scanner'].request_cancel()
                live['status'] = 'cancelling'
                stopped.append(sid)
            except Exception:
                pass
        doc = await db.vuln_scans.find_one({'id': sid}, {'_id': 0, 'status': 1})
        if doc and doc.get('status') not in ('completed', 'failed', 'cancelled'):
            await db.vuln_scans.update_one(
                {'id': sid},
                {'$set': {'status': 'cancelled',
                          'finished_at': datetime.now(timezone.utc).isoformat()}},
            )
            if sid not in stopped:
                stopped.append(sid)
    return {'ok': True, 'stopped': stopped, 'count': len(stopped),
            'requested': len(req.ids), 'authorized': len(allowed)}


@api.post('/vuln/scans/bulk-delete')
async def bulk_delete_vuln_scans(req: BulkIdsRequest, request: Request):
    """Delete many scans (and their results) in one shot.
    SEC-002 — silently filters to owned scans only."""
    ids = req.ids[:500]
    if not ids:
        return {'deleted': 0, 'ids': [], 'requested': 0, 'authorized': 0}
    allowed = await _filter_owned_ids(request, ids)
    if not allowed:
        return {'deleted': 0, 'ids': [], 'requested': len(ids), 'authorized': 0}
    # Cancel any running scans first so background tasks don't keep writing.
    for sid in allowed:
        live = VULN_SCANS.get(sid)
        if live and live.get('scanner'):
            try:
                live['scanner'].request_cancel()
            except Exception:
                pass
        VULN_SCANS.pop(sid, None)
    r1 = await db.vuln_scans.delete_many({'id': {'$in': allowed}})
    await db.vuln_scan_results.delete_many({'scan_id': {'$in': allowed}})
    return {'deleted': r1.deleted_count, 'ids': allowed,
            'requested': len(ids), 'authorized': len(allowed)}


_cors_origins = os.environ.get('CORS_ORIGINS', '*').split(',')
# If CORS_ORIGINS is "*", allow all but no credentials (browser restriction).
# Otherwise, allow explicit origins WITH credentials for auth cookies.
_allow_credentials = '*' not in _cors_origins
app.add_middleware(
    CORSMiddleware,
    allow_credentials=_allow_credentials,
    allow_origins=_cors_origins if not _allow_credentials else ['*'],
    allow_origin_regex=r'https://.+\.emergent(agent)?\.(com|host)' if _allow_credentials else None,
    allow_methods=['*'], allow_headers=['*'],
)


# ==========================================================================
# v7.2 BATCH-1 ENDPOINTS: AI Explainer, Report Gen, Subdomains, Notifications,
# Custom Payloads, Screenshot Serving
# ==========================================================================

class AIExplainRequest(BaseModel):
    model_config = ConfigDict(extra='ignore')
    finding_index: int
    lang: str = 'ar'


@api.post('/vuln/scans/{scan_id}/explain')
async def ai_explain_finding(scan_id: str, req: AIExplainRequest, request: Request):
    """AI-powered explanation for a specific finding (Arabic or English)."""
    await _owner_or_403(request, scan_id)  # SEC-002
    doc = await db.vuln_scan_results.find_one({'scan_id': scan_id}, {'_id': 0})
    if not doc:
        raise HTTPException(404, 'Scan not found')
    findings = doc.get('findings', [])
    if req.finding_index < 0 or req.finding_index >= len(findings):
        raise HTTPException(400, 'Invalid finding_index')
    from vuln.ai_explainer import explain_finding
    result = await explain_finding(findings[req.finding_index], lang=req.lang,
                                    session_id=f'{scan_id}-{req.finding_index}')
    return result


@api.post('/vuln/scans/{scan_id}/suggest-chains')
async def ai_suggest_chains(scan_id: str, request: Request, lang: str = 'ar'):
    """LLM-generated novel attack chains."""
    await _owner_or_403(request, scan_id)  # SEC-002
    doc = await db.vuln_scan_results.find_one({'scan_id': scan_id}, {'_id': 0})
    if not doc:
        raise HTTPException(404, 'Scan not found')
    from vuln.ai_explainer import suggest_attack_chain
    return await suggest_attack_chain(doc.get('findings', []), lang=lang)


# ============ v7.5 · AI False-Positive Predictor ============

@api.post('/vuln/scans/{scan_id}/fp-predict')
async def predict_false_positives(scan_id: str, request: Request, use_llm: bool = False):
    """
    Score every finding for false-positive likelihood.
    * use_llm=false (default) — instant heuristic-only scoring.
    * use_llm=true            — uses Claude Sonnet 4.6 via Emergent LLM key
                                (blended 50/50 with heuristic).
    """
    await _owner_or_403(request, scan_id)  # SEC-002
    # SEC-005 · Rate limit LLM calls harder than heuristic ones.
    if use_llm:
        _rate_limit_check(request, bucket='fp-llm', limit=30, per_seconds=3600)
    else:
        _rate_limit_check(request, bucket='fp-heuristic', limit=300, per_seconds=3600)
    doc = await db.vuln_scan_results.find_one({'scan_id': scan_id}, {'_id': 0})
    if not doc:
        raise HTTPException(404, 'Scan not found')
    from vuln.fp_predictor import heuristic_predict, llm_predict, bucket
    findings = doc.get('findings', [])
    scored = (await llm_predict(findings)) if use_llm else heuristic_predict(findings)
    buckets = {'likely_real': 0, 'review': 0, 'likely_fp': 0}
    slim = []
    for i, f in enumerate(scored):
        b = bucket(f.get('fp_score', 0.0))
        buckets[b] += 1
        # v7.6.1 · Emit a stable content key so the UI can align badges even
        # when the /findings endpoint re-orders / dedupes items.
        content_key = '|'.join([
            str(f.get('type') or ''),
            str(f.get('subtype') or ''),
            str(f.get('url') or ''),
            str(f.get('param') or ''),
        ])
        slim.append({
            'id': i,
            'key': content_key,
            'type': f.get('type'),
            'subtype': f.get('subtype'),
            'severity': f.get('severity'),
            'url': f.get('url'),
            'param': f.get('param'),
            'fp_score': f.get('fp_score'),
            'fp_layer': f.get('fp_layer'),
            'fp_reason': f.get('fp_reason'),
            'bucket': b,
        })
    return {
        'scan_id': scan_id,
        'count': len(scored),
        'scores': slim,
        'buckets': buckets,
        'used_llm': bool(use_llm),
    }


@api.get('/vuln/scans/{scan_id}/report.md', response_class=PlainTextResponse)
async def download_report_markdown(scan_id: str, request: Request, include_unverified: bool = False):
    await _owner_or_403(request, scan_id)  # SEC-002
    scan = await db.vuln_scans.find_one({'id': scan_id}, {'_id': 0})
    res = await db.vuln_scan_results.find_one({'scan_id': scan_id}, {'_id': 0})
    if not scan or not res:
        raise HTTPException(404, 'Scan not found')
    from vuln.report_generator import generate_markdown_report
    md = generate_markdown_report(scan, res.get('findings', []),
                                   res.get('attack_chains', []),
                                   res.get('recon', {}),
                                   include_unverified=include_unverified)
    return PlainTextResponse(md, media_type='text/markdown')


@api.get('/vuln/scans/{scan_id}/report.html', response_class=HTMLResponse)
async def download_report_html(scan_id: str, request: Request, include_unverified: bool = False):
    await _owner_or_403(request, scan_id)  # SEC-002
    scan = await db.vuln_scans.find_one({'id': scan_id}, {'_id': 0})
    res = await db.vuln_scan_results.find_one({'scan_id': scan_id}, {'_id': 0})
    if not scan or not res:
        raise HTTPException(404, 'Scan not found')
    from vuln.report_generator import generate_html_report
    html = generate_html_report(scan, res.get('findings', []),
                                 res.get('attack_chains', []),
                                 res.get('recon', {}),
                                 include_unverified=include_unverified)
    return HTMLResponse(html)


# ============ v7.6 · Batch 5.2 · CI/CD Integration Generators ============

@api.get('/ci/github-action.yml', response_class=PlainTextResponse)
async def download_github_action(target: str = '',
                                  depth: str = 'shallow',
                                  fail_on_severity: str = 'high'):
    """
    Generate a ready-to-drop GitHub Actions workflow that runs the CyberScope
    CLI against `target` on every push/PR and fails the build if any finding
    at or above `fail_on_severity` is discovered.
    """
    target = (target or '${{ vars.CYBERSCOPE_TARGET }}').strip()
    depth = depth if depth in ('shallow', 'medium', 'deep') else 'shallow'
    fail_on_severity = fail_on_severity if fail_on_severity in (
        'critical', 'high', 'medium', 'low', 'info') else 'high'
    yaml = f"""# .github/workflows/cyberscope.yml — auto-generated by CyberScope v7.6
name: CyberScope Security Scan
on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]
  schedule:
    - cron: '0 3 * * 1'   # weekly, Mondays 03:00 UTC
  workflow_dispatch: {{}}

jobs:
  security-scan:
    runs-on: ubuntu-latest
    timeout-minutes: 25
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install CyberScope
        run: |
          curl -fsSL https://github.com/OWNER/REPO/releases/latest/download/takeover-scanner-v6.tar.gz -o cyberscope.tar.gz
          tar xzf cyberscope.tar.gz && cd takeover-scanner-v6
          pip install -r backend/requirements.txt
      - name: Run scan
        working-directory: takeover-scanner-v6
        run: |
          python3 cyberscope_cli.py scan '{target}' \\
            --depth {depth} \\
            --json /tmp/scan.json
      - name: Fail build on severity >= {fail_on_severity}
        working-directory: takeover-scanner-v6
        run: |
          python3 <<'PY'
          import json, sys
          data = json.load(open('/tmp/scan.json'))
          bad = [f for f in data.get('findings', [])
                 if f.get('severity') in {{
                   'critical': ['critical'],
                   'high':     ['critical', 'high'],
                   'medium':   ['critical', 'high', 'medium'],
                   'low':      ['critical', 'high', 'medium', 'low'],
                   'info':     ['critical', 'high', 'medium', 'low', 'info'],
                 }}.get('{fail_on_severity}', [])]
          if bad:
              print(f'::error::found {{len(bad)}} finding(s) at or above {fail_on_severity}')
              for f in bad[:20]:
                  print(f'::error file={{f.get("url","?")}}::{{f.get("severity","?").upper()}} · {{f.get("type","?")}} — {{f.get("evidence","")[:120]}}')
              sys.exit(1)
          print(f'no findings at/above {fail_on_severity} — OK')
          PY
      - name: Upload scan report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: cyberscope-report
          path: /tmp/scan.json
"""
    return PlainTextResponse(yaml, media_type='text/yaml',
                              headers={'Content-Disposition': 'attachment; filename="cyberscope.yml"'})


@api.get('/ci/gitlab-ci.yml', response_class=PlainTextResponse)
async def download_gitlab_ci(target: str = '',
                              depth: str = 'shallow',
                              fail_on_severity: str = 'high'):
    """GitLab CI equivalent of the GitHub Action generator."""
    target = (target or '$CYBERSCOPE_TARGET').strip()
    depth = depth if depth in ('shallow', 'medium', 'deep') else 'shallow'
    yaml = f"""# .gitlab-ci.yml snippet — auto-generated by CyberScope v7.6
stages:
  - security

cyberscope-scan:
  stage: security
  image: python:3.11-slim
  timeout: 25 minutes
  script:
    - apt-get update && apt-get install -y curl
    - curl -fsSL https://your.host/takeover-scanner-v6.tar.gz -o cs.tar.gz
    - tar xzf cs.tar.gz && cd takeover-scanner-v6
    - pip install -r backend/requirements.txt
    - python3 cyberscope_cli.py scan "{target}" --depth {depth} --json scan.json
    - |
      python3 - <<'PY'
      import json, sys
      d = json.load(open('scan.json'))
      thresh = {{'critical': ['critical'], 'high': ['critical','high'],
                 'medium': ['critical','high','medium']}}.get('{fail_on_severity}', ['critical','high'])
      bad = [f for f in d.get('findings',[]) if f.get('severity') in thresh]
      if bad:
          for f in bad[:20]: print(f)
          sys.exit(1)
      PY
  artifacts:
    when: always
    paths: [takeover-scanner-v6/scan.json]
"""
    return PlainTextResponse(yaml, media_type='text/yaml',
                              headers={'Content-Disposition': 'attachment; filename=".gitlab-ci.yml"'})


@api.get('/vuln/scans/{scan_id}/screenshot/{finding_hash}')
async def get_finding_screenshot(scan_id: str, finding_hash: str, request: Request):
    """Serve a captured finding screenshot as PNG."""
    await _owner_or_403(request, scan_id)  # SEC-002
    from finding_screenshot import FINDING_SHOTS_DIR
    path = FINDING_SHOTS_DIR / f'{scan_id}_{finding_hash}.png'
    if not path.exists():
        raise HTTPException(404, 'Screenshot not found')
    return FileResponse(str(path), media_type='image/png')


@api.get('/subdomains/{domain}')
async def discover_subs(domain: str):
    from vuln.subdomain_discovery import discover_subdomains
    domain = domain.strip().lower().rstrip('/')
    if not domain or '/' in domain or ' ' in domain:
        raise HTTPException(400, 'Invalid domain')
    return await discover_subdomains(domain)


# ---- Notifications config CRUD ----
class NotifyConfig(BaseModel):
    model_config = ConfigDict(extra='ignore')
    slack_webhook: Optional[str] = None
    discord_webhook: Optional[str] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    generic_webhook: Optional[str] = None
    email_to: Optional[str] = None
    smtp: Optional[Dict[str, Any]] = None


# SEC-004 · Fields that must never leak to the API response.
_NOTIFY_SECRET_FIELDS = {
    'slack_webhook', 'discord_webhook', 'telegram_bot_token', 'generic_webhook',
}


def _mask_secret(value: Optional[str]) -> Optional[str]:
    if not value or not isinstance(value, str):
        return value
    if len(value) <= 8:
        return '***'
    return f'{value[:4]}…{value[-4:]}'


def _mask_notify_config(doc: Dict) -> Dict:
    """Return a copy of the notify_config safe to send to the client.
    Never leaks secret values — only masked previews and a `_has_*` flag so
    the UI can render "configured / not configured" state."""
    out = {'owner_id': doc.get('owner_id')}
    for k in ('slack_webhook', 'discord_webhook', 'telegram_bot_token',
              'telegram_chat_id', 'generic_webhook', 'email_to'):
        v = doc.get(k)
        if k in _NOTIFY_SECRET_FIELDS:
            out[f'{k}_preview'] = _mask_secret(v) if v else None
            out[f'{k}_configured'] = bool(v)
        else:
            out[k] = v
    smtp = doc.get('smtp') or {}
    if smtp:
        # Mask smtp password if present
        smtp_masked = {k: v for k, v in smtp.items() if k != 'password'}
        smtp_masked['password_configured'] = bool(smtp.get('password'))
        out['smtp'] = smtp_masked
    return out


@api.get('/vuln/notify-config')
async def get_notify_config(request: Request):
    """SEC-004 · Returns notify config with secrets MASKED. Requires auth."""
    owner_id = await _current_owner(request)
    doc = await db.notify_config.find_one({'owner_id': owner_id}, {'_id': 0})
    return _mask_notify_config(doc or {'owner_id': owner_id})


@api.post('/vuln/notify-config')
async def set_notify_config(cfg: NotifyConfig, request: Request):
    """SEC-004 · Merge-update. Empty / missing fields do NOT clear existing
    values so masked previews don't accidentally overwrite real secrets."""
    owner_id = await _current_owner(request)
    incoming = cfg.model_dump(exclude_none=True)
    existing = await db.notify_config.find_one({'owner_id': owner_id}, {'_id': 0}) or {}
    # Merge: incoming overrides existing; missing keys keep their prior value.
    merged = {**existing, **incoming, 'owner_id': owner_id}
    await db.notify_config.replace_one({'owner_id': owner_id}, merged, upsert=True)
    return {'ok': True}


@api.post('/vuln/notify-test')
async def test_notify(cfg: NotifyConfig, request: Request):
    """Send a test message. SEC-005 rate-limited (10/hr per IP)."""
    _rate_limit_check(request, bucket='notify-test', limit=10, per_seconds=3600)
    from vuln.notifier import dispatch_notification
    return await dispatch_notification(cfg.model_dump(exclude_none=True),
                                        '✅ CyberScope test notification',
                                        'This is a test message to verify your notification channels are configured correctly.',
                                        'info')


# ---- Custom Payloads CRUD ----
class CustomPayload(BaseModel):
    model_config = ConfigDict(extra='ignore')
    id: Optional[str] = None
    category: str  # xss, sqli, ssrf, lfi, cmd, ssti, etc.
    name: str
    payloads: List[str]
    enabled: bool = True


@api.get('/vuln/payloads/custom')
async def list_custom_payloads():
    docs = await db.custom_payloads.find({'owner_id': 'guest'}, {'_id': 0}).to_list(500)
    return {'items': docs, 'total': len(docs)}


@api.post('/vuln/payloads/custom')
async def add_custom_payload(p: CustomPayload):
    data = p.model_dump(exclude_none=True)
    data['id'] = data.get('id') or str(uuid.uuid4())
    data['owner_id'] = 'guest'
    data['created_at'] = datetime.now(timezone.utc).isoformat()
    await db.custom_payloads.replace_one({'id': data['id']}, data, upsert=True)
    return {'ok': True, 'id': data['id']}


@api.delete('/vuln/payloads/custom/{pid}')
async def delete_custom_payload(pid: str):
    r = await db.custom_payloads.delete_one({'id': pid, 'owner_id': 'guest'})
    return {'ok': True, 'deleted': r.deleted_count}


# ---- Scan Comparison ----
@api.get('/vuln/scans/{scan_a}/diff/{scan_b}')
async def diff_scans(scan_a: str, scan_b: str, request: Request):
    """Compare two scans — find new/fixed/unchanged findings.
    SEC-002 · Caller must own both scans (or be admin)."""
    await _owner_or_403(request, scan_a)
    await _owner_or_403(request, scan_b)
    a = await db.vuln_scan_results.find_one({'scan_id': scan_a}, {'_id': 0})
    b = await db.vuln_scan_results.find_one({'scan_id': scan_b}, {'_id': 0})
    if not a or not b:
        raise HTTPException(404, 'One or both scan results not found')

    def key(f):
        return (f.get('type'), f.get('subtype'),
                (f.get('url') or '').split('?')[0], f.get('param', ''))

    a_findings = a.get('findings', [])
    b_findings = b.get('findings', [])
    a_map = {key(f): f for f in a_findings}
    b_map = {key(f): f for f in b_findings}
    new_ = [f for k, f in b_map.items() if k not in a_map]
    fixed = [f for k, f in a_map.items() if k not in b_map]
    unchanged = [f for k, f in b_map.items() if k in a_map]

    # v7.6 · Severity-bucketed summary for the UI progress bar
    def _bucket(items):
        b = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in items:
            s = (f.get('severity') or 'info').lower()
            if s in b:
                b[s] += 1
        return b

    return {
        'scan_a': scan_a, 'scan_b': scan_b,
        'new': new_, 'fixed': fixed, 'unchanged_count': len(unchanged),
        'summary': {'new': len(new_), 'fixed': len(fixed),
                     'unchanged': len(unchanged)},
        'severity_new': _bucket(new_),
        'severity_fixed': _bucket(fixed),
    }


# ==========================================================================
# v7.3 BATCH-2: WebSocket logs, Nuclei importer, Scheduled scans, Rate/Proxy
# ==========================================================================

@app.websocket('/api/ws/scans/{scan_id}')
async def ws_scan_logs(websocket: WebSocket, scan_id: str):
    """
    Real-time log streaming for a running scan.
    Client connects → server pushes new log lines every second.
    """
    await websocket.accept()
    last_len = 0
    try:
        while True:
            live = VULN_SCANS.get(scan_id)
            if live:
                logs = list(live.get('logs', []))
                new_lines = logs[last_len:]
                last_len = len(logs)
                if new_lines:
                    await websocket.send_json({'type': 'logs', 'lines': new_lines})
                status = live.get('status', 'running')
                if status in ('completed', 'failed', 'cancelled', 'error', 'stopped'):
                    await websocket.send_json({'type': 'done', 'status': status})
                    break
            else:
                # Fallback to DB
                doc = await db.vuln_scans.find_one({'id': scan_id}, {'logs': 1, 'status': 1})
                if doc:
                    logs = doc.get('logs') or []
                    new_lines = logs[last_len:]
                    last_len = len(logs)
                    if new_lines:
                        await websocket.send_json({'type': 'logs', 'lines': new_lines})
                    if doc.get('status') in ('completed', 'failed', 'cancelled', 'error', 'stopped'):
                        await websocket.send_json({'type': 'done', 'status': doc['status']})
                        break
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass


# ---- Nuclei importer ----
class NucleiImportText(BaseModel):
    model_config = ConfigDict(extra='ignore')
    yaml_text: str


@api.post('/vuln/nuclei/import-text')
async def nuclei_import_text(req: NucleiImportText):
    from vuln.nuclei_importer import import_from_yaml_text
    result = import_from_yaml_text(req.yaml_text)
    if result.get('template'):
        tpl = result['template']
        tpl['owner_id'] = 'guest'
        tpl['created_at'] = datetime.now(timezone.utc).isoformat()
        await db.nuclei_templates.replace_one({'id': tpl['id']}, tpl, upsert=True)
    return result


@api.get('/vuln/nuclei/templates')
async def list_nuclei_templates():
    docs = await db.nuclei_templates.find({'owner_id': 'guest'}, {'_id': 0}).to_list(2000)
    return {'total': len(docs), 'templates': docs}


@api.delete('/vuln/nuclei/templates/{tid}')
async def delete_nuclei_template(tid: str):
    r = await db.nuclei_templates.delete_one({'id': tid, 'owner_id': 'guest'})
    return {'ok': True, 'deleted': r.deleted_count}


# ---- Scheduled scans ----
class ScheduledScanReq(BaseModel):
    model_config = ConfigDict(extra='ignore')
    id: Optional[str] = None
    target: str
    schedule: str = 'daily'  # daily | hourly | weekly | monthly | 'every 6h' | once
    depth: str = 'medium'
    modules: Optional[List[str]] = None
    enabled: bool = True
    name: Optional[str] = None


@api.post('/vuln/schedules')
async def create_schedule(req: ScheduledScanReq):
    from vuln.scheduler import next_run_from_schedule
    data = req.model_dump(exclude_none=True)
    data['id'] = data.get('id') or str(uuid.uuid4())
    data['owner_id'] = 'guest'
    data['created_at'] = datetime.now(timezone.utc).isoformat()
    nxt = next_run_from_schedule(req.schedule)
    data['next_run_at'] = nxt.isoformat() if nxt else None
    await db.scheduled_scans.replace_one({'id': data['id']}, data, upsert=True)
    return {'ok': True, 'id': data['id'], 'next_run_at': data['next_run_at']}


@api.get('/vuln/schedules')
async def list_schedules():
    docs = await db.scheduled_scans.find({'owner_id': 'guest'}, {'_id': 0}).to_list(500)
    return {'total': len(docs), 'schedules': docs}


@api.delete('/vuln/schedules/{sid}')
async def delete_schedule(sid: str):
    r = await db.scheduled_scans.delete_one({'id': sid, 'owner_id': 'guest'})
    return {'ok': True, 'deleted': r.deleted_count}


@api.post('/vuln/schedules/{sid}/toggle')
async def toggle_schedule(sid: str):
    doc = await db.scheduled_scans.find_one({'id': sid, 'owner_id': 'guest'})
    if not doc:
        raise HTTPException(404, 'schedule not found')
    new_val = not doc.get('enabled', True)
    await db.scheduled_scans.update_one({'id': sid}, {'$set': {'enabled': new_val}})
    return {'ok': True, 'enabled': new_val}


# ============ v7.7 · Batch 6 · Total Annihilation Scanner endpoints ============

@api.post('/vuln/crawl-v2')
async def crawler_v2_endpoint(payload: dict, request: Request):
    """
    Standalone crawler-v2 run — used both by the enhanced scanner and by
    UI power-users who want to preview attack surface before launching a scan.

    Body: {target, max_depth?, max_urls?, render_js?, mine_hidden_params?,
           extra_seeds?, har_seeds?}
    """
    from vuln.crawler_v2 import crawl_v2
    from vuln.http_client import AdaptiveHTTPClient
    from vuln.ssrf_guard import is_url_safe, set_scope_allowlist, clear_scope_allowlist
    from urllib.parse import urlparse

    target = (payload.get('target') or '').strip()
    if not target:
        raise HTTPException(400, 'target is required')
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    ok, reason = is_url_safe(target)
    if not ok:
        raise HTTPException(400, f'SSRF guard: {reason}')
    _rate_limit_check(request, bucket='crawl-v2', limit=30, per_seconds=3600)

    host = urlparse(target).hostname or ''
    set_scope_allowlist({host, host.lstrip('www.')})
    try:
        async with AdaptiveHTTPClient(concurrency=int(payload.get('concurrency', 12))) as client:
            result = await crawl_v2(
                client, target,
                max_depth=min(int(payload.get('max_depth', 3)), 5),
                max_urls=min(int(payload.get('max_urls', 400)), 2000),
                render_js=bool(payload.get('render_js', False)),
                mine_hidden_params=bool(payload.get('mine_hidden_params', True)),
                extra_seeds=payload.get('extra_seeds'),
                har_seeds=payload.get('har_seeds'),
            )
        return result
    finally:
        clear_scope_allowlist()


@api.post('/vuln/wordlists/sync')
async def sync_wordlists(request: Request, force: bool = False):
    """Download / refresh public payload lists into /app/scanner/wordlists/."""
    _rate_limit_check(request, bucket='wordlist-sync', limit=5, per_seconds=3600)
    from vuln.wordlist_manager import ensure_wordlists
    counts = await ensure_wordlists(force=force)
    return {'ok': True, 'counts': counts, 'total_payloads': sum(counts.values())}


@api.get('/vuln/wordlists/stats')
async def wordlists_stats():
    from vuln.wordlist_manager import stats, sample
    return {
        'counts': stats(),
        'sample_xss': sample('xss', 5),
        'sample_sqli': sample('sqli', 5),
    }


class MutateRequest(BaseModel):
    model_config = ConfigDict(extra='ignore')
    payload: str
    waf: Optional[str] = None
    encodings: Optional[List[str]] = None


@api.post('/vuln/mutate')
async def mutate_payload(req: MutateRequest, request: Request):
    """Return WAF-bypass variants for a base payload."""
    _rate_limit_check(request, bucket='mutate', limit=200, per_seconds=3600)
    from vuln.mutation_engine import mutate, bypass
    return {
        'base': req.payload,
        'waf': req.waf,
        'mutations': mutate(req.payload, req.encodings),
        'waf_bypasses': bypass(req.payload, req.waf) if req.waf else [],
    }


@api.post('/vuln/scans/{scan_id}/ai-verify/{finding_idx}')
async def ai_verify_finding(scan_id: str, finding_idx: int, request: Request):
    """AI Destroyer — verify a single finding with LLM. Returns confirmed /
    needs_manual / false_positive plus Burp-Suite steps."""
    await _owner_or_403(request, scan_id)
    _rate_limit_check(request, bucket='ai-verify', limit=100, per_seconds=3600)
    doc = await db.vuln_scan_results.find_one({'scan_id': scan_id}, {'_id': 0})
    if not doc:
        raise HTTPException(404, 'scan results not found')
    findings = doc.get('findings', [])
    if finding_idx < 0 or finding_idx >= len(findings):
        raise HTTPException(400, 'finding_idx out of range')
    from vuln.ai_destroyer import verify_finding
    return await verify_finding(findings[finding_idx],
                                 session_id=f'{scan_id}-{finding_idx}')


@api.post('/vuln/scans/{scan_id}/ai-triage')
async def ai_triage_endpoint(scan_id: str, request: Request):
    """LLM-graded exploitability ranking (Auto-triage)."""
    await _owner_or_403(request, scan_id)
    _rate_limit_check(request, bucket='ai-triage', limit=30, per_seconds=3600)
    doc = await db.vuln_scan_results.find_one({'scan_id': scan_id}, {'_id': 0})
    if not doc:
        raise HTTPException(404, 'scan results not found')
    from vuln.ai_destroyer import auto_triage
    return await auto_triage(doc.get('findings', []))


@api.post('/vuln/scans/{scan_id}/ai-chains-v2')
async def ai_chains_v2(scan_id: str, request: Request, lang: str = 'en'):
    """AI Destroyer — build multi-step exploit chains from findings."""
    await _owner_or_403(request, scan_id)
    _rate_limit_check(request, bucket='ai-chains', limit=30, per_seconds=3600)
    doc = await db.vuln_scan_results.find_one({'scan_id': scan_id}, {'_id': 0})
    if not doc:
        raise HTTPException(404, 'scan results not found')
    from vuln.ai_destroyer import build_ai_chains
    return await build_ai_chains(doc.get('findings', []), lang=lang)


class CraftPayloadRequest(BaseModel):
    model_config = ConfigDict(extra='ignore')
    vulnerability_type: str
    waf: Optional[str] = ''
    tech: Optional[str] = ''
    original_payload: Optional[str] = ''
    observed_response: Optional[str] = ''


@api.post('/vuln/ai-craft')
async def ai_craft_endpoint(req: CraftPayloadRequest, request: Request):
    """AI Destroyer — craft 5 context-aware bypass payloads.
    v7.7.1 · anonymous callers are throttled harder because this hits the LLM."""
    owner_id = await _current_owner(request)
    is_auth = owner_id != 'guest'
    _rate_limit_check(request, bucket='ai-craft',
                      limit=120 if is_auth else 20,
                      per_seconds=3600)
    from vuln.ai_destroyer import craft_payload
    return await craft_payload(
        vulnerability_type=req.vulnerability_type,
        waf=req.waf or '', tech=req.tech or '',
        original_payload=req.original_payload or '',
        observed_response=req.observed_response or '',
    )


class SemanticDiffRequest(BaseModel):
    model_config = ConfigDict(extra='ignore')
    a: str
    b: str


@api.post('/vuln/semantic-diff')
async def semantic_diff_endpoint(req: SemanticDiffRequest, request: Request):
    """Verification-layer helper — smart response comparison."""
    _rate_limit_check(request, bucket='semantic-diff', limit=500, per_seconds=3600)
    from vuln.verification_layer import semantic_diff
    return semantic_diff(req.a, req.b)


@api.get('/vuln/batch6-info')
async def batch6_info():
    """Report which Batch 6 features are active."""
    from vuln.wordlist_manager import stats
    from vuln.verification_layer import oob_available
    ws = stats()
    return {
        'version': '7.7.0',
        'codename': 'Total Annihilation',
        'features': {
            'crawler_v2': True,
            'wordlist_encyclopedia': True,
            'ai_destroyer': bool(os.environ.get('EMERGENT_LLM_KEY')),
            'verification_layer': True,
            'auto_triage': True,
            'oob_configured': oob_available(),
        },
        'wordlist_counts': ws,
        'wordlist_total': sum(ws.values()),
    }


# ============ v7.7 · Batch 6.1 · Burp project export + history diff ============

@api.get('/vuln/scans/{scan_id}/burp.zip')
async def download_burp_project(scan_id: str, request: Request):
    """Export a scan as a Burp Suite-ready ZIP containing:
      * repeater/<idx>.http  — one raw HTTP request per finding
      * intruder/<idx>.txt   — an Intruder attack template with §payload§ marker
      * README.md            — how to import
    """
    await _owner_or_403(request, scan_id)
    doc = await db.vuln_scan_results.find_one({'scan_id': scan_id}, {'_id': 0})
    if not doc:
        raise HTTPException(404, 'scan results not found')
    scan_meta = await db.vuln_scans.find_one({'id': scan_id}, {'_id': 0})
    findings = doc.get('findings', [])

    import io
    import zipfile
    from urllib.parse import urlparse

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('README.md', (
            f'# CyberScope · Burp Project Bundle\n\n'
            f'Scan: {scan_id}\nTarget: {(scan_meta or {}).get("target", "?")}\n'
            f'Findings: {len(findings)}\n\n'
            '## How to use\n'
            '1. Extract this zip.\n'
            '2. Copy each `repeater/*.http` into a Burp Repeater tab.\n'
            '3. `intruder/*.txt` files show the exact position of the payload '
            '(look for `§...§` markers) — paste into Intruder tab.\n'
        ))
        for i, f in enumerate(findings[:100]):
            url = f.get('url') or ''
            method = (f.get('method') or 'GET').upper()
            param = f.get('param') or ''
            payload = f.get('payload') or ''
            try:
                p = urlparse(url)
                path = p.path or '/'
                if p.query:
                    path += '?' + p.query
                host = p.netloc
            except Exception:
                path, host = '/', 'target'
            headers = [
                f'Host: {host}',
                'User-Agent: Mozilla/5.0 CyberScope/7.7',
                'Accept: */*',
                'Connection: close',
            ]
            body = ''
            if method in ('POST', 'PUT', 'PATCH') and param and payload:
                body = f'{param}={payload}'
                headers.append('Content-Type: application/x-www-form-urlencoded')
                headers.append(f'Content-Length: {len(body)}')
            raw = f'{method} {path} HTTP/1.1\r\n' + '\r\n'.join(headers) + '\r\n\r\n' + body
            z.writestr(f'repeater/{i:03d}_{(f.get("type") or "vuln")[:20]}.http', raw)
            if payload and payload in raw:
                intruder = raw.replace(payload, '§' + payload + '§', 1)
            elif param and f'{param}=' in raw:
                intruder = raw.replace(f'{param}={payload}', f'{param}=§{payload}§', 1)
            else:
                intruder = raw
            z.writestr(
                f'intruder/{i:03d}_{(f.get("type") or "vuln")[:20]}.txt',
                (f'# {f.get("severity","?").upper()} · {f.get("type","?")}\n'
                 f'# evidence: {(f.get("evidence") or "")[:200]}\n\n' + intruder),
            )
    buf.seek(0)
    return Response(
        content=buf.read(),
        media_type='application/zip',
        headers={'Content-Disposition': f'attachment; filename="cyberscope-burp-{scan_id[:8]}.zip"'},
    )


@api.get('/vuln/history-diff')
async def vuln_history_diff(request: Request, target: str, limit: int = 30):
    """Time-ordered severity counts for every scan against `target`."""
    owner_id = await _current_owner(request)
    q = {'target': target, 'owner_id': owner_id}
    try:
        user = await auth_get_optional_user(request, db)
    except Exception:
        user = None
    if user and user.get('role') == 'admin':
        q = {'target': target}
    scans = await db.vuln_scans.find(q, {'_id': 0}).sort('started_at', -1).to_list(limit)
    scans.reverse()
    series = []
    for s in scans:
        summ = s.get('summary') or {}
        series.append({
            'scan_id': s.get('id'),
            'started_at': s.get('started_at'),
            'critical': summ.get('critical', 0),
            'high': summ.get('high', 0),
            'medium': summ.get('medium', 0),
            'low': summ.get('low', 0),
            'total': summ.get('total', 0),
        })
    return {'target': target, 'points': series, 'count': len(series)}


# ═══════════════════════════════════════════════════════════════════
#  v7.7.2 · TOTAL ANNIHILATION endpoints — JWT Cracker · GraphQL ·
#  WebSocket · Race Condition · AI Autopilot · Monitoring · Nuclei
#  live sync · CVE lookup.
# ═══════════════════════════════════════════════════════════════════

class JWTCrackRequest(BaseModel):
    token: str
    max_secrets: int = 100_000
    tamper: Optional[Dict[str, Any]] = None


@api.post('/vuln/jwt/inspect')
async def jwt_inspect(req: JWTCrackRequest, request: Request):
    """Decode a JWT and surface obvious red flags — no cracking."""
    _rate_limit_check(request, 'jwt_inspect', 20, 60)
    try:
        from vuln.jwt_cracker import inspect_token
        return {'result': inspect_token(req.token)}
    except Exception as e:
        raise HTTPException(500, f'jwt_inspect_error: {e}')


@api.post('/vuln/jwt/crack')
async def jwt_crack(req: JWTCrackRequest, request: Request):
    """
    Full crack: alg=none, HS256 weak-secret brute (100K default), plus
    inspection.  Rate-limited to 4/min — pure CPU work.
    """
    _rate_limit_check(request, 'jwt_crack', 4, 60)
    try:
        from vuln.jwt_cracker import crack_jwt
        return await crack_jwt(req.token, max_secrets=req.max_secrets, tamper=req.tamper)
    except Exception as e:
        raise HTTPException(500, f'jwt_crack_error: {e}')


class GraphQLProbeRequest(BaseModel):
    url: str


@api.post('/vuln/graphql/probe')
async def graphql_probe(req: GraphQLProbeRequest, request: Request):
    """Introspection + batching + depth-limit probe against a GraphQL URL."""
    _rate_limit_check(request, 'gql_probe', 12, 60)
    from vuln.ssrf_guard import is_url_safe as _safe
    from vuln.http_client import AdaptiveHTTPClient as _Http
    ok, err = _safe(req.url)
    if not ok:
        raise HTTPException(400, f'ssrf_guard: {err}')
    try:
        from vuln.graphql_scanner import scan_graphql as _sg
        async with _Http() as client:
            return await _sg(client, req.url)
    except Exception as e:
        raise HTTPException(500, f'graphql_probe_error: {e}')


class RaceRequest(BaseModel):
    url: str
    method: str = 'POST'
    json_body: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, str]] = None
    n: int = 50


@api.post('/vuln/race')
async def race_endpoint(req: RaceRequest, request: Request):
    """Fire N concurrent requests and detect race-condition surface."""
    _rate_limit_check(request, 'race', 6, 60)
    from vuln.ssrf_guard import is_url_safe as _safe
    from vuln.http_client import AdaptiveHTTPClient as _Http
    ok, err = _safe(req.url)
    if not ok:
        raise HTTPException(400, f'ssrf_guard: {err}')
    try:
        from vuln.race_condition import race_probe
        async with _Http() as client:
            return await race_probe(
                client, req.url, method=req.method, json_body=req.json_body,
                headers=req.headers, n=req.n)
    except Exception as e:
        raise HTTPException(500, f'race_error: {e}')


class AutopilotRequest(BaseModel):
    target: str
    depth: str = 'medium'


@api.post('/vuln/autopilot')
async def autopilot_endpoint(req: AutopilotRequest, request: Request, bg: BackgroundTasks):
    """
    Ask the AI to plan an attack for the target then run it.  Behaves like
    a normal /vuln/scans launch but marks the scan with `mode='autopilot'`
    and stashes the plan in the metadata.
    """
    _rate_limit_check(request, 'autopilot', 4, 60)
    from vuln.ssrf_guard import is_url_safe as _safe
    from vuln.http_client import AdaptiveHTTPClient as _Http
    ok, err = _safe(req.target)
    if not ok:
        raise HTTPException(400, f'ssrf_guard: {err}')
    if not VULN_AVAILABLE:
        raise HTTPException(500, 'vuln_scanner_unavailable')

    owner_id = await _current_owner(request)
    scan_id = str(uuid.uuid4())

    # We ask the AI for a plan BEFORE launching so the modules list is fixed.
    plan = {'modules': ['fingerprint', 'recon', 'crawler', 'xss', 'sqli', 'ssrf',
                        'open_redirect', 'cors', 'csp', 'directory_listing'],
            'reason': 'default-broad'}
    try:
        from vuln.ai_autopilot import plan_attack
        async with _Http() as client:
            fp_probe = await client.get(req.target)
            fp_dict = {
                'server': (fp_probe.headers or {}).get('server') or '',
                'x-powered-by': (fp_probe.headers or {}).get('x-powered-by') or '',
                'body_snippet': (fp_probe.text or '')[:1500],
            }
            plan_result = await plan_attack(fp_dict, req.target)
            if plan_result.get('modules'):
                plan = plan_result
    except Exception:
        pass  # fall back to default modules

    doc = {
        'id': scan_id,
        'owner_id': owner_id,
        'target': req.target,
        'depth': req.depth,
        'status': 'pending',
        'mode': 'autopilot',
        'plan': plan,
        'started_at': datetime.now(timezone.utc).isoformat(),
        'findings': [], 'summary': {}, 'logs': [],
    }
    await db.vuln_scans.insert_one(doc)
    scan_req = VulnScanRequest(
        target=req.target,
        depth=req.depth,
        modules=plan['modules'],
    )
    bg.add_task(_run_vuln_scan_task, scan_id, scan_req, owner_id)
    return {'scan_id': scan_id, 'status': 'pending', 'plan': plan}


@api.post('/vuln/scans/{scan_id}/exploit-chain')
async def build_exploit_chain_endpoint(scan_id: str, request: Request):
    """AI-driven exploit-chain builder for a completed scan."""
    _rate_limit_check(request, 'chain', 6, 60)
    owner_id = await _current_owner(request)
    scan = await db.vuln_scans.find_one({'id': scan_id, 'owner_id': owner_id}, {'_id': 0})
    if not scan:
        raise HTTPException(404, 'scan_not_found')
    try:
        from vuln.ai_autopilot import build_exploit_chain
        result = await build_exploit_chain(scan.get('findings') or [], scan.get('target') or '')
        # Persist result on the scan doc
        await db.vuln_scans.update_one(
            {'id': scan_id}, {'$set': {'exploit_chain': result}})
        return result
    except Exception as e:
        raise HTTPException(500, f'exploit_chain_error: {e}')


class MonitorRequest(BaseModel):
    target: str
    interval_hours: int = 24
    channels: List[str] = []  # 'discord', 'slack', 'telegram'
    webhook_url: Optional[str] = None
    active: bool = True


@api.get('/vuln/monitors-v2')
async def list_monitors_v2(request: Request):
    """List continuous attack surface monitors owned by the caller."""
    owner_id = await _current_owner(request)
    items = await db.vuln_monitors.find(
        {'owner_id': owner_id}, {'_id': 0}
    ).sort('created_at', -1).to_list(200)
    return {'monitors': items}


@api.post('/vuln/monitors-v2')
async def create_monitor_v2(req: MonitorRequest, request: Request):
    """Create a continuous monitor — a scan that runs every N hours."""
    from vuln.ssrf_guard import is_url_safe as _safe
    ok, err = _safe(req.target)
    if not ok:
        raise HTTPException(400, f'ssrf_guard: {err}')
    owner_id = await _current_owner(request)
    doc = {
        'id': str(uuid.uuid4()),
        'owner_id': owner_id,
        'target': req.target,
        'interval_hours': max(1, min(req.interval_hours, 24 * 30)),
        'channels': req.channels or [],
        'webhook_url': req.webhook_url,
        'active': req.active,
        'created_at': datetime.now(timezone.utc).isoformat(),
        'last_run_at': None,
        'last_run_summary': None,
        'runs_count': 0,
    }
    await db.vuln_monitors.insert_one(doc)
    doc.pop('_id', None)
    return doc


@api.delete('/vuln/monitors-v2/{mid}')
async def delete_monitor_v2(mid: str, request: Request):
    owner_id = await _current_owner(request)
    r = await db.vuln_monitors.delete_one({'id': mid, 'owner_id': owner_id})
    return {'deleted': r.deleted_count}


@api.post('/vuln/monitors-v2/{mid}/toggle')
async def toggle_monitor_v2(mid: str, request: Request):
    owner_id = await _current_owner(request)
    doc = await db.vuln_monitors.find_one({'id': mid, 'owner_id': owner_id})
    if not doc:
        raise HTTPException(404, 'monitor_not_found')
    new = not doc.get('active', True)
    await db.vuln_monitors.update_one({'id': mid}, {'$set': {'active': new}})
    return {'id': mid, 'active': new}


@api.get('/vuln/dashboard-stats')
async def dashboard_stats(request: Request):
    """v7.7.2 · Ops-focused KPI dump used by the new Dashboard."""
    owner_id = await _current_owner(request)
    q = {'owner_id': owner_id}
    total_scans = await db.vuln_scans.count_documents(q)
    running_count = await db.vuln_scans.count_documents(
        {**q, 'status': {'$in': ['pending', 'running', 'discovering',
                                 'analyzing', 'verifying', 'cancelling']}})
    # aggregate severities over last 30 scans
    scans = await db.vuln_scans.find(q, {'_id': 0}).sort('started_at', -1).to_list(30)
    agg = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'total': 0}
    by_type_agg: Dict[str, int] = {}
    for s in scans:
        sm = s.get('summary') or {}
        for k in agg:
            agg[k] += sm.get(k, 0) or 0
        for t, n in (sm.get('by_type') or {}).items():
            by_type_agg[t] = by_type_agg.get(t, 0) + (n or 0)
    monitors_count = await db.vuln_monitors.count_documents(q)
    return {
        'total_scans': total_scans,
        'running_count': running_count,
        'severities_last30': agg,
        'by_type_last30': by_type_agg,
        'monitors_count': monitors_count,
        'recent_scans': [
            {'id': s['id'], 'target': s.get('target'), 'status': s.get('status'),
             'depth': s.get('depth'), 'mode': s.get('mode'),
             'started_at': s.get('started_at'), 'summary': s.get('summary')}
            for s in scans[:10]
        ],
    }


# ═══════════════════════════════════════════════════════════════════
#  v7.8 · WEAPONIZED WAVE — new attack + intel endpoints (10 modules).
# ═══════════════════════════════════════════════════════════════════


class SmuggleRequest(BaseModel):
    urls: List[str]


@api.post('/vuln/smuggling-v2')
async def smuggling_v2_endpoint(req: SmuggleRequest, request: Request):
    _rate_limit_check(request, 'smuggle', 6, 60)
    from vuln.ssrf_guard import is_url_safe as _safe
    from vuln.http_client import AdaptiveHTTPClient as _Http
    from vuln.http_smuggling_v2 import scan_smuggling_v2
    for u in req.urls:
        ok, err = _safe(u)
        if not ok:
            raise HTTPException(400, f'ssrf_guard: {err}')
    try:
        async with _Http(timeout=10.0) as c:
            return await scan_smuggling_v2(c, req.urls)
    except Exception as e:
        raise HTTPException(500, f'smuggle_error: {e}')


class CacheRequest(BaseModel):
    urls: List[str]


@api.post('/vuln/cache-v2')
async def cache_v2_endpoint(req: CacheRequest, request: Request):
    _rate_limit_check(request, 'cache', 6, 60)
    from vuln.ssrf_guard import is_url_safe as _safe
    from vuln.http_client import AdaptiveHTTPClient as _Http
    from vuln.cache_deception_v2 import scan_cache_v2
    for u in req.urls:
        ok, err = _safe(u)
        if not ok:
            raise HTTPException(400, f'ssrf_guard: {err}')
    try:
        async with _Http(timeout=8.0) as c:
            return await scan_cache_v2(c, req.urls)
    except Exception as e:
        raise HTTPException(500, f'cache_error: {e}')


class PayloadGenRequest(BaseModel):
    category: str
    waf: str = 'None'
    count: int = 30
    context: str = ''
    avoid: List[str] = []


@api.post('/vuln/payloads/ai-generate')
async def ai_payload_gen(req: PayloadGenRequest, request: Request):
    _rate_limit_check(request, 'payload_gen', 6, 60)
    try:
        from vuln.ai_payload_generator import generate_payloads
        return await generate_payloads(
            req.category, waf=req.waf, count=min(60, max(5, req.count)),
            context=req.context, avoid=req.avoid,
        )
    except Exception as e:
        raise HTTPException(500, f'payload_gen_error: {e}')


class PPRequest(BaseModel):
    urls: List[str]


@api.post('/vuln/prototype-pollution')
async def pp_endpoint(req: PPRequest, request: Request):
    _rate_limit_check(request, 'pp', 6, 60)
    from vuln.ssrf_guard import is_url_safe as _safe
    from vuln.http_client import AdaptiveHTTPClient as _Http
    from vuln.prototype_pollution_v2 import scan_prototype_pollution
    for u in req.urls:
        ok, err = _safe(u)
        if not ok:
            raise HTTPException(400, f'ssrf_guard: {err}')
    try:
        async with _Http(timeout=8.0) as c:
            return await scan_prototype_pollution(c, req.urls)
    except Exception as e:
        raise HTTPException(500, f'pp_error: {e}')


class SSRFDeepRequest(BaseModel):
    ssrf_url_template: str   # must include {PAYLOAD}


@api.post('/vuln/ssrf-deep')
async def ssrf_deep_endpoint(req: SSRFDeepRequest, request: Request):
    _rate_limit_check(request, 'ssrf_deep', 4, 60)
    if '{PAYLOAD}' not in req.ssrf_url_template:
        raise HTTPException(400, 'ssrf_url_template must contain {PAYLOAD}')
    from vuln.ssrf_guard import is_url_safe as _safe
    from vuln.http_client import AdaptiveHTTPClient as _Http
    from vuln.ssrf_deep import exploit_via_ssrf
    # Guard the *template* itself (its non-payload part)
    ok, err = _safe(req.ssrf_url_template.replace('{PAYLOAD}', 'https://example.com'))
    if not ok:
        raise HTTPException(400, f'ssrf_guard: {err}')
    try:
        async with _Http(timeout=10.0) as c:
            return await exploit_via_ssrf(c, req.ssrf_url_template)
    except Exception as e:
        raise HTTPException(500, f'ssrf_deep_error: {e}')


class MFARequest(BaseModel):
    url: str
    form_field: str = 'code'
    headers: Optional[Dict[str, str]] = None


@api.post('/vuln/mfa-bypass')
async def mfa_endpoint(req: MFARequest, request: Request):
    _rate_limit_check(request, 'mfa', 4, 60)
    from vuln.ssrf_guard import is_url_safe as _safe
    from vuln.http_client import AdaptiveHTTPClient as _Http
    from vuln.mfa_bypass import scan_mfa_endpoint
    ok, err = _safe(req.url)
    if not ok:
        raise HTTPException(400, f'ssrf_guard: {err}')
    try:
        async with _Http(timeout=10.0) as c:
            return await scan_mfa_endpoint(c, req.url, form_field=req.form_field, headers=req.headers)
    except Exception as e:
        raise HTTPException(500, f'mfa_error: {e}')


@api.post('/vuln/scans/{scan_id}/compliance')
async def compliance_endpoint(scan_id: str, request: Request):
    """Map a completed scan's findings to OWASP/CWE/PCI/GDPR/SOC2/HIPAA."""
    owner_id = await _current_owner(request)
    scan = await db.vuln_scans.find_one({'id': scan_id, 'owner_id': owner_id}, {'_id': 0})
    if not scan:
        raise HTTPException(404, 'scan_not_found')
    from vuln.compliance_mapper import map_findings
    result = map_findings(scan.get('findings') or [])
    await db.vuln_scans.update_one({'id': scan_id}, {'$set': {'compliance': result}})
    return result


@api.post('/vuln/scans/{scan_id}/bounty-estimate')
async def bounty_estimate_endpoint(scan_id: str, request: Request):
    """Estimate expected bounty payout across findings."""
    owner_id = await _current_owner(request)
    scan = await db.vuln_scans.find_one({'id': scan_id, 'owner_id': owner_id}, {'_id': 0})
    if not scan:
        raise HTTPException(404, 'scan_not_found')
    from vuln.business_intel import estimate_bounty, estimate_business_impact
    findings = scan.get('findings') or []
    result = {
        'bounty': estimate_bounty(findings),
        'business_impact': estimate_business_impact(findings),
    }
    await db.vuln_scans.update_one({'id': scan_id}, {'$set': {'bounty_estimate': result}})
    return result


@api.post('/vuln/cve-feed/sync')
async def cve_feed_sync_endpoint(request: Request):
    """Manual trigger — sync the last 30 days of high-severity CVEs from NVD."""
    _rate_limit_check(request, 'cve_sync', 2, 60)
    from vuln.cve_feed_sync import sync_cves_to_db
    try:
        return await sync_cves_to_db(db)
    except Exception as e:
        raise HTTPException(500, f'cve_sync_error: {e}')


@api.post('/vuln/scans/{scan_id}/triage-v2')
async def triple_vote_triage(scan_id: str, request: Request, max_items: int = 20):
    """v7.9.2 · Triple-model AI triage (Claude · GPT · Gemini). Returns
    P0/P1/P2/P3 buckets + false-positive shortlist. Rate-limited to keep LLM
    cost predictable."""
    _rate_limit_check(request, 'triage_v2', 20, 3600)
    owner_id = await _current_owner(request)
    scan = await db.vuln_scans.find_one({'id': scan_id, 'owner_id': owner_id}, {'_id': 0})
    if not scan:
        raise HTTPException(404, 'scan_not_found')
    from vuln.ai_prioritizer import triage_findings
    try:
        result = await triage_findings(scan.get('findings') or [], max_items=min(50, max(1, max_items)))
    except Exception as e:
        raise HTTPException(500, f'triage_error: {e}')
    await db.vuln_scans.update_one({'id': scan_id}, {'$set': {'triage_v2': result}})
    return result


@api.post('/vuln/findings/verify-vote')
async def verify_finding_vote(request: Request):
    """v7.9.2 · Ad-hoc triple-vote for a single finding payload (POST body).
    Used by the playground / SDK integrations that don't need a full scan."""
    _rate_limit_check(request, 'verify_vote', 30, 3600)
    try:
        finding = await request.json()
    except Exception:
        raise HTTPException(400, 'invalid_json')
    if not isinstance(finding, dict):
        raise HTTPException(400, 'expected_object')
    from vuln.ai_prioritizer import triple_vote_verdict
    try:
        return await triple_vote_verdict(finding)
    except Exception as e:
        raise HTTPException(500, f'verify_error: {e}')


@api.get('/stats/social-proof')
async def social_proof(request: Request):
    """Public counter powering the landing-page social-proof banner.
    Returns paying customers, total scans this month, targets covered."""
    now = datetime.now(timezone.utc)
    seven_days_ago = now.timestamp() - 7 * 86400
    paying = await db.billing.count_documents({'tier': {'$in': ['pro', 'pro_plus', 'enterprise', 'lifetime']}})
    total_users = await db.users.count_documents({})
    scans_total = await db.vuln_scans.count_documents({})
    # New signups in last 7 days (rough — created_at is ISO string, filter client-side)
    recent_users = await db.users.find({}, {'created_at': 1, '_id': 0}).sort('created_at', -1).limit(200).to_list(200)
    new_last_7d = 0
    for u in recent_users:
        try:
            ts = datetime.fromisoformat((u.get('created_at') or '').replace('Z', '+00:00')).timestamp()
            if ts >= seven_days_ago:
                new_last_7d += 1
        except Exception:
            pass
    return {
        'paying_customers': paying,
        'total_users':      total_users,
        'total_scans':      scans_total,
        'new_last_7d':      new_last_7d,
        'ts':               now.isoformat(),
    }


@api.get('/downloads/sdk/python')
async def download_python_sdk(request: Request):
    """Serve the Python SDK single-file — gated by Enterprise/Lifetime tier."""
    user = await auth_get_optional_user(request, db)
    if not user:
        raise HTTPException(401, 'authentication_required')
    billing = await db.billing.find_one({'user_id': user['id']}) or {}
    tier = billing.get('tier') or user.get('tier') or 'free'
    if tier not in ('enterprise', 'lifetime') and user.get('role') != 'admin':
        raise HTTPException(403, f'sdk_requires_enterprise_or_lifetime · your_tier={tier}')
    path = _ARTIFACTS_DIR / 'cyberscope_sdk.py'
    if not path.exists():
        raise HTTPException(404, 'sdk_not_found')
    return FileResponse(path=str(path), filename='cyberscope_sdk.py',
                        media_type='text/x-python')


@api.get('/downloads/sdk/javascript')
async def download_js_sdk(request: Request):
    """Serve the JavaScript SDK — gated by Enterprise/Lifetime tier."""
    user = await auth_get_optional_user(request, db)
    if not user:
        raise HTTPException(401, 'authentication_required')
    billing = await db.billing.find_one({'user_id': user['id']}) or {}
    tier = billing.get('tier') or user.get('tier') or 'free'
    if tier not in ('enterprise', 'lifetime') and user.get('role') != 'admin':
        raise HTTPException(403, f'sdk_requires_enterprise_or_lifetime · your_tier={tier}')
    path = _ARTIFACTS_DIR / 'cyberscope-sdk.js'
    if not path.exists():
        raise HTTPException(404, 'sdk_not_found')
    return FileResponse(path=str(path), filename='cyberscope-sdk.js',
                        media_type='application/javascript')


@api.get('/vuln/cve-feed')
async def cve_feed_list(request: Request, limit: int = 50):
    """List recent CVEs stored locally."""
    cursor = db.cve_feed.find({}, {'_id': 0}).sort('published', -1).limit(min(200, max(1, limit)))
    items = await cursor.to_list(200)
    return {'items': items, 'count': len(items)}


@api.get('/vuln/weaponry/status')
async def weaponry_status(request: Request):
    owner_id = await _current_owner(request)
    # Count recent activity by owner (safe for guests)
    recent_scans = await db.vuln_scans.count_documents(
        {'owner_id': owner_id}) if owner_id != 'guest' else 0
    cve_count = await db.cve_feed.count_documents({})
    modules = [
        {'id': 'smuggling-v2',        'name': 'HTTP Smuggling v2',      'ready': True},
        {'id': 'cache-v2',            'name': 'Cache Deception v2',     'ready': True},
        {'id': 'ai-payloads',         'name': 'AI Payload Generator',   'ready': True},
        {'id': 'prototype-pollution', 'name': 'Prototype Pollution v2', 'ready': True},
        {'id': 'ssrf-deep',           'name': 'SSRF Deep (cloud meta)', 'ready': True},
        {'id': 'mfa-bypass',          'name': 'MFA Bypass',             'ready': True},
        {'id': 'jwt-cracker',         'name': 'JWT Cracker',            'ready': True},
        {'id': 'graphql',             'name': 'GraphQL Scanner',        'ready': True},
        {'id': 'race',                'name': 'Race Condition x200',    'ready': True},
        {'id': 'compliance',          'name': 'Compliance Mapper',      'ready': True},
        {'id': 'bounty',              'name': 'Bounty Estimator',       'ready': True},
        {'id': 'threat-intel',        'name': 'Threat Intel Feed',      'ready': True},
    ]
    return {
        'version': '7.9.0',
        'wave': 'Weaponized · Commercial',
        'modules': modules,
        'modules_count': len(modules),
        'ready_count': sum(1 for m in modules if m['ready']),
        'cve_feed_size': cve_count,
        'recent_scans': recent_scans,
    }


@api.get('/vuln/threat-intel')
async def threat_intel_endpoint(request: Request):
    """AI-generated weekly intel brief tuned to the caller's recent activity."""
    _rate_limit_check(request, 'intel', 4, 60)
    owner_id = await _current_owner(request)
    recent = await db.vuln_scans.find(
        {'owner_id': owner_id}, {'_id': 0, 'target': 1, 'summary': 1, 'recon': 1}
    ).sort('started_at', -1).to_list(10)
    targets = [s.get('target') for s in recent if s.get('target')]
    techs: List[str] = []
    for s in recent:
        for t in (s.get('recon') or {}).get('techs', []) or []:
            if t and t not in techs:
                techs.append(t)
    cves_cursor = db.cve_feed.find({}, {'_id': 0}).sort('cvss', -1).limit(5)
    cves = await cves_cursor.to_list(5)
    from vuln.threat_intel_feed import generate_brief
    try:
        return await generate_brief(targets, techs, cves_context=cves)
    except Exception as e:
        raise HTTPException(500, f'intel_error: {e}')



# Register all API routes (including the v7.2 batch-1 endpoints above)
app.include_router(api)


@app.on_event('startup')
async def startup_event():
    await db.scans.create_index('id', unique=True)
    await db.scans.create_index([('started_at', -1)])
    await db.scans.create_index('owner_id')
    await db.scan_results.create_index('scan_id', unique=True)
    await db.monitors.create_index('id', unique=True)
    await db.users.create_index('email', unique=True)
    await db.users.create_index('id', unique=True)
    # v7.9.x · Audit log indexes
    try:
        await db.audit_log.create_index([('ts', -1)])
        await db.audit_log.create_index('actor_id')
        await db.audit_log.create_index('action')
    except Exception:
        pass
    await db.login_attempts.create_index('identifier')
    await db.vuln_scans.create_index('id', unique=True)
    await db.vuln_scans.create_index('owner_id')
    await db.vuln_scans.create_index([('started_at', -1)])
    await db.vuln_scan_results.create_index('scan_id', unique=True)
    # v7.2 new indexes
    await db.notify_config.create_index('owner_id', unique=True)
    await db.custom_payloads.create_index('owner_id')
    await db.scheduled_scans.create_index('owner_id')
    await db.scheduled_scans.create_index('next_run_at')
    await db.nuclei_templates.create_index('id', unique=True)
    await db.nuclei_templates.create_index('owner_id')
    # v7.9 · Commercial Wave indexes
    await db.billing.create_index('user_id', unique=True)
    await db.billing.create_index('stripe_customer_id')
    await db.workspaces.create_index('id', unique=True)
    await db.workspaces.create_index('owner_id')
    await db.workspace_members.create_index([('workspace_id', 1), ('user_id', 1)], unique=True)
    await db.workspace_members.create_index('user_id')
    await db.workspace_invites.create_index('token', unique=True)
    await db.workspace_invites.create_index('email')
    await db.workspace_assignments.create_index([('workspace_id', 1), ('scan_id', 1)], unique=True)
    await db.workspace_comments.create_index([('workspace_id', 1), ('scan_id', 1)])
    # Start scheduler loop
    from vuln.scheduler import scheduler_loop

    async def _run_scheduled(schedule):
        """Trigger a scheduled scan via the same endpoint the UI uses."""
        req_data = {
            'target': schedule['target'],
            'depth': schedule.get('depth', 'medium'),
            'concurrency': 20, 'timeout': 12.0,
        }
        if schedule.get('modules'):
            req_data['modules'] = schedule['modules']
        req = VulnScanRequest(**req_data)
        scan_id = str(uuid.uuid4())
        VULN_SCANS[scan_id] = {'status': 'queued', 'logs': [], 'result': None}
        started_at = datetime.now(timezone.utc).isoformat()
        await db.vuln_scans.insert_one({
            'id': scan_id, 'target': req.target, 'status': 'queued',
            'depth': req.depth, 'modules': req.modules,
            'started_at': started_at, 'owner_id': schedule.get('owner_id', 'guest'),
            'scheduled_id': schedule['id'],
        })
        asyncio.create_task(_run_vuln_scan_task(scan_id, req, schedule.get('owner_id', 'guest')))

    asyncio.create_task(scheduler_loop(db, _run_scheduled, interval_sec=60))
    # v7.7.1 · auto-populate Payload Encyclopedia in background so the UI never shows
    # zero counts on fresh containers. Silent-fail if network is unavailable.
    async def _bg_ensure_wordlists():
        try:
            from vuln.wordlist_manager import ensure_wordlists
            await ensure_wordlists()
        except Exception:
            pass
    asyncio.create_task(_bg_ensure_wordlists())

    # v7.7.3 · Ensure Playwright symlinks exist so the deep crawler can use
    # headless Chromium even when PLAYWRIGHT_BROWSERS_PATH is set to a
    # non-default location (the container may install browsers to
    # /pw-browsers/ but Playwright looks at ~/.cache/ms-playwright/ at runtime).
    def _heal_playwright_paths():
        import os as _os
        src_dir = _os.environ.get('PLAYWRIGHT_BROWSERS_PATH', '/pw-browsers')
        dst_dir = _os.path.expanduser('~/.cache/ms-playwright')
        if not _os.path.isdir(src_dir):
            return
        try:
            _os.makedirs(dst_dir, exist_ok=True)
            for name in _os.listdir(src_dir):
                src = _os.path.join(src_dir, name)
                dst = _os.path.join(dst_dir, name)
                if _os.path.isdir(src) and not _os.path.exists(dst):
                    try:
                        _os.symlink(src, dst)
                    except OSError:
                        pass
        except Exception:
            pass
    try:
        _heal_playwright_paths()
    except Exception:
        pass

    # v7.7.2 · Vuln Monitor loop — auto-runs scans on active monitors, respects
    # per-monitor `interval_hours`, and posts a compact webhook summary.
    async def _monitors_loop():
        import httpx as _hx
        while True:
            try:
                now = datetime.now(timezone.utc)
                # Find monitors whose next-run is due
                cursor = db.vuln_monitors.find({'active': True})
                async for m in cursor:
                    last = m.get('last_run_at')
                    interval_s = int(m.get('interval_hours', 24)) * 3600
                    if last:
                        try:
                            last_dt = datetime.fromisoformat(str(last).replace('Z', '+00:00'))
                        except Exception:
                            last_dt = None
                        if last_dt and (now - last_dt).total_seconds() < interval_s:
                            continue
                    # Trigger a scan
                    scan_id = str(uuid.uuid4())
                    started_at = now.isoformat()
                    req = VulnScanRequest(target=m['target'], depth='medium')
                    await db.vuln_scans.insert_one({
                        'id': scan_id, 'target': req.target, 'status': 'queued',
                        'depth': req.depth, 'started_at': started_at,
                        'owner_id': m.get('owner_id', 'guest'),
                        'mode': 'monitor', 'monitor_id': m['id'],
                    })
                    asyncio.create_task(_run_vuln_scan_task(scan_id, req, m.get('owner_id', 'guest')))
                    await db.vuln_monitors.update_one(
                        {'id': m['id']},
                        {'$set': {'last_run_at': started_at},
                         '$inc': {'runs_count': 1}})
                    # webhook post (best-effort)
                    if m.get('webhook_url'):
                        try:
                            async with _hx.AsyncClient(timeout=5.0) as c:
                                await c.post(m['webhook_url'], json={
                                    'text': f'CyberScope monitor · {req.target} · scan {scan_id[:8]} launched',
                                    'content': f'CyberScope monitor · {req.target} · scan {scan_id[:8]} launched',
                                })
                        except Exception:
                            pass
            except Exception:
                pass
            await asyncio.sleep(120)  # check every 2 min

    asyncio.create_task(_monitors_loop())

    # v7.8 · CVE feed live sync — pulls last 30-day high-severity CVEs from
    # NVD every 6 hours so the cve_correlator has fresh data.
    async def _cve_loop():
        try:
            from vuln.cve_feed_sync import cve_feed_loop
            await cve_feed_loop(db, interval_hours=6)
        except Exception:
            pass
    asyncio.create_task(_cve_loop())
    # v7.9.x · Auto-recover orphaned scans (left in 'running' from a previous process)
    try:
        from scan_recovery import recover_orphaned_scans, recovery_loop
        await recover_orphaned_scans(db)
        asyncio.create_task(recovery_loop(db))
    except Exception as _rec_err:
        import logging
        logging.getLogger('cyberscope').warning(f'auto-recovery init failed: {_rec_err}')

    # Seed admin from env
    await auth_seed_admin(db)
    # Write test credentials file
    try:
        from pathlib import Path
        mem = Path(os.environ.get('MEMORY_DIR', _APP_ROOT / 'memory'))
        mem.mkdir(parents=True, exist_ok=True)
        (mem / 'test_credentials.md').write_text(
            f"""# Takeover Scanner v5 - Test Credentials

## Admin (auto-seeded from backend/.env)
- Email: `{os.environ.get('ADMIN_EMAIL', 'admin@takeoverscan.io')}`
- Password: `{os.environ.get('ADMIN_PASSWORD', 'Admin@Scan2026')}`
- Role: admin
- Sees ALL scans across all users

## Auth Endpoints
- `POST /api/auth/register` — Register with email+password
- `POST /api/auth/login` — Login, sets httpOnly cookies
- `POST /api/auth/logout` — Clear cookies
- `GET  /api/auth/me` — Current user (requires auth)
- `POST /api/auth/refresh` — Refresh access token

## Multi-Tenancy
- Non-admin users see only their OWN scans, monitors, settings.
- Guests (no login) see only guest-owned resources (backwards-compatible).
- Admin sees everything.

## Test Users
Register any via `/api/auth/register` — automatic role="user".
""")
    except OSError:
        pass
    asyncio.create_task(monitor_loop())


@app.on_event('shutdown')
async def shutdown_event():
    client.close()
