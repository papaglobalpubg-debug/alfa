"""CyberScope v7.9.x - Auto-Recovery for Orphaned Scans."""
import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

log = logging.getLogger('cyberscope.scan_recovery')

ORPHAN_TIMEOUT_MIN = int(os.environ.get('CS_ORPHAN_TIMEOUT_MIN', '30'))
RECOVERY_INTERVAL_S = int(os.environ.get('CS_RECOVERY_INTERVAL_S', '300'))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _is_orphaned(scan: Dict[str, Any], now: datetime) -> bool:
    status = (scan.get('status') or '').lower()
    if status not in ('running', 'queued', 'pending'):
        return False
    started = scan.get('started_at')
    if not started:
        return True
    try:
        if isinstance(started, str):
            started_dt = datetime.fromisoformat(started.replace('Z', '+00:00'))
        else:
            started_dt = started
        if started_dt.tzinfo is None:
            started_dt = started_dt.replace(tzinfo=timezone.utc)
        return (now - started_dt) > timedelta(minutes=ORPHAN_TIMEOUT_MIN)
    except Exception:
        return True


async def recover_orphaned_scans(db) -> int:
    now = _now()
    recovered = 0
    try:
        cursor = db.vuln_scans.find(
            {'status': {'$in': ['running', 'queued', 'pending']}},
            {'id': 1, 'status': 1, 'started_at': 1, 'owner_id': 1, 'target': 1},
        )
        async for s in cursor:
            if not _is_orphaned(s, now):
                continue
            await db.vuln_scans.update_one(
                {'id': s['id']},
                {'$set': {
                    'status': 'interrupted',
                    'finished_at': now.isoformat(),
                    'error': 'auto-recovered: process was restarted while scan was running',
                }},
            )
            log.warning('recovered orphaned scan %s (target=%s)', s.get('id'), s.get('target'))
            recovered += 1
    except Exception as exc:
        log.warning('recover_orphaned_scans failed: %s', exc)
    if recovered:
        log.info('auto-recovery: marked %d scan(s) as interrupted', recovered)
    return recovered


async def recovery_loop(db) -> None:
    while True:
        try:
            await recover_orphaned_scans(db)
        except Exception as exc:
            log.warning('recovery_loop iteration failed: %s', exc)
        await asyncio.sleep(RECOVERY_INTERVAL_S)
