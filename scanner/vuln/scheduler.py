"""
Scheduled scans engine — periodically checks the DB for due scans and enqueues them.
Runs as a background task in FastAPI's lifespan.
"""
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Optional


def next_run_from_schedule(schedule: str, base_time: Optional[datetime] = None) -> Optional[datetime]:
    """
    Compute the next-run datetime from a simple schedule format.
    Supported formats:
      - 'every 1h', 'every 6h', 'every 24h'
      - 'daily'    (every 24h)
      - 'hourly'   (every 1h)
      - 'weekly'   (every 7 days)
      - 'monthly'  (every 30 days)
      - 'once'     (do not re-schedule)
    """
    now = base_time or datetime.now(timezone.utc)
    s = (schedule or '').lower().strip()
    if s == 'once':
        return None
    if s == 'hourly' or s == 'every 1h':
        return now + timedelta(hours=1)
    if s == 'daily' or s == 'every 24h':
        return now + timedelta(days=1)
    if s == 'weekly':
        return now + timedelta(days=7)
    if s == 'monthly':
        return now + timedelta(days=30)
    # every Xh / Xd / Xm patterns
    import re
    m = re.match(r'every\s+(\d+)\s*(h|hour|hours|d|day|days|m|min|minutes)', s)
    if m:
        n = int(m.group(1))
        unit = m.group(2)
        if unit.startswith('h'):
            return now + timedelta(hours=n)
        if unit.startswith('d'):
            return now + timedelta(days=n)
        if unit.startswith('m'):
            return now + timedelta(minutes=max(n, 5))  # min 5 min
    return now + timedelta(days=1)  # default fallback


async def scheduler_loop(db, run_scan_fn, interval_sec: int = 60):
    """
    Background loop: every `interval_sec` seconds, checks for due schedules
    and triggers scans. `run_scan_fn(schedule_doc)` is an async callable.
    """
    while True:
        try:
            now = datetime.now(timezone.utc)
            cursor = db.scheduled_scans.find({
                'enabled': True,
                '$or': [
                    {'next_run_at': {'$lte': now.isoformat()}},
                    {'next_run_at': None},
                ],
            })
            due = await cursor.to_list(50)
            for schedule in due:
                try:
                    await run_scan_fn(schedule)
                    next_run = next_run_from_schedule(schedule.get('schedule', 'daily'), now)
                    update = {'last_run_at': now.isoformat()}
                    if next_run is None:
                        update['enabled'] = False
                        update['next_run_at'] = None
                    else:
                        update['next_run_at'] = next_run.isoformat()
                    await db.scheduled_scans.update_one(
                        {'id': schedule['id']}, {'$set': update}
                    )
                except Exception as e:
                    # Log but don't break scheduler on one bad schedule
                    await db.scheduled_scans.update_one(
                        {'id': schedule['id']},
                        {'$set': {'last_error': str(e),
                                  'last_error_at': now.isoformat()}},
                    )
        except Exception:
            pass
        await asyncio.sleep(interval_sec)
