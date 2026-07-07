"""CyberScope v7.9.x - Audit Logging Helper."""
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

log = logging.getLogger('cyberscope.audit')


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def record_event(
    db,
    *,
    actor_id: str = '',
    actor_email: str = '',
    action: str,
    target: str = '',
    ip: str = '',
    user_agent: str = '',
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    try:
        doc: Dict[str, Any] = {
            'ts': _now(),
            'actor_id': actor_id,
            'actor_email': actor_email,
            'action': action,
            'target': target,
            'ip': ip,
            'user_agent': user_agent,
        }
        if extra:
            doc['extra'] = extra
        await db.audit_log.insert_one(doc)
    except Exception as exc:
        log.warning('audit_log insert failed: %s', exc)
