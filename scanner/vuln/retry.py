"""CyberScope v7.9.x - Generic Async Retry Helper."""
import asyncio
import logging
import random
from typing import Any, Awaitable, Callable, Optional, Tuple, Type, TypeVar

log = logging.getLogger('cyberscope.retry')

T = TypeVar('T')


class RetryError(Exception):
    pass


async def retry_async(
    func: Callable[..., Awaitable[T]],
    *args: Any,
    max_attempts: int = 3,
    base_delay: float = 0.5,
    max_delay: float = 10.0,
    retriable_exceptions: Tuple[Type[BaseException], ...] = (Exception,),
    on_retry: Optional[Callable[[int, BaseException, float], None]] = None,
    **kwargs: Any,
) -> T:
    attempt = 0
    last_exc: Optional[BaseException] = None
    while attempt < max_attempts:
        try:
            return await func(*args, **kwargs)
        except asyncio.CancelledError:
            raise
        except retriable_exceptions as exc:
            attempt += 1
            last_exc = exc
            if attempt >= max_attempts:
                break
            delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
            delay = delay * (0.5 + random.random() * 0.5)
            if on_retry is not None:
                try:
                    on_retry(attempt, exc, delay)
                except Exception:
                    pass
            else:
                log.warning(
                    'retry %d/%d after %.2fs (%s: %s)',
                    attempt, max_attempts, delay, type(exc).__name__, exc,
                )
            await asyncio.sleep(delay)
    raise RetryError(
        f'failed after {max_attempts} attempts: '
        f'{type(last_exc).__name__ if last_exc else "unknown"}: {last_exc}'
    ) from last_exc
