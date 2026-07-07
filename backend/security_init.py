"""CyberScope v7.9.x - Security Initialization Helper."""
import logging
import os
import secrets
from pathlib import Path

log = logging.getLogger('cyberscope.security')

_WEAK_PLACEHOLDERS = {
    '', 'changeme', 'change_me', 'change-me',
    'your-256-bit-secret', 'your_secret_key',
    'your-256-bit-secret-key-here',
    'replace-me', 'placeholder',
    'change_me_to_a_very_long_random_string_64_chars_or_more',
    'change_me_strong_password',
}

MIN_SECRET_LENGTH = 32
FALLBACK_SECRET_FILE = Path(__file__).parent / '.jwt_secret'


def is_weak_secret(secret: str) -> bool:
    if not secret:
        return True
    if len(secret) < MIN_SECRET_LENGTH:
        return True
    if secret.lower() in _WEAK_PLACEHOLDERS:
        return True
    return False


def generate_strong_secret(length: int = 64) -> str:
    return secrets.token_hex(length // 2)


def _read_fallback_secret() -> str:
    try:
        if FALLBACK_SECRET_FILE.is_file():
            content = FALLBACK_SECRET_FILE.read_text().strip()
            if content and not is_weak_secret(content):
                return content
    except OSError as exc:
        log.warning('could not read fallback secret file: %s', exc)
    return ''


def _write_fallback_secret(secret: str) -> None:
    try:
        FALLBACK_SECRET_FILE.write_text(secret)
        try:
            FALLBACK_SECRET_FILE.chmod(0o600)
        except OSError:
            pass
    except OSError as exc:
        log.warning('could not write fallback secret file: %s', exc)


def ensure_jwt_secret() -> str:
    current = os.environ.get('JWT_SECRET', '')
    if current and not is_weak_secret(current):
        return current
    fallback = _read_fallback_secret()
    if fallback and not is_weak_secret(fallback):
        os.environ['JWT_SECRET'] = fallback
        if not current or is_weak_secret(current):
            log.info('JWT secret restored from local fallback file')
        return fallback
    new_secret = generate_strong_secret(64)
    os.environ['JWT_SECRET'] = new_secret
    _write_fallback_secret(new_secret)
    log.warning(
        'JWT_SECRET was missing or weak; generated a new one and stored it in %s. '
        'Set JWT_SECRET in your .env file for production.',
        FALLBACK_SECRET_FILE,
    )
    return new_secret


try:
    ensure_jwt_secret()
except Exception as _exc:
    log.warning('ensure_jwt_secret failed on import: %s', _exc)
