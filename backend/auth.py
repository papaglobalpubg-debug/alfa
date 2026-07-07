"""
Authentication module for Takeover Scanner v5.
JWT + bcrypt + brute-force protection + admin seed.

Provides an OPTIONAL auth layer:
- If Authorization header / cookie is present and valid → user is attached to request state
- If not → request is treated as GUEST (owner_id="guest") for backwards compatibility
- New /api/auth/* endpoints for register/login/logout/me/refresh
- Multi-tenant scoping is handled by callers by checking `request.state.user`
"""
from __future__ import annotations

import os
import secrets
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional

import bcrypt
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel, EmailStr, ConfigDict, Field

JWT_ALGORITHM = 'HS256'
ACCESS_TTL_MIN = 60
REFRESH_TTL_DAYS = 7
LOCK_ATTEMPTS = 5
LOCK_MINUTES = 15


def _secret() -> str:
    s = os.environ.get('JWT_SECRET', '')
    if not s or len(s) < 16:
        raise RuntimeError('JWT_SECRET not set or too short')
    return s


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except (ValueError, TypeError):
        return False


def create_access_token(user_id: str, email: str, role: str = 'user') -> str:
    payload = {
        'sub': user_id, 'email': email, 'role': role, 'type': 'access',
        'exp': datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TTL_MIN),
    }
    return jwt.encode(payload, _secret(), algorithm=JWT_ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    payload = {
        'sub': user_id, 'type': 'refresh',
        'exp': datetime.now(timezone.utc) + timedelta(days=REFRESH_TTL_DAYS),
    }
    return jwt.encode(payload, _secret(), algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> Dict[str, Any]:
    return jwt.decode(token, _secret(), algorithms=[JWT_ALGORITHM])


# ============== Pydantic models ==============
class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra='ignore')
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    name: Optional[str] = None


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra='ignore')
    email: EmailStr
    password: str


class UserPublic(BaseModel):
    id: str
    email: EmailStr
    name: Optional[str] = None
    role: str = 'user'
    created_at: Optional[str] = None


# ============== Helpers ==============
# P3 · Cookie hardening — Secure flag ON in production (HTTPS), SameSite=strict.
# Set COOKIE_SECURE=0 in dev if you're using plain HTTP on localhost.
_COOKIE_SECURE = os.environ.get('COOKIE_SECURE', '1') == '1'
_COOKIE_SAMESITE = os.environ.get('COOKIE_SAMESITE', 'strict')


def _cookie_kwargs():
    return dict(httponly=True, secure=_COOKIE_SECURE,
                samesite=_COOKIE_SAMESITE, path='/')


def _set_auth_cookies(resp: Response, access: str, refresh: str) -> None:
    resp.set_cookie('access_token', access, max_age=ACCESS_TTL_MIN * 60, **_cookie_kwargs())
    resp.set_cookie('refresh_token', refresh, max_age=REFRESH_TTL_DAYS * 86400, **_cookie_kwargs())


def _clear_auth_cookies(resp: Response) -> None:
    resp.delete_cookie('access_token', path='/')
    resp.delete_cookie('refresh_token', path='/')


def _extract_token(request: Request) -> Optional[str]:
    t = request.cookies.get('access_token')
    if t:
        return t
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        return auth[7:]
    return None


async def get_optional_user(request: Request, db: AsyncIOMotorDatabase) -> Optional[Dict[str, Any]]:
    """Returns user dict if authenticated, else None (guest mode)."""
    token = _extract_token(request)
    if not token:
        return None
    try:
        payload = decode_token(token)
    except jwt.PyJWTError:
        return None
    if payload.get('type') != 'access':
        return None
    user = await db.users.find_one({'id': payload.get('sub')}, {'password_hash': 0})
    return user


async def get_current_user(request: Request, db: AsyncIOMotorDatabase) -> Dict[str, Any]:
    """Returns user dict, raises 401 if not authenticated."""
    user = await get_optional_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail='Not authenticated')
    return user


def user_public(user: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'id': user.get('id'),
        'email': user.get('email'),
        'name': user.get('name'),
        'role': user.get('role', 'user'),
        'created_at': user.get('created_at'),
    }


def _client_ip(request: Request) -> str:
    """Extract real client IP from X-Forwarded-For / X-Real-IP (trusted behind ingress)."""
    xff = request.headers.get('x-forwarded-for', '').strip()
    if xff:
        # First entry is the original client
        return xff.split(',')[0].strip()
    xri = request.headers.get('x-real-ip', '').strip()
    if xri:
        return xri
    return request.client.host if request.client else 'unknown'


# ============== Brute force protection ==============
async def _check_lockout(db: AsyncIOMotorDatabase, identifier: str) -> None:
    doc = await db.login_attempts.find_one({'identifier': identifier})
    if not doc:
        return
    attempts = doc.get('attempts', 0)
    last_at = doc.get('last_at')
    if attempts >= LOCK_ATTEMPTS and last_at:
        if isinstance(last_at, str):
            last_at = datetime.fromisoformat(last_at.replace('Z', '+00:00'))
        if (datetime.now(timezone.utc) - last_at).total_seconds() < LOCK_MINUTES * 60:
            raise HTTPException(status_code=429,
                detail=f'Too many failed attempts. Try again in {LOCK_MINUTES} minutes.')
        # Expire
        await db.login_attempts.delete_one({'identifier': identifier})


async def _record_attempt(db: AsyncIOMotorDatabase, identifier: str, success: bool) -> None:
    if success:
        await db.login_attempts.delete_one({'identifier': identifier})
        return
    await db.login_attempts.update_one(
        {'identifier': identifier},
        {'$inc': {'attempts': 1}, '$set': {'last_at': datetime.now(timezone.utc).isoformat()}},
        upsert=True)


# ============== Admin seeding ==============
async def seed_admin(db: AsyncIOMotorDatabase) -> None:
    email = os.environ.get('ADMIN_EMAIL', '').lower().strip()
    password = os.environ.get('ADMIN_PASSWORD', '')
    if not email or not password:
        return
    existing = await db.users.find_one({'email': email})
    if existing is None:
        user_id = secrets.token_hex(12)
        await db.users.insert_one({
            'id': user_id,
            'email': email,
            'password_hash': hash_password(password),
            'name': 'Admin',
            'role': 'admin',
            'created_at': datetime.now(timezone.utc).isoformat(),
        })
    else:
        if not verify_password(password, existing.get('password_hash', '')):
            await db.users.update_one(
                {'email': email},
                {'$set': {'password_hash': hash_password(password)}})


# ============== Router ==============
def make_router(get_db):
    """
    Create the /api/auth router.
    `get_db` must be a callable returning the motor DB (dependency).
    """
    router = APIRouter(prefix='/api/auth', tags=['auth'])

    def _db_dep(request: Request):
        return get_db()

    @router.post('/register')
    async def register(payload: RegisterRequest, request: Request, response: Response):
        db = get_db()
        email = payload.email.lower().strip()
        existing = await db.users.find_one({'email': email})
        if existing:
            raise HTTPException(400, 'Email already registered')
        user_id = secrets.token_hex(12)
        user_doc = {
            'id': user_id,
            'email': email,
            'password_hash': hash_password(payload.password),
            'name': payload.name or email.split('@')[0],
            'role': 'user',
            'created_at': datetime.now(timezone.utc).isoformat(),
        }
        await db.users.insert_one(user_doc)
        access = create_access_token(user_id, email, 'user')
        refresh = create_refresh_token(user_id)
        _set_auth_cookies(response, access, refresh)
        return {'user': user_public(user_doc), 'access_token': access}

    @router.post('/login')
    async def login(payload: LoginRequest, request: Request, response: Response):
        db = get_db()
        email = payload.email.lower().strip()
        ip = _client_ip(request)
        identifier = f'{ip}:{email}'
        # Also check email-only lockout to defend when IP rotates
        email_identifier = f'*:{email}'
        await _check_lockout(db, identifier)
        await _check_lockout(db, email_identifier)
        user = await db.users.find_one({'email': email})
        if not user or not verify_password(payload.password, user.get('password_hash', '')):
            await _record_attempt(db, identifier, success=False)
            await _record_attempt(db, email_identifier, success=False)
            raise HTTPException(401, 'Invalid credentials')
        await _record_attempt(db, identifier, success=True)
        await _record_attempt(db, email_identifier, success=True)
        access = create_access_token(user['id'], email, user.get('role', 'user'))
        refresh = create_refresh_token(user['id'])
        _set_auth_cookies(response, access, refresh)
        try:
            from audit import record_event
            await record_event(
                db,
                actor_id=user['id'],
                actor_email=email,
                action='login_success',
                ip=ip,
            )
        except Exception:
            pass
        return {'user': user_public(user), 'access_token': access}

    @router.post('/logout')
    async def logout(response: Response):
        _clear_auth_cookies(response)
        return {'ok': True}

    @router.get('/me')
    async def me(request: Request):
        db = get_db()
        user = await get_current_user(request, db)
        return user_public(user)

    @router.post('/refresh')
    async def refresh_token_endpoint(request: Request, response: Response):
        db = get_db()
        token = request.cookies.get('refresh_token')
        if not token:
            raise HTTPException(401, 'No refresh token')
        try:
            payload = decode_token(token)
        except jwt.PyJWTError:
            raise HTTPException(401, 'Invalid refresh token')
        if payload.get('type') != 'refresh':
            raise HTTPException(401, 'Wrong token type')
        user = await db.users.find_one({'id': payload.get('sub')}, {'password_hash': 0})
        if not user:
            raise HTTPException(401, 'User not found')
        access = create_access_token(user['id'], user['email'], user.get('role', 'user'))
        _set_auth_cookies(response, access, token)
        return {'access_token': access, 'user': user_public(user)}

    return router
