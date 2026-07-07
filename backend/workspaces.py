"""
Team Workspaces + RBAC router — v7.9 Commercial Wave.

A user can:
  - Create workspaces (they become owner)
  - Invite members by email (role: analyst | viewer | admin)
  - Assign scans to workspace members
  - Add comments on findings

Enforced roles
--------------
  owner   → full control, billing, delete workspace
  admin   → invite/remove members, assign scans
  analyst → run scans, resolve findings, comment
  viewer  → read-only
"""
from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, EmailStr, ConfigDict, Field


ROLES = ('owner', 'admin', 'analyst', 'viewer')


class WorkspaceCreate(BaseModel):
    model_config = ConfigDict(extra='ignore')
    name: str = Field(min_length=2, max_length=80)
    description: Optional[str] = None


class InviteRequest(BaseModel):
    model_config = ConfigDict(extra='ignore')
    email: EmailStr
    role: str = 'analyst'


class RoleUpdate(BaseModel):
    model_config = ConfigDict(extra='ignore')
    role: str


class AssignRequest(BaseModel):
    model_config = ConfigDict(extra='ignore')
    scan_id: str
    assignee_id: str
    note: Optional[str] = None


class CommentRequest(BaseModel):
    model_config = ConfigDict(extra='ignore')
    scan_id: str
    finding_hash: Optional[str] = None
    body: str = Field(min_length=1, max_length=4000)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_router(get_db, get_current_user):
    router = APIRouter(prefix='/api/workspaces', tags=['workspaces'])

    async def _member(db, workspace_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        return await db.workspace_members.find_one({'workspace_id': workspace_id, 'user_id': user_id})

    async def _require_role(db, workspace_id: str, user_id: str, allowed: List[str]) -> Dict[str, Any]:
        m = await _member(db, workspace_id, user_id)
        if not m or m.get('role') not in allowed:
            raise HTTPException(403, 'insufficient_role')
        return m

    @router.get('')
    async def list_my_workspaces(request: Request):
        db = get_db()
        user = await get_current_user(request, db)
        memberships = await db.workspace_members.find({'user_id': user['id']}, {'_id': 0}).to_list(500)
        ws_ids = [m['workspace_id'] for m in memberships]
        workspaces = await db.workspaces.find({'id': {'$in': ws_ids}}, {'_id': 0}).to_list(500)
        by_id = {w['id']: w for w in workspaces}
        return {
            'workspaces': [
                {**by_id.get(m['workspace_id'], {}), 'role': m.get('role')}
                for m in memberships if m['workspace_id'] in by_id
            ]
        }

    @router.post('')
    async def create_workspace(req: WorkspaceCreate, request: Request):
        db = get_db()
        user = await get_current_user(request, db)
        wid = secrets.token_hex(10)
        doc = {
            'id': wid,
            'name': req.name.strip(),
            'description': (req.description or '').strip(),
            'owner_id': user['id'],
            'created_at': _now(),
        }
        await db.workspaces.insert_one(dict(doc))
        await db.workspace_members.insert_one({
            'workspace_id': wid,
            'user_id': user['id'],
            'email': user.get('email'),
            'role': 'owner',
            'joined_at': _now(),
        })
        return {**doc, 'role': 'owner'}

    @router.get('/{workspace_id}')
    async def get_workspace(workspace_id: str, request: Request):
        db = get_db()
        user = await get_current_user(request, db)
        await _require_role(db, workspace_id, user['id'], list(ROLES))
        ws = await db.workspaces.find_one({'id': workspace_id}, {'_id': 0})
        if not ws:
            raise HTTPException(404, 'workspace_not_found')
        members = await db.workspace_members.find({'workspace_id': workspace_id}, {'_id': 0}).to_list(500)
        invites = await db.workspace_invites.find(
            {'workspace_id': workspace_id, 'status': 'pending'}, {'_id': 0}
        ).to_list(500)
        return {'workspace': ws, 'members': members, 'pending_invites': invites}

    @router.delete('/{workspace_id}')
    async def delete_workspace(workspace_id: str, request: Request):
        db = get_db()
        user = await get_current_user(request, db)
        await _require_role(db, workspace_id, user['id'], ['owner'])
        await db.workspaces.delete_one({'id': workspace_id})
        await db.workspace_members.delete_many({'workspace_id': workspace_id})
        await db.workspace_invites.delete_many({'workspace_id': workspace_id})
        return {'ok': True}

    @router.post('/{workspace_id}/invite')
    async def invite_member(workspace_id: str, req: InviteRequest, request: Request):
        db = get_db()
        user = await get_current_user(request, db)
        await _require_role(db, workspace_id, user['id'], ['owner', 'admin'])
        role = req.role.lower()
        if role not in ('admin', 'analyst', 'viewer'):
            raise HTTPException(400, 'invalid_role')
        email = req.email.lower().strip()

        # If the invitee already has an account, add them directly
        target_user = await db.users.find_one({'email': email})
        if target_user:
            existing = await _member(db, workspace_id, target_user['id'])
            if existing:
                raise HTTPException(400, 'already_a_member')
            await db.workspace_members.insert_one({
                'workspace_id': workspace_id,
                'user_id': target_user['id'],
                'email': email,
                'role': role,
                'joined_at': _now(),
            })
            return {'ok': True, 'added': True, 'user_id': target_user['id']}

        # Otherwise create a pending invite (token-based)
        token = secrets.token_urlsafe(20)
        await db.workspace_invites.insert_one({
            'workspace_id': workspace_id,
            'email': email,
            'role': role,
            'token': token,
            'status': 'pending',
            'invited_by': user['id'],
            'created_at': _now(),
        })
        return {'ok': True, 'added': False, 'invite_token': token}

    @router.post('/invites/{token}/accept')
    async def accept_invite(token: str, request: Request):
        db = get_db()
        user = await get_current_user(request, db)
        invite = await db.workspace_invites.find_one({'token': token, 'status': 'pending'})
        if not invite:
            raise HTTPException(404, 'invite_not_found_or_expired')
        if invite['email'].lower().strip() != (user.get('email') or '').lower().strip():
            raise HTTPException(403, 'invite_email_mismatch')
        existing = await _member(db, invite['workspace_id'], user['id'])
        if existing:
            await db.workspace_invites.update_one({'token': token}, {'$set': {'status': 'accepted'}})
            return {'ok': True, 'workspace_id': invite['workspace_id']}
        await db.workspace_members.insert_one({
            'workspace_id': invite['workspace_id'],
            'user_id': user['id'],
            'email': user.get('email'),
            'role': invite['role'],
            'joined_at': _now(),
        })
        await db.workspace_invites.update_one({'token': token}, {'$set': {'status': 'accepted'}})
        return {'ok': True, 'workspace_id': invite['workspace_id']}

    @router.patch('/{workspace_id}/members/{user_id}')
    async def update_role(workspace_id: str, user_id: str, req: RoleUpdate, request: Request):
        db = get_db()
        user = await get_current_user(request, db)
        await _require_role(db, workspace_id, user['id'], ['owner', 'admin'])
        role = req.role.lower()
        if role not in ('admin', 'analyst', 'viewer'):
            raise HTTPException(400, 'invalid_role')
        target = await _member(db, workspace_id, user_id)
        if not target:
            raise HTTPException(404, 'member_not_found')
        if target.get('role') == 'owner':
            raise HTTPException(400, 'cannot_change_owner_role')
        await db.workspace_members.update_one(
            {'workspace_id': workspace_id, 'user_id': user_id},
            {'$set': {'role': role}},
        )
        return {'ok': True}

    @router.delete('/{workspace_id}/members/{user_id}')
    async def remove_member(workspace_id: str, user_id: str, request: Request):
        db = get_db()
        user = await get_current_user(request, db)
        await _require_role(db, workspace_id, user['id'], ['owner', 'admin'])
        target = await _member(db, workspace_id, user_id)
        if not target:
            raise HTTPException(404, 'member_not_found')
        if target.get('role') == 'owner':
            raise HTTPException(400, 'cannot_remove_owner')
        await db.workspace_members.delete_one({'workspace_id': workspace_id, 'user_id': user_id})
        return {'ok': True}

    # ---------- Scan assignment & comments ----------
    @router.post('/{workspace_id}/assign')
    async def assign_scan(workspace_id: str, req: AssignRequest, request: Request):
        db = get_db()
        user = await get_current_user(request, db)
        await _require_role(db, workspace_id, user['id'], ['owner', 'admin', 'analyst'])
        assignee = await _member(db, workspace_id, req.assignee_id)
        if not assignee:
            raise HTTPException(404, 'assignee_not_in_workspace')
        await db.workspace_assignments.update_one(
            {'workspace_id': workspace_id, 'scan_id': req.scan_id},
            {'$set': {
                'workspace_id': workspace_id,
                'scan_id': req.scan_id,
                'assignee_id': req.assignee_id,
                'assigned_by': user['id'],
                'note': req.note or '',
                'updated_at': _now(),
            }},
            upsert=True,
        )
        return {'ok': True}

    @router.get('/{workspace_id}/assignments')
    async def list_assignments(workspace_id: str, request: Request):
        db = get_db()
        user = await get_current_user(request, db)
        await _require_role(db, workspace_id, user['id'], list(ROLES))
        rows = await db.workspace_assignments.find(
            {'workspace_id': workspace_id}, {'_id': 0}
        ).to_list(500)
        return {'assignments': rows}

    @router.post('/{workspace_id}/comments')
    async def add_comment(workspace_id: str, req: CommentRequest, request: Request):
        db = get_db()
        user = await get_current_user(request, db)
        await _require_role(db, workspace_id, user['id'], ['owner', 'admin', 'analyst'])
        doc = {
            'id': secrets.token_hex(8),
            'workspace_id': workspace_id,
            'scan_id': req.scan_id,
            'finding_hash': req.finding_hash,
            'author_id': user['id'],
            'author_email': user.get('email'),
            'body': req.body,
            'created_at': _now(),
        }
        await db.workspace_comments.insert_one(doc)
        doc.pop('_id', None)
        return doc

    @router.get('/{workspace_id}/comments/{scan_id}')
    async def list_comments(workspace_id: str, scan_id: str, request: Request):
        db = get_db()
        user = await get_current_user(request, db)
        await _require_role(db, workspace_id, user['id'], list(ROLES))
        rows = await db.workspace_comments.find(
            {'workspace_id': workspace_id, 'scan_id': scan_id}, {'_id': 0}
        ).sort('created_at', 1).to_list(1000)
        return {'comments': rows}

    return router
