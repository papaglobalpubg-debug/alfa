import React, { useEffect, useState } from 'react';
import api from '@/lib/api';
import {
  Users, Plus, Shield, UserPlus, Trash2, Crown, UserCog, Eye,
  Copy, CheckCircle2, XCircle, Mail,
} from 'lucide-react';

const ROLE_META = {
  owner:   { color: 'text-amber-300 border-amber-500/40 bg-amber-500/10',   icon: Crown  },
  admin:   { color: 'text-red-300 border-red-500/40 bg-red-500/10',         icon: Shield },
  analyst: { color: 'text-emerald-300 border-emerald-500/40 bg-emerald-500/10', icon: UserCog },
  viewer:  { color: 'text-zinc-300 border-zinc-700 bg-zinc-800/40',         icon: Eye    },
};

function RoleBadge({ role }) {
  const meta = ROLE_META[role] || ROLE_META.viewer;
  const Icon = meta.icon;
  return (
    <span className={`inline-flex items-center gap-1 text-[10px] mono uppercase tracking-widest px-1.5 py-0.5 border ${meta.color}`}>
      <Icon className="w-3 h-3" /> {role}
    </span>
  );
}

export default function Workspaces() {
  const [workspaces, setWorkspaces] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [newName, setNewName] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState('analyst');
  const [inviteToken, setInviteToken] = useState('');
  const [acceptToken, setAcceptToken] = useState('');

  const refresh = async () => {
    setLoading(true);
    try {
      const { data } = await api.listWorkspaces();
      setWorkspaces(data.workspaces || []);
      if (!selectedId && data.workspaces?.length) {
        setSelectedId(data.workspaces[0].id);
      }
    } catch (e) {
      setError(e.response?.data?.detail || 'Failed to load workspaces');
    } finally {
      setLoading(false);
    }
  };

  const loadDetail = async (id) => {
    if (!id) return;
    try {
      const { data } = await api.getWorkspace(id);
      setDetail(data);
    } catch (e) {
      setError(e.response?.data?.detail || 'Failed to load workspace');
    }
  };

  useEffect(() => { refresh(); }, []);
  useEffect(() => { loadDetail(selectedId); }, [selectedId]);

  const create = async () => {
    if (!newName.trim()) return;
    setError('');
    try {
      const { data } = await api.createWorkspace({ name: newName, description: newDesc });
      setNewName('');
      setNewDesc('');
      await refresh();
      setSelectedId(data.id);
    } catch (e) {
      setError(e.response?.data?.detail || 'Create failed');
    }
  };

  const remove = async (id) => {
    if (!window.confirm('Delete this workspace? All members and comments are removed.')) return;
    try {
      await api.deleteWorkspace(id);
      setSelectedId(null);
      setDetail(null);
      await refresh();
    } catch (e) {
      setError(e.response?.data?.detail || 'Delete failed');
    }
  };

  const invite = async () => {
    if (!selectedId || !inviteEmail.trim()) return;
    setError('');
    setInviteToken('');
    try {
      const { data } = await api.inviteMember(selectedId, { email: inviteEmail.trim(), role: inviteRole });
      setInviteEmail('');
      if (data.invite_token) setInviteToken(data.invite_token);
      await loadDetail(selectedId);
    } catch (e) {
      setError(e.response?.data?.detail || 'Invite failed');
    }
  };

  const removeMember = async (uid) => {
    if (!window.confirm('Remove this member?')) return;
    try {
      await api.removeMember(selectedId, uid);
      await loadDetail(selectedId);
    } catch (e) {
      setError(e.response?.data?.detail || 'Remove failed');
    }
  };

  const changeRole = async (uid, role) => {
    try {
      await api.updateMemberRole(selectedId, uid, role);
      await loadDetail(selectedId);
    } catch (e) {
      setError(e.response?.data?.detail || 'Update failed');
    }
  };

  const accept = async () => {
    if (!acceptToken.trim()) return;
    setError('');
    try {
      const { data } = await api.acceptInvite(acceptToken.trim());
      setAcceptToken('');
      await refresh();
      if (data.workspace_id) setSelectedId(data.workspace_id);
    } catch (e) {
      setError(e.response?.data?.detail || 'Accept failed');
    }
  };

  const myRole = detail?.members?.find((m) => detail.workspace && m.workspace_id === detail.workspace.id)?.role;
  const canManage = detail?.workspace && workspaces.find((w) => w.id === detail.workspace.id)?.role &&
    ['owner', 'admin'].includes(workspaces.find((w) => w.id === detail.workspace.id).role);

  return (
    <div data-testid="workspaces-page" className="max-w-6xl mx-auto space-y-6 animate-fade-in-up">
      <header className="border border-amber-500/40 bg-gradient-to-r from-amber-950/30 via-zinc-950 to-zinc-950 p-6">
        <div className="flex items-center gap-2 mb-2">
          <Users className="w-5 h-5 text-amber-400" />
          <span className="text-[10px] mono uppercase tracking-widest text-amber-400 border border-amber-500/50 bg-amber-500/10 px-2 py-0.5">
            Team Workspaces · v7.9
          </span>
        </div>
        <h1 className="text-2xl md:text-3xl font-display font-bold text-zinc-50">Collaborate on hunts.</h1>
        <p className="text-zinc-400 text-sm mt-2">
          Invite analysts, assign findings, and comment inline. Roles: <b className="mono">owner</b> ·
          <b className="mono"> admin</b> · <b className="mono">analyst</b> · <b className="mono">viewer</b>.
        </p>
      </header>

      {error && (
        <div className="border border-red-500/40 bg-red-500/10 text-red-300 px-4 py-2 text-sm flex items-center gap-2" data-testid="workspaces-error">
          <XCircle className="w-4 h-4" /> {error}
        </div>
      )}

      <div className="grid md:grid-cols-3 gap-4">
        {/* LEFT — list + create */}
        <div className="space-y-4">
          <div className="border border-zinc-800 bg-zinc-900/40 p-4">
            <div className="text-xs mono uppercase tracking-widest text-zinc-500 mb-2">Create workspace</div>
            <input
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="Team name"
              data-testid="ws-new-name"
              className="w-full bg-zinc-950 border border-zinc-800 px-3 py-2 text-sm mb-2 focus:outline-none focus:border-emerald-500"
            />
            <input
              value={newDesc}
              onChange={(e) => setNewDesc(e.target.value)}
              placeholder="What is this team hunting?"
              data-testid="ws-new-desc"
              className="w-full bg-zinc-950 border border-zinc-800 px-3 py-2 text-sm mb-2 focus:outline-none focus:border-emerald-500"
            />
            <button
              onClick={create}
              disabled={!newName.trim()}
              data-testid="ws-create-btn"
              className="w-full bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-zinc-950 font-mono text-xs font-semibold py-2 flex items-center justify-center gap-1"
            >
              <Plus className="w-3.5 h-3.5" /> Create
            </button>
          </div>

          <div className="border border-zinc-800 bg-zinc-900/40">
            <div className="px-4 py-3 border-b border-zinc-800 text-xs mono uppercase tracking-widest text-zinc-500">
              My workspaces {loading && '· loading…'}
            </div>
            <div className="divide-y divide-zinc-800 max-h-[400px] overflow-auto">
              {workspaces.map((w) => (
                <button
                  key={w.id}
                  onClick={() => setSelectedId(w.id)}
                  data-testid={`ws-item-${w.id}`}
                  className={`w-full text-left px-4 py-3 hover:bg-zinc-900 transition-colors ${
                    selectedId === w.id ? 'bg-zinc-900 border-l-2 border-l-emerald-500' : ''
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="text-sm font-medium text-zinc-100 truncate">{w.name}</div>
                    <RoleBadge role={w.role} />
                  </div>
                  {w.description && <div className="text-[11px] text-zinc-500 mt-0.5 truncate">{w.description}</div>}
                </button>
              ))}
              {!loading && workspaces.length === 0 && (
                <div className="px-4 py-6 text-center text-xs text-zinc-500">No workspaces yet.</div>
              )}
            </div>
          </div>

          {/* Accept invite */}
          <div className="border border-zinc-800 bg-zinc-900/40 p-4">
            <div className="text-xs mono uppercase tracking-widest text-zinc-500 mb-2 flex items-center gap-1">
              <Mail className="w-3.5 h-3.5" /> Accept invite
            </div>
            <input
              value={acceptToken}
              onChange={(e) => setAcceptToken(e.target.value)}
              placeholder="Paste invite token"
              data-testid="ws-accept-token"
              className="w-full bg-zinc-950 border border-zinc-800 px-3 py-2 text-sm mb-2 focus:outline-none focus:border-emerald-500 mono"
            />
            <button
              onClick={accept}
              disabled={!acceptToken.trim()}
              data-testid="ws-accept-btn"
              className="w-full border border-zinc-700 hover:border-emerald-500/50 disabled:opacity-50 text-zinc-100 font-mono text-xs py-2 flex items-center justify-center gap-1"
            >
              <CheckCircle2 className="w-3.5 h-3.5" /> Accept
            </button>
          </div>
        </div>

        {/* RIGHT — detail */}
        <div className="md:col-span-2 space-y-4">
          {!detail && (
            <div className="border border-dashed border-zinc-800 p-12 text-center text-zinc-500 text-sm">
              Select or create a workspace to get started.
            </div>
          )}
          {detail && (
            <>
              <div className="border border-zinc-800 bg-zinc-900/40 p-5">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <div className="text-[10px] mono uppercase tracking-widest text-zinc-500">Workspace</div>
                    <div className="text-xl font-display font-bold text-zinc-50">{detail.workspace.name}</div>
                    {detail.workspace.description && (
                      <div className="text-sm text-zinc-400 mt-1">{detail.workspace.description}</div>
                    )}
                  </div>
                  {canManage && (
                    <button
                      onClick={() => remove(detail.workspace.id)}
                      data-testid="ws-delete-btn"
                      className="text-red-400 hover:text-red-300 text-xs mono flex items-center gap-1"
                    >
                      <Trash2 className="w-3.5 h-3.5" /> Delete
                    </button>
                  )}
                </div>
              </div>

              {/* Invite */}
              {canManage && (
                <div className="border border-zinc-800 bg-zinc-900/40 p-5">
                  <div className="text-xs mono uppercase tracking-widest text-zinc-500 mb-3 flex items-center gap-1">
                    <UserPlus className="w-3.5 h-3.5" /> Invite member
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <input
                      type="email"
                      value={inviteEmail}
                      onChange={(e) => setInviteEmail(e.target.value)}
                      placeholder="teammate@company.com"
                      data-testid="ws-invite-email"
                      className="flex-1 min-w-[240px] bg-zinc-950 border border-zinc-800 px-3 py-2 text-sm focus:outline-none focus:border-emerald-500"
                    />
                    <select
                      value={inviteRole}
                      onChange={(e) => setInviteRole(e.target.value)}
                      data-testid="ws-invite-role"
                      className="bg-zinc-950 border border-zinc-800 px-3 py-2 text-sm mono focus:outline-none focus:border-emerald-500"
                    >
                      <option value="admin">admin</option>
                      <option value="analyst">analyst</option>
                      <option value="viewer">viewer</option>
                    </select>
                    <button
                      onClick={invite}
                      disabled={!inviteEmail.trim()}
                      data-testid="ws-invite-btn"
                      className="bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-zinc-950 font-mono text-xs font-semibold px-4 py-2"
                    >
                      Send invite
                    </button>
                  </div>
                  {inviteToken && (
                    <div className="mt-3 border border-emerald-500/40 bg-emerald-500/5 p-3 text-xs">
                      <div className="text-emerald-300 mb-1">Invite created — share this token:</div>
                      <div className="flex items-center gap-2">
                        <code className="mono text-emerald-200 bg-zinc-950 px-2 py-1 break-all flex-1" data-testid="ws-invite-token-value">
                          {inviteToken}
                        </code>
                        <button
                          onClick={() => navigator.clipboard.writeText(inviteToken)}
                          className="text-zinc-400 hover:text-zinc-100"
                          title="Copy"
                        >
                          <Copy className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Members */}
              <div className="border border-zinc-800 bg-zinc-900/40">
                <div className="px-5 py-3 border-b border-zinc-800 text-xs mono uppercase tracking-widest text-zinc-500 flex items-center justify-between">
                  <span>Members ({detail.members?.length || 0})</span>
                </div>
                <div className="divide-y divide-zinc-800">
                  {detail.members?.map((m) => (
                    <div key={m.user_id} className="px-5 py-3 flex items-center justify-between gap-3">
                      <div className="min-w-0">
                        <div className="text-sm text-zinc-100 truncate">{m.email || m.user_id}</div>
                        <div className="text-[10px] mono text-zinc-500">joined {new Date(m.joined_at).toLocaleDateString()}</div>
                      </div>
                      <div className="flex items-center gap-2">
                        <RoleBadge role={m.role} />
                        {canManage && m.role !== 'owner' && (
                          <>
                            <select
                              value={m.role}
                              onChange={(e) => changeRole(m.user_id, e.target.value)}
                              data-testid={`ws-member-role-${m.user_id}`}
                              className="bg-zinc-950 border border-zinc-800 text-xs mono px-2 py-1"
                            >
                              <option value="admin">admin</option>
                              <option value="analyst">analyst</option>
                              <option value="viewer">viewer</option>
                            </select>
                            <button
                              onClick={() => removeMember(m.user_id)}
                              data-testid={`ws-remove-${m.user_id}`}
                              className="text-red-400 hover:text-red-300"
                              title="Remove"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Pending invites */}
              {detail.pending_invites?.length > 0 && (
                <div className="border border-zinc-800 bg-zinc-900/40">
                  <div className="px-5 py-3 border-b border-zinc-800 text-xs mono uppercase tracking-widest text-zinc-500">
                    Pending invites ({detail.pending_invites.length})
                  </div>
                  <div className="divide-y divide-zinc-800">
                    {detail.pending_invites.map((inv) => (
                      <div key={inv.token} className="px-5 py-3 flex items-center justify-between gap-3">
                        <div className="min-w-0">
                          <div className="text-sm text-zinc-100 truncate">{inv.email}</div>
                          <div className="text-[10px] mono text-zinc-500 truncate">token: {inv.token.slice(0, 12)}…</div>
                        </div>
                        <RoleBadge role={inv.role} />
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
