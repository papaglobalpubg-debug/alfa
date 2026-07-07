import React, { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Bomb, Trash2, ExternalLink, Square, CheckSquare, StopCircle, X } from 'lucide-react';
import api from '@/lib/api';
import { scanStatusColor } from '@/lib/uiHelpers';

const RUNNING_STATES = new Set([
  'pending', 'queued', 'running', 'discovering', 'analyzing',
  'verifying', 'cancelling',
]);

export default function VulnScanHistory() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(new Set());
  const [busy, setBusy] = useState(false);
  const [flash, setFlash] = useState(null);

  const load = async () => {
    try {
      const r = await api.listVulnScans({ limit: 200 });
      setScans(r.data.scans || []);
    } catch (e) {
      // Silent — best-effort load
    }
    setLoading(false);
  };

  useEffect(() => {
    load();
    const iv = setInterval(load, 4000);
    return () => clearInterval(iv);
  }, []);

  const toggleSelect = (id) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const selectAll = () => {
    if (selected.size === scans.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(scans.map((s) => s.id)));
    }
  };

  const runningSelected = useMemo(
    () => scans.filter((s) => selected.has(s.id) && RUNNING_STATES.has(s.status)),
    [scans, selected],
  );

  const showFlash = (text, tone = 'ok') => {
    setFlash({ text, tone });
    setTimeout(() => setFlash(null), 2500);
  };

  const stopOne = async (id, e) => {
    if (e) e.stopPropagation();
    setBusy(true);
    try {
      await api.cancelVulnScan(id);
      showFlash('Scan stopped');
      load();
    } catch (err) {
      showFlash('Stop failed', 'err');
    }
    setBusy(false);
  };

  const delOne = async (id, e) => {
    if (e) e.stopPropagation();
    if (!window.confirm('Delete this scan?')) return;
    setBusy(true);
    try {
      await api.deleteVulnScan(id);
      setSelected((prev) => {
        const next = new Set(prev); next.delete(id); return next;
      });
      showFlash('Deleted');
      load();
    } catch (err) {
      showFlash('Delete failed', 'err');
    }
    setBusy(false);
  };

  const bulkStop = async () => {
    const ids = runningSelected.map((s) => s.id);
    if (!ids.length) return;
    setBusy(true);
    try {
      const r = await api.bulkCancelVulnScans(ids);
      showFlash(`Stopped ${r.data.count} scan(s)`);
      load();
    } catch (err) {
      showFlash('Bulk stop failed', 'err');
    }
    setBusy(false);
  };

  const bulkDelete = async () => {
    const ids = Array.from(selected);
    if (!ids.length) return;
    if (!window.confirm(`Delete ${ids.length} scan(s)? This cannot be undone.`)) return;
    setBusy(true);
    try {
      const r = await api.bulkDeleteVulnScans(ids);
      showFlash(`Deleted ${r.data.deleted} scan(s)`);
      setSelected(new Set());
      load();
    } catch (err) {
      showFlash('Bulk delete failed', 'err');
    }
    setBusy(false);
  };

  const allSelected = scans.length > 0 && selected.size === scans.length;

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-zinc-50 tracking-tight flex items-center gap-2">
            <Bomb className="w-5 h-5 text-red-500" /> Vuln Scan History
          </h1>
          <p className="text-xs mono text-zinc-500 mt-1">
            CyberScope v7.4 — {scans.length} scans · {selected.size} selected
          </p>
        </div>
        <Link
          to="/vuln/new"
          data-testid="link-new-vuln-scan"
          className="px-4 py-2 bg-red-500 hover:bg-red-600 text-white font-bold mono text-xs uppercase tracking-widest transition-colors"
        >
          + New Scan
        </Link>
      </div>

      {/* Bulk actions bar — sticky when items selected */}
      <div
        data-testid="bulk-actions-bar"
        className={`mb-4 border transition-all ${
          selected.size > 0
            ? 'border-red-500/40 bg-red-500/5 p-3'
            : 'border-zinc-800 bg-zinc-950 p-2'
        }`}
      >
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-3">
            <button
              data-testid="select-all-btn"
              onClick={selectAll}
              disabled={scans.length === 0}
              className="flex items-center gap-2 text-xs mono text-zinc-300 hover:text-zinc-50 disabled:opacity-40"
            >
              {allSelected ? <CheckSquare className="w-4 h-4 text-red-400" /> : <Square className="w-4 h-4" />}
              {allSelected ? 'Deselect all' : 'Select all'}
            </button>
            <span className="text-xs mono text-zinc-500">
              {selected.size > 0 && `${selected.size} selected · ${runningSelected.length} running`}
            </span>
          </div>
          <div className="flex items-center gap-2">
            {flash && (
              <span className={`text-xs mono px-2 py-1 border ${
                flash.tone === 'err'
                  ? 'border-red-500/40 text-red-400'
                  : 'border-emerald-500/40 text-emerald-400'
              }`}>{flash.text}</span>
            )}
            <button
              data-testid="bulk-stop-btn"
              disabled={busy || runningSelected.length === 0}
              onClick={bulkStop}
              className="flex items-center gap-1 px-3 py-1.5 border border-amber-500/40 text-amber-400 hover:bg-amber-500/10 mono text-xs uppercase tracking-widest disabled:opacity-30 disabled:cursor-not-allowed"
            >
              <StopCircle className="w-3 h-3" />
              Stop ({runningSelected.length})
            </button>
            <button
              data-testid="bulk-delete-btn"
              disabled={busy || selected.size === 0}
              onClick={bulkDelete}
              className="flex items-center gap-1 px-3 py-1.5 border border-red-500/40 text-red-400 hover:bg-red-500/10 mono text-xs uppercase tracking-widest disabled:opacity-30 disabled:cursor-not-allowed"
            >
              <Trash2 className="w-3 h-3" />
              Delete ({selected.size})
            </button>
            {selected.size > 0 && (
              <button
                data-testid="bulk-clear-btn"
                onClick={() => setSelected(new Set())}
                className="flex items-center gap-1 px-2 py-1.5 border border-zinc-800 text-zinc-400 hover:text-zinc-50 mono text-xs"
              >
                <X className="w-3 h-3" />
              </button>
            )}
          </div>
        </div>
      </div>

      <div className="border border-zinc-800 bg-zinc-950 overflow-x-auto">
        <table className="w-full text-xs mono">
          <thead>
            <tr className="border-b border-zinc-800 bg-zinc-900/50">
              <th className="w-10 p-3"></th>
              <th className="text-left p-3 text-zinc-500 uppercase tracking-widest">Target</th>
              <th className="text-left p-3 text-zinc-500 uppercase tracking-widest">Depth</th>
              <th className="text-left p-3 text-zinc-500 uppercase tracking-widest">Status</th>
              <th className="text-left p-3 text-zinc-500 uppercase tracking-widest">Findings</th>
              <th className="text-left p-3 text-zinc-500 uppercase tracking-widest">Started</th>
              <th className="text-right p-3 text-zinc-500 uppercase tracking-widest">Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading && scans.length === 0 && (
              <tr><td colSpan={7} className="p-6 text-center text-zinc-500">Loading...</td></tr>
            )}
            {!loading && scans.length === 0 && (
              <tr><td colSpan={7} className="p-6 text-center text-zinc-500">
                No scans yet. <Link to="/vuln/new" className="text-emerald-500">Launch one</Link>.
              </td></tr>
            )}
            {scans.map((s) => {
              const running = RUNNING_STATES.has(s.status);
              const isSel = selected.has(s.id);
              return (
                <tr
                  key={s.id}
                  data-testid={`vuln-scan-row-${s.id}`}
                  className={`border-b border-zinc-900 hover:bg-zinc-900/30 ${
                    isSel ? 'bg-red-500/5' : ''
                  }`}
                >
                  <td className="p-3">
                    <button
                      data-testid={`select-vuln-${s.id}`}
                      onClick={() => toggleSelect(s.id)}
                      className="text-zinc-400 hover:text-red-400"
                    >
                      {isSel
                        ? <CheckSquare className="w-4 h-4 text-red-400" />
                        : <Square className="w-4 h-4" />}
                    </button>
                  </td>
                  <td className="p-3 text-zinc-100 truncate max-w-xs">{s.target}</td>
                  <td className="p-3 text-zinc-400 uppercase tracking-widest">{s.depth}</td>
                  <td className="p-3">
                    <span className={scanStatusColor(s.status)}>{s.status}</span>
                  </td>
                  <td className="p-3">
                    <div className="flex gap-2">
                      {s.summary?.critical > 0 && <span className="text-red-500">C:{s.summary.critical}</span>}
                      {s.summary?.high > 0 && <span className="text-orange-400">H:{s.summary.high}</span>}
                      {s.summary?.medium > 0 && <span className="text-yellow-400">M:{s.summary.medium}</span>}
                      {s.summary?.low > 0 && <span className="text-blue-400">L:{s.summary.low}</span>}
                      {!s.summary?.total && <span className="text-zinc-600">—</span>}
                    </div>
                  </td>
                  <td className="p-3 text-zinc-500">{new Date(s.started_at).toLocaleString()}</td>
                  <td className="p-3 text-right">
                    <div className="flex gap-1 justify-end">
                      {running && (
                        <button
                          data-testid={`stop-vuln-${s.id}`}
                          onClick={(e) => stopOne(s.id, e)}
                          title="Stop scan immediately"
                          className="p-1 text-amber-400 hover:text-amber-300 hover:bg-amber-500/10 border border-transparent hover:border-amber-500/30"
                        >
                          <StopCircle className="w-4 h-4" />
                        </button>
                      )}
                      <Link
                        to={`/vuln/scan/${s.id}`}
                        data-testid={`view-vuln-${s.id}`}
                        className="p-1 text-zinc-400 hover:text-emerald-500"
                      >
                        <ExternalLink className="w-4 h-4" />
                      </Link>
                      <button
                        onClick={(e) => delOne(s.id, e)}
                        data-testid={`del-vuln-${s.id}`}
                        className="p-1 text-zinc-400 hover:text-red-500"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
