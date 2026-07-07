import React, { useState, useEffect } from 'react';
import { GitCompare, ArrowRight, Loader2 } from 'lucide-react';
import api from '@/lib/api';

const DiffColumn = ({ title, items, color }) => (
  <div className="border border-zinc-800 bg-zinc-950">
    <div className="p-3 border-b border-zinc-800 text-xs mono flex items-center justify-between">
      <span className={`uppercase tracking-widest ${color}`}>{title}</span>
      <span className="text-zinc-400 font-bold">{items?.length || 0}</span>
    </div>
    <div className="max-h-[500px] overflow-y-auto p-2 space-y-1">
      {(items || []).length === 0 ? (
        <div className="p-6 text-center text-[10px] mono text-zinc-500">None</div>
      ) : items.map((f, i) => (
        <div key={i} className="p-2 border border-zinc-900 bg-zinc-950 text-[11px] mono">
          <div className="flex items-center gap-2 mb-1">
            <span className={`uppercase text-[9px] tracking-widest ${
              f.severity === 'critical' ? 'text-red-400' :
              f.severity === 'high' ? 'text-orange-400' : 'text-yellow-400'
            }`}>{f.severity}</span>
            <span className="text-zinc-400">{f.type}·{f.subtype || ''}</span>
          </div>
          <div className="text-zinc-500 truncate">{f.url}</div>
        </div>
      ))}
    </div>
  </div>
);

export default function CompareScansPage() {
  const [scans, setScans] = useState([]);
  const [a, setA] = useState('');
  const [b, setB] = useState('');
  const [diff, setDiff] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    api.listVulnScans({ limit: 50 }).then(r => {
      setScans(r.data.items || r.data.scans || []);
    }).catch(() => {});
  }, []);

  const run = async () => {
    if (!a || !b || a === b) return;
    setLoading(true); setDiff(null);
    try {
      const r = await api.diffScans(a, b);
      setDiff(r.data);
    } catch (e) {
      setDiff({ error: String(e?.message || e) });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-4" data-testid="compare-page">
      <div className="flex items-center gap-3 mb-2">
        <GitCompare className="w-6 h-6 text-emerald-500" />
        <div>
          <h1 className="text-2xl font-bold text-zinc-50">Scan Comparison</h1>
          <p className="text-xs mono text-zinc-500">Compare two scans to detect regressions and confirm fixes.</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-[1fr_auto_1fr_auto] gap-3 items-end">
        <div>
          <div className="text-[10px] mono uppercase tracking-widest text-zinc-500 mb-1">Baseline scan (A)</div>
          <select value={a} onChange={e => setA(e.target.value)} data-testid="select-scan-a"
                  className="w-full bg-zinc-900 border border-zinc-800 px-3 py-2 mono text-sm">
            <option value="">-- select --</option>
            {scans.map(s => <option key={s.id} value={s.id}>{s.target} · {(s.id || '').slice(0,8)}</option>)}
          </select>
        </div>
        <ArrowRight className="w-5 h-5 text-emerald-500 mb-3" />
        <div>
          <div className="text-[10px] mono uppercase tracking-widest text-zinc-500 mb-1">New scan (B)</div>
          <select value={b} onChange={e => setB(e.target.value)} data-testid="select-scan-b"
                  className="w-full bg-zinc-900 border border-zinc-800 px-3 py-2 mono text-sm">
            <option value="">-- select --</option>
            {scans.map(s => <option key={s.id} value={s.id}>{s.target} · {(s.id || '').slice(0,8)}</option>)}
          </select>
        </div>
        <button onClick={run} disabled={loading || !a || !b || a === b} data-testid="run-diff-btn"
                className="px-4 py-2 bg-emerald-500 hover:bg-emerald-600 disabled:opacity-50 text-black font-bold mono text-xs uppercase tracking-widest flex items-center gap-2">
          {loading ? <Loader2 className="w-3 h-3 animate-spin" /> : null}
          {loading ? 'Comparing...' : 'Compare'}
        </button>
      </div>

      {diff?.error && (
        <div className="border border-red-500/40 bg-red-500/10 text-red-400 p-4 mono text-xs">{diff.error}</div>
      )}

      {diff && !diff.error && (
        <>
          <div className="grid grid-cols-3 gap-2">
            <div className="border border-red-500/30 bg-red-500/5 p-3 text-xs mono">
              <div className="text-red-400 uppercase text-[10px] tracking-widest">NEW findings</div>
              <div className="text-red-400 text-2xl font-bold">{diff.summary?.new || 0}</div>
            </div>
            <div className="border border-emerald-500/30 bg-emerald-500/5 p-3 text-xs mono">
              <div className="text-emerald-400 uppercase text-[10px] tracking-widest">FIXED</div>
              <div className="text-emerald-400 text-2xl font-bold">{diff.summary?.fixed || 0}</div>
            </div>
            <div className="border border-zinc-700 bg-zinc-900 p-3 text-xs mono">
              <div className="text-zinc-400 uppercase text-[10px] tracking-widest">UNCHANGED</div>
              <div className="text-zinc-400 text-2xl font-bold">{diff.summary?.unchanged || 0}</div>
            </div>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <DiffColumn title="🔴 New in B" items={diff.new} color="text-red-400" />
            <DiffColumn title="🟢 Fixed (was in A)" items={diff.fixed} color="text-emerald-400" />
          </div>
        </>
      )}
    </div>
  );
}
