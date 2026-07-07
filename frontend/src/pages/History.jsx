import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '@/lib/api';
import { StatusBadge, PulseDot } from '@/components/Badges';
import { HISTORY } from '@/constants/testIds';

function fmt(iso) {
  if (!iso) return '-';
  try { return new Date(iso).toLocaleString(); } catch (e) { return iso; }
}

const STATUSES = ['pending', 'discovering', 'analyzing', 'verifying', 'completed', 'failed'];

export default function History() {
  const nav = useNavigate();
  const [scans, setScans] = useState([]);
  const [total, setTotal] = useState(0);
  const [domainF, setDomainF] = useState('');
  const [statusF, setStatusF] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    const load = async () => {
      try {
        const { data } = await api.listScans({
          domain: domainF || undefined,
          status: statusF || undefined,
          limit: 100,
        });
        if (mounted) {
          setScans(data.scans || []);
          setTotal(data.total || 0);
        }
      } finally {
        if (mounted) setLoading(false);
      }
    };
    load();
    const t = setInterval(load, 5000);
    return () => { mounted = false; clearInterval(t); };
  }, [domainF, statusF]);

  return (
    <div data-testid={HISTORY.container} className="space-y-6 max-w-7xl">
      <header>
        <h1 className="text-2xl font-display font-bold text-zinc-50 tracking-tight">
          <span className="text-emerald-500">&gt;</span> Scan History
        </h1>
        <p className="text-zinc-500 text-sm mt-1 mono">
          {total} total scans
        </p>
      </header>

      <div className="bg-zinc-900 border border-zinc-800 p-4">
        <div className="flex gap-2 mb-4">
          <input
            data-testid={HISTORY.filterDomain}
            type="text"
            placeholder="filter by domain..."
            value={domainF}
            onChange={(e) => setDomainF(e.target.value)}
            className="px-3 py-1.5 bg-black border border-zinc-800 mono text-xs text-zinc-300 focus:outline-none focus:border-emerald-500 w-64"
          />
          <select
            data-testid={HISTORY.filterStatus}
            value={statusF}
            onChange={(e) => setStatusF(e.target.value)}
            className="px-3 py-1.5 bg-black border border-zinc-800 mono text-xs text-zinc-300 focus:outline-none focus:border-emerald-500"
          >
            <option value="">All statuses</option>
            {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>

        {loading ? (
          <div className="text-zinc-600 mono text-sm p-8 text-center">Loading...</div>
        ) : scans.length === 0 ? (
          <div className="text-zinc-600 mono text-sm p-8 text-center border border-dashed border-zinc-800">
            No scans found.
          </div>
        ) : (
          <table data-testid={HISTORY.table} className="w-full text-sm">
            <thead>
              <tr className="text-left text-zinc-500 text-[10px] uppercase tracking-widest border-b border-zinc-800">
                <th className="py-2 px-2 font-medium">Domain</th>
                <th className="py-2 px-2 font-medium">Status</th>
                <th className="py-2 px-2 font-medium">Findings</th>
                <th className="py-2 px-2 font-medium">Started</th>
                <th className="py-2 px-2 font-medium">Finished</th>
                <th className="py-2 px-2 font-medium">Duration</th>
                <th className="py-2 px-2 font-medium">ID</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => {
                const running = ['pending', 'discovering', 'analyzing', 'verifying'].includes(s.status);
                return (
                  <tr key={s.id}
                    data-testid={`history-row-${s.id}`}
                    onClick={() => nav(`/scan/${s.id}`)}
                    className="border-b border-zinc-900 hover:bg-zinc-800/40 cursor-pointer transition-colors">
                    <td className="py-2 px-2 mono text-zinc-50">
                      {running && <span className="mr-2"><PulseDot /></span>}
                      {s.domain}
                    </td>
                    <td className="py-2 px-2"><StatusBadge status={s.status} /></td>
                    <td className="py-2 px-2 mono text-xs text-zinc-400">
                      {(s.summary?.verified_claimable || 0) > 0 && (
                        <span className="text-red-400 mr-2">V:{s.summary.verified_claimable}</span>
                      )}
                      {(s.summary?.claimable || 0) > 0 && (
                        <span className="text-emerald-400 mr-2">C:{s.summary.claimable}</span>
                      )}
                      <span className="text-zinc-600">/ {s.summary?.total_analyzed || 0}</span>
                    </td>
                    <td className="py-2 px-2 mono text-xs text-zinc-500">{fmt(s.started_at)}</td>
                    <td className="py-2 px-2 mono text-xs text-zinc-500">{fmt(s.finished_at)}</td>
                    <td className="py-2 px-2 mono text-xs text-zinc-500">
                      {s.duration ? `${s.duration.toFixed(1)}s` : '-'}
                    </td>
                    <td className="py-2 px-2 mono text-xs text-zinc-600">{s.id.slice(0, 8)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
