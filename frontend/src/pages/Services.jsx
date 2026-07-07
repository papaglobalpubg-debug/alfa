import React, { useEffect, useState } from 'react';
import api from '@/lib/api';
import { PriorityBadge } from '@/components/Badges';
import { SERVICES } from '@/constants/testIds';

export default function Services() {
  const [items, setItems] = useState([]);
  const [q, setQ] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.services().then(({ data }) => {
      setItems(data.services || []);
      setLoading(false);
    });
  }, []);

  const filtered = items.filter(
    (s) =>
      !q ||
      s.name.toLowerCase().includes(q.toLowerCase()) ||
      s.key.toLowerCase().includes(q.toLowerCase()) ||
      s.cnames.some((c) => c.toLowerCase().includes(q.toLowerCase()))
  );

  const claimable = items.filter((s) => s.claimable === true).length;
  const verifiable = items.filter((s) => s.claimable === 'verify').length;
  const dead = items.filter((s) => s.claimable === false).length;

  return (
    <div data-testid={SERVICES.container} className="max-w-6xl space-y-6">
      <header>
        <h1 className="text-2xl font-display font-bold text-zinc-50 tracking-tight">
          <span className="text-emerald-500">&gt;</span> Service Fingerprints
        </h1>
        <p className="text-zinc-500 text-sm mt-1 mono">
          {items.length} services recognized ({claimable} claimable, {verifiable} verify-required, {dead} dead)
        </p>
      </header>

      <div className="bg-zinc-900 border border-zinc-800 p-4">
        <input
          data-testid={SERVICES.searchInput}
          type="text"
          placeholder="search by name, key, or CNAME pattern..."
          value={q}
          onChange={(e) => setQ(e.target.value)}
          className="w-full px-3 py-2 bg-black border border-zinc-800 mono text-sm text-zinc-50 focus:outline-none focus:border-emerald-500 mb-4"
        />
        {loading ? (
          <div className="text-zinc-600 mono text-sm p-8 text-center">Loading...</div>
        ) : (
          <table data-testid={SERVICES.table} className="w-full text-sm">
            <thead>
              <tr className="text-left text-zinc-500 text-[10px] uppercase tracking-widest border-b border-zinc-800">
                <th className="py-2 px-2 font-medium">Service</th>
                <th className="py-2 px-2 font-medium">Priority</th>
                <th className="py-2 px-2 font-medium">Claimable</th>
                <th className="py-2 px-2 font-medium">Verifier</th>
                <th className="py-2 px-2 font-medium">CNAME Patterns</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((s) => (
                <tr key={s.key} className="border-b border-zinc-900 hover:bg-zinc-800/40">
                  <td className="py-2 px-2 mono">
                    <span className="text-zinc-50">{s.name}</span>
                    <span className="text-zinc-600 text-xs ml-2">({s.key})</span>
                  </td>
                  <td className="py-2 px-2"><PriorityBadge priority={s.priority} /></td>
                  <td className="py-2 px-2 mono text-xs">
                    {s.claimable === true && <span className="text-emerald-500">YES</span>}
                    {s.claimable === 'verify' && <span className="text-amber-500">VERIFY</span>}
                    {s.claimable === false && <span className="text-zinc-600">NO</span>}
                  </td>
                  <td className="py-2 px-2 mono text-xs">
                    {s.has_verifier ? <span className="text-emerald-500">ACTIVE</span> : <span className="text-zinc-700">-</span>}
                  </td>
                  <td className="py-2 px-2 mono text-xs text-zinc-400 max-w-[500px]">
                    <div className="truncate" title={s.cnames.join(', ')}>
                      {s.cnames.join(', ') || '-'}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
