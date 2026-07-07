import React, { useEffect, useState } from 'react';
import api from '@/lib/api';
import { MONITORS } from '@/constants/testIds';
import { Plus, Trash2, Play, Pause } from 'lucide-react';

function fmt(iso) {
  if (!iso) return 'never';
  try { return new Date(iso).toLocaleString(); } catch (e) { return iso; }
}

export default function Monitors() {
  const [items, setItems] = useState([]);
  const [showAdd, setShowAdd] = useState(false);
  const [domain, setDomain] = useState('');
  const [interval, setIntervalVal] = useState(24);

  const load = async () => {
    const { data } = await api.listMonitors();
    setItems(data.monitors || []);
  };

  useEffect(() => {
    load();
    const t = setInterval(load, 8000);
    return () => clearInterval(t);
  }, []);

  const add = async () => {
    if (!domain.trim()) return;
    await api.createMonitor({
      domain: domain.trim().toLowerCase(),
      interval_hours: Number(interval),
      enabled: true,
    });
    setDomain('');
    setIntervalVal(24);
    setShowAdd(false);
    load();
  };

  const toggle = async (m) => {
    await api.updateMonitor(m.id, { enabled: !m.enabled });
    load();
  };

  const del = async (m) => {
    if (!window.confirm(`Delete monitor for ${m.domain}?`)) return;
    await api.deleteMonitor(m.id);
    load();
  };

  return (
    <div data-testid={MONITORS.container} className="max-w-5xl space-y-6">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-display font-bold text-zinc-50 tracking-tight">
            <span className="text-emerald-500">&gt;</span> Continuous Monitoring
          </h1>
          <p className="text-zinc-500 text-sm mt-1 mono">
            Automatically rescan domains at fixed intervals
          </p>
        </div>
        <button
          data-testid={MONITORS.addBtn}
          onClick={() => setShowAdd(!showAdd)}
          className="flex items-center gap-2 px-4 py-2 bg-emerald-500 text-zinc-950 font-semibold hover:bg-emerald-400 mono text-sm"
        >
          <Plus className="w-4 h-4" /> Add Monitor
        </button>
      </header>

      {showAdd && (
        <div className="bg-zinc-900 border border-zinc-800 p-4">
          <div className="grid grid-cols-3 gap-3">
            <label className="col-span-2">
              <div className="text-xs uppercase tracking-widest text-zinc-500 mono mb-1">Domain</div>
              <input
                data-testid={MONITORS.domainInput}
                type="text"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="example.com"
                className="w-full px-3 py-2 bg-black border border-zinc-800 mono text-sm text-zinc-50 focus:outline-none focus:border-emerald-500"
              />
            </label>
            <label>
              <div className="text-xs uppercase tracking-widest text-zinc-500 mono mb-1">Interval (hours)</div>
              <input
                data-testid={MONITORS.intervalInput}
                type="number" min="1" max="720" value={interval}
                onChange={(e) => setIntervalVal(e.target.value)}
                className="w-full px-3 py-2 bg-black border border-zinc-800 mono text-sm text-zinc-50 focus:outline-none focus:border-emerald-500"
              />
            </label>
          </div>
          <div className="flex justify-end gap-2 mt-3">
            <button onClick={() => setShowAdd(false)}
              className="px-3 py-1.5 border border-zinc-800 text-zinc-400 hover:text-zinc-50 mono text-xs">
              Cancel
            </button>
            <button data-testid={MONITORS.saveBtn} onClick={add}
              className="px-4 py-1.5 bg-emerald-500 text-zinc-950 mono text-xs font-semibold hover:bg-emerald-400">
              Save
            </button>
          </div>
        </div>
      )}

      <div className="bg-zinc-900 border border-zinc-800 p-4">
        {items.length === 0 ? (
          <div className="text-zinc-600 mono text-sm p-8 text-center border border-dashed border-zinc-800">
            No monitors yet. Add one to enable continuous monitoring.
          </div>
        ) : (
          <table data-testid={MONITORS.table} className="w-full text-sm">
            <thead>
              <tr className="text-left text-zinc-500 text-[10px] uppercase tracking-widest border-b border-zinc-800">
                <th className="py-2 px-2 font-medium">Domain</th>
                <th className="py-2 px-2 font-medium">Interval</th>
                <th className="py-2 px-2 font-medium">Enabled</th>
                <th className="py-2 px-2 font-medium">Last Scan</th>
                <th className="py-2 px-2 font-medium">Created</th>
                <th className="py-2 px-2 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map((m) => (
                <tr key={m.id} data-testid={`monitor-row-${m.id}`}
                  className="border-b border-zinc-900 hover:bg-zinc-800/40 transition-colors">
                  <td className="py-2 px-2 mono text-zinc-50">{m.domain}</td>
                  <td className="py-2 px-2 mono text-xs text-zinc-400">{m.interval_hours}h</td>
                  <td className="py-2 px-2">
                    <span className={`inline-block w-2 h-2 rounded-full ${m.enabled ? 'bg-emerald-500' : 'bg-zinc-600'}`}></span>
                    <span className="ml-2 text-xs mono text-zinc-400">{m.enabled ? 'ON' : 'OFF'}</span>
                  </td>
                  <td className="py-2 px-2 mono text-xs text-zinc-500">{fmt(m.last_scan_at)}</td>
                  <td className="py-2 px-2 mono text-xs text-zinc-500">{fmt(m.created_at)}</td>
                  <td className="py-2 px-2 text-right">
                    <button onClick={() => toggle(m)}
                      data-testid={`monitor-toggle-${m.id}`}
                      className="mr-2 p-1 border border-zinc-800 hover:border-zinc-700 text-zinc-400 hover:text-zinc-50">
                      {m.enabled ? <Pause className="w-3 h-3" /> : <Play className="w-3 h-3" />}
                    </button>
                    <button onClick={() => del(m)}
                      data-testid={`monitor-delete-${m.id}`}
                      className="p-1 border border-red-500/30 hover:bg-red-500/10 text-red-400">
                      <Trash2 className="w-3 h-3" />
                    </button>
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
