import React, { useState, useEffect } from 'react';
import api from '@/lib/api';
import { Radar, Plus, Trash2, PowerOff, Power } from 'lucide-react';
import { RippleDot, RadarSweep, StatusPill } from '@/components/Loaders';

const CHANNEL_OPTIONS = ['discord', 'slack', 'telegram'];

export default function VulnMonitors() {
  const [items, setItems] = useState([]);
  const [target, setTarget] = useState('');
  const [interval, setInterval] = useState(24);
  const [channels, setChannels] = useState([]);
  const [webhook, setWebhook] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  const load = async () => {
    try {
      const { data } = await api.listVulnMonitors();
      setItems(data.monitors || []);
    } catch { setItems([]); }
  };
  useEffect(() => { load(); }, []);

  const create = async () => {
    setBusy(true); setErr('');
    try {
      await api.createVulnMonitor({
        target, interval_hours: interval,
        channels, webhook_url: webhook || null, active: true,
      });
      setTarget(''); setChannels([]); setWebhook('');
      await load();
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message);
    }
    setBusy(false);
  };

  return (
    <div data-testid="vuln-monitors-page" className="max-w-5xl mx-auto space-y-6 animate-fade-in-up">
      <header className="relative border border-cyan-500/40 bg-gradient-to-r from-cyan-950/40 via-zinc-950 to-zinc-950 p-6 overflow-hidden">
        <div className="relative flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Radar className="w-6 h-6 text-cyan-400 animate-glow-pulse" />
              <span className="text-[10px] mono uppercase tracking-widest text-cyan-400 border border-cyan-500/50 bg-cyan-500/10 px-2 py-0.5">
                Continuous Attack Surface Monitoring
              </span>
            </div>
            <h1 className="text-2xl md:text-3xl font-display font-bold text-zinc-50">Vuln Monitors</h1>
            <p className="text-zinc-400 text-sm mt-2 max-w-xl">
              Fire-and-forget attack surface watchdogs. Runs a scan every N hours and
              pings Discord / Slack / Telegram on findings.
            </p>
          </div>
          <RadarSweep size={48} color="cyan" />
        </div>
      </header>

      <section className="bg-zinc-900/50 border border-zinc-800 p-4 space-y-3">
        <h3 className="text-xs font-semibold text-cyan-400 mono uppercase tracking-widest">Create monitor</h3>
        <input
          data-testid="monitor-target"
          value={target}
          onChange={(e) => setTarget(e.target.value.trim())}
          className="w-full bg-zinc-950 border border-zinc-800 text-zinc-100 mono text-sm p-3 focus:border-cyan-500/50 focus:outline-none"
          placeholder="https://target.example.com"
        />
        <div className="flex gap-2 items-center flex-wrap">
          <label className="text-[10px] mono uppercase text-zinc-500">Every</label>
          <input type="number" min={1} max={720} value={interval} onChange={(e) => setInterval(+e.target.value)}
            data-testid="monitor-interval"
            className="w-20 bg-zinc-950 border border-zinc-800 text-zinc-100 mono text-sm p-2 text-center" />
          <span className="text-[10px] mono text-zinc-500">hours</span>
          <div className="flex-1 min-w-0" />
          {CHANNEL_OPTIONS.map((c) => (
            <button key={c} onClick={() => setChannels(channels.includes(c) ? channels.filter(x => x !== c) : [...channels, c])}
              data-testid={`monitor-channel-${c}`}
              className={`px-2 py-1 border mono text-[10px] uppercase tracking-widest ${
                channels.includes(c) ? 'border-cyan-500 bg-cyan-500/20 text-cyan-300' : 'border-zinc-800 text-zinc-400'
              }`}>{c}</button>
          ))}
        </div>
        {channels.length > 0 && (
          <input value={webhook} onChange={(e) => setWebhook(e.target.value.trim())}
            data-testid="monitor-webhook"
            className="w-full bg-zinc-950 border border-zinc-800 text-zinc-100 mono text-xs p-2"
            placeholder="Webhook URL (Discord/Slack)" />
        )}
        <div className="flex gap-2 items-center">
          <button
            data-testid="monitor-create-btn"
            onClick={create} disabled={busy || !target}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-zinc-950 font-bold mono text-xs uppercase tracking-widest disabled:opacity-40"
          >
            <Plus className="w-3 h-3" /> Create monitor
          </button>
          {err && <span className="text-red-400 text-xs mono">{err}</span>}
        </div>
      </section>

      <section className="bg-zinc-900/50 border border-zinc-800 divide-y divide-zinc-800">
        {items.length === 0 ? (
          <div className="p-8 text-center text-zinc-500 mono text-sm">No monitors yet.</div>
        ) : items.map((m) => (
          <div key={m.id} data-testid={`monitor-row-${m.id}`} className="p-3 flex items-center gap-3 mono text-xs">
            {m.active && <RippleDot color="cyan" size="sm" />}
            <div className="flex-1 min-w-0">
              <div className="text-zinc-100 truncate">{m.target}</div>
              <div className="text-[10px] text-zinc-500 mt-1">
                every {m.interval_hours}h · {m.runs_count} run{m.runs_count === 1 ? '' : 's'} ·
                last: {m.last_run_at || 'never'}
                {m.channels?.length ? ` · ${m.channels.join(', ')}` : ''}
              </div>
            </div>
            <StatusPill status={m.active ? 'running' : 'cancelled'} />
            <button data-testid={`monitor-toggle-${m.id}`}
              onClick={async () => { await api.toggleVulnMonitor(m.id); load(); }}
              className="p-1.5 text-cyan-400 hover:bg-cyan-500/10 border border-cyan-500/30">
              {m.active ? <PowerOff className="w-3 h-3" /> : <Power className="w-3 h-3" />}
            </button>
            <button data-testid={`monitor-delete-${m.id}`}
              onClick={async () => { if (!window.confirm('Delete?')) return; await api.deleteVulnMonitor(m.id); load(); }}
              className="p-1.5 text-red-400 hover:bg-red-500/10 border border-red-500/30">
              <Trash2 className="w-3 h-3" />
            </button>
          </div>
        ))}
      </section>
    </div>
  );
}
