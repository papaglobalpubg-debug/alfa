import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '@/lib/api';
import { Bot, Rocket, ShieldAlert, Brain } from 'lucide-react';
import { LoadingBar, RadarSweep } from '@/components/Loaders';

export default function AutoPilot() {
  const [target, setTarget] = useState('');
  const [depth, setDepth] = useState('medium');
  const [busy, setBusy] = useState(false);
  const [plan, setPlan] = useState(null);
  const [err, setErr] = useState('');
  const navigate = useNavigate();

  const launch = async () => {
    if (!target) { setErr('Target required'); return; }
    setBusy(true); setErr(''); setPlan(null);
    try {
      const { data } = await api.autopilot(target, depth);
      setPlan(data);
      setTimeout(() => navigate(`/vuln/scan/${data.scan_id}`), 1400);
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message);
    }
    setBusy(false);
  };

  return (
    <div data-testid="autopilot-page" className="max-w-4xl mx-auto space-y-6 animate-fade-in-up">
      <header className="relative border border-cyan-500/40 bg-gradient-to-r from-cyan-950/40 via-zinc-950 to-zinc-950 p-6 overflow-hidden">
        <div className="absolute -top-16 -right-16 w-72 h-72 bg-cyan-500/10 blur-3xl rounded-full pointer-events-none" />
        <div className="relative flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Bot className="w-6 h-6 text-cyan-400 animate-glow-pulse" />
              <span className="text-[10px] mono uppercase tracking-widest text-cyan-400 border border-cyan-500/50 bg-cyan-500/10 px-2 py-0.5">
                AI · Autonomous Pentester
              </span>
            </div>
            <h1 className="text-2xl md:text-3xl font-display font-bold text-zinc-50">AI Autopilot</h1>
            <p className="text-zinc-400 text-sm mt-2 max-w-xl">
              Give a target · Claude plans the attack surface and picks the optimal
              modules · orchestrator runs them · verifier drops false positives.
              You just watch.
            </p>
          </div>
          {busy && <RadarSweep size={60} color="cyan" />}
        </div>
      </header>

      <section className="bg-zinc-900/50 border border-zinc-800 p-4 space-y-3">
        <div>
          <label className="block text-[10px] mono uppercase tracking-widest text-zinc-500 mb-1">Target URL</label>
          <input
            data-testid="autopilot-target"
            value={target}
            onChange={(e) => setTarget(e.target.value.trim())}
            spellCheck={false}
            className="w-full bg-zinc-950 border border-zinc-800 text-zinc-100 mono text-sm p-3 focus:border-cyan-500/50 focus:outline-none"
            placeholder="https://target.example.com"
          />
        </div>
        <div>
          <label className="block text-[10px] mono uppercase tracking-widest text-zinc-500 mb-1">Depth</label>
          <div className="flex gap-2 flex-wrap">
            {['quick', 'medium', 'deep', 'insane'].map((d) => (
              <button
                key={d}
                data-testid={`depth-${d}`}
                onClick={() => setDepth(d)}
                className={`px-3 py-1.5 border mono text-xs uppercase tracking-widest ${
                  depth === d
                    ? 'border-cyan-500 bg-cyan-500/20 text-cyan-300'
                    : 'border-zinc-800 text-zinc-400 hover:border-zinc-700'
                }`}
              >
                {d}
              </button>
            ))}
          </div>
        </div>
        <div className="flex gap-2 flex-wrap items-center">
          <button
            data-testid="autopilot-launch-btn"
            onClick={launch} disabled={busy || !target}
            className="flex items-center gap-2 px-6 py-3 bg-cyan-500 hover:bg-cyan-400 text-zinc-950 font-bold mono text-sm uppercase tracking-widest disabled:opacity-40"
          >
            <Rocket className="w-4 h-4" /> Engage Autopilot
          </button>
          {err && <span className="text-red-400 text-xs mono">{err}</span>}
        </div>
        {busy && <LoadingBar color="cyan" label="AI planning attack surface..." />}
      </section>

      {plan && (
        <section data-testid="autopilot-plan" className="bg-cyan-950/30 border border-cyan-500/40 p-4 space-y-3 animate-fade-in-up">
          <div className="flex items-center gap-2">
            <Brain className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm mono uppercase tracking-widest font-semibold text-cyan-300">AI Plan</h3>
          </div>
          <div className="text-xs mono">
            <div className="text-zinc-500 uppercase text-[10px] tracking-widest mb-1">Chosen modules ({plan.plan?.modules?.length || 0})</div>
            <div className="flex flex-wrap gap-1">
              {(plan.plan?.modules || []).map((m) => (
                <span key={m} className="px-2 py-0.5 border border-cyan-500/40 text-cyan-300 uppercase text-[10px] tracking-widest">
                  {m}
                </span>
              ))}
            </div>
          </div>
          <div className="text-xs mono">
            <div className="text-zinc-500 uppercase text-[10px] tracking-widest mb-1">Reason</div>
            <div className="text-zinc-300">{plan.plan?.reason}</div>
          </div>
          <div className="text-[10px] mono text-cyan-400 flex items-center gap-2">
            <ShieldAlert className="w-3 h-3" /> Redirecting to scan detail...
          </div>
        </section>
      )}
    </div>
  );
}
