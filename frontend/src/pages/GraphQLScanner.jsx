import React, { useState } from 'react';
import api from '@/lib/api';
import { Waypoints, Play, ShieldAlert, CheckCircle2 } from 'lucide-react';
import { LoadingBar, StatusPill } from '@/components/Loaders';

export default function GraphQLScanner() {
  const [url, setUrl] = useState('https://countries.trevorblades.com/');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [err, setErr] = useState('');

  const doProbe = async () => {
    setBusy(true); setErr(''); setResult(null);
    try {
      const { data } = await api.graphqlProbe(url);
      setResult(data);
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message);
    }
    setBusy(false);
  };

  return (
    <div data-testid="graphql-page" className="max-w-5xl mx-auto space-y-6 animate-fade-in-up">
      <header className="relative border border-purple-500/40 bg-gradient-to-r from-purple-950/40 via-zinc-950 to-zinc-950 p-6 overflow-hidden">
        <div className="absolute -top-16 -right-16 w-64 h-64 bg-purple-500/10 blur-3xl rounded-full pointer-events-none" />
        <div className="relative">
          <div className="flex items-center gap-2 mb-2">
            <Waypoints className="w-6 h-6 text-purple-400 animate-glow-pulse" />
            <span className="text-[10px] mono uppercase tracking-widest text-purple-400 border border-purple-500/50 bg-purple-500/10 px-2 py-0.5">
              GraphQL · Nightmare
            </span>
          </div>
          <h1 className="text-2xl md:text-3xl font-display font-bold text-zinc-50">GraphQL Attack Suite</h1>
          <p className="text-zinc-400 text-sm mt-2">
            Introspection · batching (rate-limit bypass) · depth-limit DoS · schema mining.
          </p>
        </div>
      </header>

      <section className="bg-zinc-900/50 border border-zinc-800 p-4">
        <label className="block text-[10px] mono uppercase tracking-widest text-zinc-500 mb-2">GraphQL endpoint URL</label>
        <input
          data-testid="gql-url-input"
          value={url}
          onChange={(e) => setUrl(e.target.value.trim())}
          spellCheck={false}
          className="w-full bg-zinc-950 border border-zinc-800 text-zinc-100 mono text-xs p-3 focus:border-purple-500/50 focus:outline-none"
          placeholder="https://target.com/graphql"
        />
        <div className="flex gap-2 mt-3">
          <button
            data-testid="gql-probe-btn"
            onClick={doProbe} disabled={busy || !url}
            className="flex items-center gap-2 px-4 py-2 bg-purple-500 hover:bg-purple-400 text-white font-bold mono text-xs uppercase tracking-widest disabled:opacity-40"
          >
            <Play className="w-3 h-3" /> Probe
          </button>
          {err && <span className="text-red-400 text-xs mono self-center">{err}</span>}
        </div>
        {busy && <div className="mt-3"><LoadingBar color="cyan" label="Probing endpoint..." /></div>}
      </section>

      {result && (
        <section data-testid="gql-result" className="space-y-3 animate-fade-in-up">
          <div className="bg-zinc-900/50 border border-zinc-800 p-4">
            <h3 className="text-xs font-semibold text-purple-400 mono uppercase tracking-widest mb-2">Discovery</h3>
            <div className="text-xs mono">
              <div className="text-zinc-400">Endpoints tested: <span className="text-zinc-100">{result.endpoints?.length || 0}</span></div>
              {result.endpoints?.map((e, i) => (
                <div key={i} className="text-zinc-500 mt-1 flex items-center gap-2">
                  <span className="w-1 h-1 bg-purple-400 rounded-full" />
                  <span className="text-zinc-200">{e}</span>
                </div>
              ))}
            </div>
          </div>
          {result.findings?.map((f, i) => (
            <FindingCard key={i} f={f} />
          ))}
          {(!result.findings || result.findings.length === 0) && result.endpoints?.length > 0 && (
            <div className="bg-emerald-950/20 border border-emerald-500/30 p-4 mono text-xs text-emerald-300 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4" /> No exposed introspection · batching · or depth DoS surfaces on the tested endpoint(s).
            </div>
          )}
        </section>
      )}
    </div>
  );
}

function FindingCard({ f }) {
  const sevColor = {
    critical: 'red', high: 'red', medium: 'amber', low: 'cyan', info: 'zinc',
  }[f.severity] || 'zinc';
  const cls = {
    red:    'border-red-500/40 bg-red-950/20 text-red-300',
    amber:  'border-amber-500/40 bg-amber-950/20 text-amber-300',
    cyan:   'border-cyan-500/40 bg-cyan-950/20 text-cyan-300',
    zinc:   'border-zinc-800 bg-zinc-900/50 text-zinc-400',
  }[sevColor];
  return (
    <div className={`border ${cls} p-4`}>
      <div className="flex items-center gap-2 mb-2">
        <ShieldAlert className="w-4 h-4" />
        <h4 className="text-sm mono uppercase tracking-widest font-semibold">
          {f.subtype?.replace(/_/g, ' ')}
        </h4>
        <StatusPill status="completed" className="ml-auto" />
      </div>
      <div className="text-xs mono text-zinc-300">{f.evidence}</div>
      <div className="text-[10px] mono text-zinc-500 mt-2">
        {f.url} · severity: {f.severity} · CVSS: {f.cvss} · confidence: {f.confidence}%
      </div>
    </div>
  );
}
