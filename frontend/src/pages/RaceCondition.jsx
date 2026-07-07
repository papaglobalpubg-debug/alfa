import React, { useState, useEffect } from 'react';
import api from '@/lib/api';
import { Radio, Play, Zap, StopCircle } from 'lucide-react';
import { LoadingBar, StatusPill } from '@/components/Loaders';

export default function RaceCondition() {
  const [url, setUrl] = useState('');
  const [method, setMethod] = useState('POST');
  const [body, setBody] = useState('{}');
  const [n, setN] = useState(50);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [err, setErr] = useState('');

  const doRace = async () => {
    setBusy(true); setErr(''); setResult(null);
    let parsedBody = null;
    try {
      if (method === 'POST' && body.trim()) parsedBody = JSON.parse(body);
    } catch {
      setErr('Body must be valid JSON');
      setBusy(false); return;
    }
    try {
      const { data } = method === 'POST'
        ? await api.racePost(url, parsedBody, n)
        : await api.raceGet(url, n);
      setResult(data);
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message);
    }
    setBusy(false);
  };

  return (
    <div data-testid="race-page" className="max-w-4xl mx-auto space-y-6 animate-fade-in-up">
      <header className="relative border border-emerald-500/40 bg-gradient-to-r from-emerald-950/40 via-zinc-950 to-zinc-950 p-6 overflow-hidden">
        <div className="absolute -top-16 -right-16 w-64 h-64 bg-emerald-500/10 blur-3xl rounded-full pointer-events-none" />
        <div className="relative">
          <div className="flex items-center gap-2 mb-2">
            <Radio className="w-6 h-6 text-emerald-400 animate-glow-pulse" />
            <span className="text-[10px] mono uppercase tracking-widest text-emerald-400 border border-emerald-500/50 bg-emerald-500/10 px-2 py-0.5">
              Race Condition Exploiter
            </span>
          </div>
          <h1 className="text-2xl md:text-3xl font-display font-bold text-zinc-50">Race Condition Probe</h1>
          <p className="text-zinc-400 text-sm mt-2">
            Fire up to 200 concurrent requests. Detects: double-spend · duplicate-signup ·
            coupon reuse · balance races. Server responses are compared for divergence.
          </p>
        </div>
      </header>

      <section className="bg-zinc-900/50 border border-zinc-800 p-4 space-y-3">
        <input
          data-testid="race-url"
          value={url}
          onChange={(e) => setUrl(e.target.value.trim())}
          className="w-full bg-zinc-950 border border-zinc-800 text-zinc-100 mono text-sm p-3 focus:border-emerald-500/50 focus:outline-none"
          placeholder="https://target.com/api/redeem"
        />
        <div className="flex gap-2 flex-wrap items-center">
          <div className="flex gap-1">
            {['POST', 'GET'].map((m) => (
              <button key={m} onClick={() => setMethod(m)}
                data-testid={`race-method-${m}`}
                className={`px-3 py-1.5 border mono text-xs uppercase ${
                  method === m ? 'border-emerald-500 bg-emerald-500/20 text-emerald-300' : 'border-zinc-800 text-zinc-400'
                }`}>{m}</button>
            ))}
          </div>
          <label className="text-[10px] mono uppercase text-zinc-500">N=</label>
          <input type="number" min={2} max={200} value={n} onChange={(e) => setN(+e.target.value)}
            data-testid="race-n"
            className="w-20 bg-zinc-950 border border-zinc-800 text-zinc-100 mono text-sm p-2 text-center" />
        </div>
        {method === 'POST' && (
          <textarea rows={3} value={body} onChange={(e) => setBody(e.target.value)}
            data-testid="race-body"
            className="w-full bg-zinc-950 border border-zinc-800 text-zinc-100 mono text-xs p-3"
            placeholder='{"coupon":"SAVE50"}' />
        )}
        <div className="flex gap-2 items-center">
          <button
            data-testid="race-fire-btn"
            onClick={doRace} disabled={busy || !url}
            className="flex items-center gap-2 px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-zinc-950 font-bold mono text-xs uppercase tracking-widest disabled:opacity-40"
          >
            <Zap className="w-3 h-3" /> Fire {n} concurrent
          </button>
          {err && <span className="text-red-400 text-xs mono">{err}</span>}
        </div>
        {busy && <LoadingBar color="emerald" label={`Firing ${n} requests...`} />}
      </section>

      {result && (
        <section data-testid="race-result" className="bg-zinc-900/50 border border-zinc-800 p-4 animate-fade-in-up">
          <h3 className="text-xs font-semibold text-emerald-400 mono uppercase tracking-widest mb-3">Result</h3>
          <div className="grid grid-cols-3 gap-3 mb-3">
            <Stat label="Attempts" value={result.attempts} />
            <Stat label="Unique hashes" value={result.unique_hashes} accent={result.unique_hashes > 1 ? 'amber' : 'emerald'} />
            <Stat label="Findings" value={result.findings?.length || 0} accent={result.findings?.length ? 'red' : 'emerald'} />
          </div>
          <div className="text-xs mono">
            <div className="text-zinc-500 uppercase text-[10px] tracking-widest mb-1">Status distribution</div>
            <div className="flex gap-1 flex-wrap">
              {Object.entries(result.status_counts || {}).map(([s, c]) => (
                <span key={s} className={`px-2 py-0.5 border mono text-[10px] ${
                  s === '0' ? 'border-red-500/40 text-red-400' :
                  s.startsWith('2') ? 'border-emerald-500/40 text-emerald-400' :
                  s.startsWith('4') ? 'border-amber-500/40 text-amber-400' :
                  'border-zinc-700 text-zinc-400'
                }`}>{s === '0' ? 'ERR' : s}: {c}</span>
              ))}
            </div>
          </div>
          {result.findings?.length > 0 && (
            <div className="mt-4 space-y-2">
              {result.findings.map((f, i) => (
                <div key={i} className="border border-red-500/40 bg-red-950/30 p-3">
                  <div className="text-xs mono uppercase font-semibold text-red-300">{f.subtype}</div>
                  <div className="text-xs mono text-zinc-300 mt-1">{f.evidence}</div>
                </div>
              ))}
            </div>
          )}
        </section>
      )}
    </div>
  );
}

function Stat({ label, value, accent = 'zinc' }) {
  const cls = {
    red:     'text-red-400 border-red-500/40',
    amber:   'text-amber-400 border-amber-500/40',
    emerald: 'text-emerald-400 border-emerald-500/40',
    zinc:    'text-zinc-300 border-zinc-800',
  }[accent];
  return (
    <div className={`bg-zinc-950 border p-3 ${cls}`}>
      <div className="text-[10px] mono uppercase tracking-widest text-zinc-500">{label}</div>
      <div className="text-xl mono font-bold mt-1">{value}</div>
    </div>
  );
}
