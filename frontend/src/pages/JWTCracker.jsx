import React, { useState } from 'react';
import api from '@/lib/api';
import { KeyRound, Skull, Play, ShieldAlert, CheckCircle2, XCircle } from 'lucide-react';
import { LoadingBar, MatrixLoader, StatusPill } from '@/components/Loaders';

const DEMO_HS = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

export default function JWTCracker() {
  const [token, setToken] = useState(DEMO_HS);
  const [inspect, setInspect] = useState(null);
  const [crack, setCrack] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  const doInspect = async () => {
    setBusy(true); setErr('');
    try {
      const { data } = await api.jwtInspect(token);
      setInspect(data.result);
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message);
    }
    setBusy(false);
  };

  const doCrack = async () => {
    setBusy(true); setErr(''); setCrack(null);
    try {
      const { data } = await api.jwtCrack(token, 150000);
      setCrack(data);
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message);
    }
    setBusy(false);
  };

  return (
    <div data-testid="jwt-cracker-page" className="max-w-5xl mx-auto space-y-6 animate-fade-in-up">
      <header className="relative border border-amber-500/40 bg-gradient-to-r from-amber-950/40 via-zinc-950 to-zinc-950 p-6 overflow-hidden">
        <div className="absolute -top-16 -right-16 w-64 h-64 bg-amber-500/10 blur-3xl rounded-full pointer-events-none" />
        <div className="relative">
          <div className="flex items-center gap-2 mb-2">
            <KeyRound className="w-6 h-6 text-amber-400 animate-glow-pulse" />
            <span className="text-[10px] mono uppercase tracking-widest text-amber-400 border border-amber-500/50 bg-amber-500/10 px-2 py-0.5">
              JWT · Auth Bypass Engine
            </span>
          </div>
          <h1 className="text-2xl md:text-3xl font-display font-bold text-zinc-50">Weaponized JWT Cracker</h1>
          <p className="text-zinc-400 text-sm mt-2">
            Decode · <span className="text-amber-400">alg=none</span> forgery · <span className="text-amber-400">HS256</span> brute-force against 104K weak secrets.
          </p>
        </div>
      </header>

      <section className="bg-zinc-900/50 border border-zinc-800 p-4">
        <label className="block text-[10px] mono uppercase tracking-widest text-zinc-500 mb-2">JWT Token</label>
        <textarea
          data-testid="jwt-token-input"
          value={token}
          onChange={(e) => setToken(e.target.value.trim())}
          rows={5}
          spellCheck={false}
          className="w-full bg-zinc-950 border border-zinc-800 text-zinc-100 mono text-xs p-3 focus:border-amber-500/50 focus:outline-none break-all"
          placeholder="eyJhbGciOi..."
        />
        <div className="flex gap-2 mt-3 flex-wrap">
          <button
            data-testid="jwt-inspect-btn"
            onClick={doInspect} disabled={busy || !token}
            className="flex items-center gap-2 px-4 py-2 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/10 mono text-xs uppercase tracking-widest disabled:opacity-40"
          >
            <Play className="w-3 h-3" /> Inspect
          </button>
          <button
            data-testid="jwt-crack-btn"
            onClick={doCrack} disabled={busy || !token}
            className="flex items-center gap-2 px-4 py-2 bg-amber-500 hover:bg-amber-400 text-zinc-950 font-bold mono text-xs uppercase tracking-widest disabled:opacity-40"
          >
            <Skull className="w-3 h-3" /> Crack (150K secrets)
          </button>
          {err && (
            <span className="text-red-400 text-xs mono self-center">{err}</span>
          )}
        </div>
        {busy && (
          <div className="mt-3">
            <LoadingBar color="amber" label="Working — max 3 seconds..." />
          </div>
        )}
      </section>

      {inspect && (
        <section data-testid="jwt-inspect-result" className="bg-zinc-900/50 border border-cyan-500/30 p-4 animate-fade-in-up">
          <h3 className="text-xs font-semibold text-cyan-400 mono uppercase tracking-widest mb-3">Inspection</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs mono">
            <div>
              <div className="text-zinc-500 uppercase tracking-widest text-[10px] mb-1">Header</div>
              <pre className="bg-zinc-950 border border-zinc-800 p-2 overflow-x-auto text-zinc-100">
                {JSON.stringify(inspect.header, null, 2)}
              </pre>
            </div>
            <div>
              <div className="text-zinc-500 uppercase tracking-widest text-[10px] mb-1">Payload</div>
              <pre className="bg-zinc-950 border border-zinc-800 p-2 overflow-x-auto text-zinc-100">
                {JSON.stringify(inspect.payload, null, 2)}
              </pre>
            </div>
          </div>
          {inspect.warnings?.length > 0 && (
            <div className="mt-4 space-y-1">
              {inspect.warnings.map((w, i) => (
                <div key={i} className="flex items-start gap-2 text-xs mono">
                  <ShieldAlert className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                  <span className="text-amber-300">{w}</span>
                </div>
              ))}
            </div>
          )}
        </section>
      )}

      {crack && (
        <section data-testid="jwt-crack-result" className="space-y-3 animate-fade-in-up">
          {/* alg=none forgery */}
          <AttackCard
            title="Attack #1 · alg=none forgery"
            success={crack.attacks?.alg_none?.success}
            body={crack.attacks?.alg_none?.token ? (
              <>
                <div className="text-[10px] mono uppercase tracking-widest text-zinc-500 mb-1">Forged token (paste in Authorization header):</div>
                <pre className="bg-zinc-950 border border-zinc-800 p-2 text-xs mono text-red-300 break-all whitespace-pre-wrap">
                  {crack.attacks.alg_none.token}
                </pre>
              </>
            ) : <div className="text-xs mono text-zinc-500">Failed: {crack.attacks?.alg_none?.error}</div>}
          />
          {/* HS256 crack */}
          <AttackCard
            title="Attack #2 · HS256 weak-secret crack (104K)"
            success={crack.attacks?.hs_crack?.success}
            body={crack.attacks?.hs_crack?.success ? (
              <div>
                <div className="text-emerald-400 text-sm mono font-bold">
                  🎯 Secret found: <span className="text-yellow-300">{crack.attacks.hs_crack.secret}</span>
                </div>
                <div className="text-[10px] mono text-zinc-500 mt-2">
                  {crack.attacks.hs_crack.alg} · tried {crack.attacks.hs_crack.tried?.toLocaleString()} · {crack.attacks.hs_crack.duration_sec}s
                </div>
              </div>
            ) : (
              <div className="text-xs mono text-zinc-400">
                {crack.attacks?.hs_crack?.reason === 'exhausted'
                  ? `Exhausted ${crack.attacks?.hs_crack?.tried?.toLocaleString()} candidates in ${crack.attacks?.hs_crack?.duration_sec}s — no match.`
                  : `Skipped: ${crack.attacks?.hs_crack?.reason}`}
              </div>
            )}
          />
        </section>
      )}
    </div>
  );
}

function AttackCard({ title, success, body }) {
  return (
    <div className={`border ${success ? 'border-emerald-500/50 bg-emerald-950/20' : 'border-zinc-800 bg-zinc-900/50'} p-4`}>
      <div className="flex items-center gap-2 mb-3">
        {success
          ? <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          : <XCircle className="w-4 h-4 text-zinc-500" />}
        <h4 className="text-sm mono uppercase tracking-widest font-semibold text-zinc-100">{title}</h4>
        <StatusPill status={success ? 'completed' : 'failed'} className="ml-auto" />
      </div>
      {body}
    </div>
  );
}
