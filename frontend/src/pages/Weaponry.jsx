import React, { useState } from 'react';
import api from '@/lib/api';
import HelpTip from '@/components/HelpTip';
import {
  Swords, Bomb, ShieldAlert, Sparkles, Layers, Radio, KeyRound, Waves,
  ScrollText, Play, CheckCircle2, XCircle, Cloud,
} from 'lucide-react';
import { LoadingBar, StatusPill } from '@/components/Loaders';

/**
 * v7.8 · Weaponry — unified page exposing the 6 new attack modules.
 * Tabs: Smuggling · Cache · Payload-Gen · PP+DOM · SSRF-Deep · MFA-Bypass
 */
const TABS = [
  { id: 'smuggling', label: 'HTTP Smuggling',    icon: Waves },
  { id: 'cache',     label: 'Cache Poisoning',   icon: Layers },
  { id: 'payload',   label: 'AI Payloads',       icon: Sparkles },
  { id: 'pp',        label: 'Prototype Pollution', icon: Bomb },
  { id: 'ssrf',      label: 'SSRF Deep',         icon: Cloud },
  { id: 'mfa',       label: 'MFA Bypass',        icon: KeyRound },
];

export default function Weaponry() {
  const [tab, setTab] = useState('smuggling');
  return (
    <div data-testid="weaponry-page" className="max-w-6xl mx-auto space-y-6 animate-fade-in-up">
      <header className="relative border border-red-500/40 bg-gradient-to-r from-red-950/40 via-zinc-950 to-zinc-950 p-6 overflow-hidden">
        <div className="absolute -top-16 -right-16 w-64 h-64 bg-red-500/10 blur-3xl rounded-full pointer-events-none" />
        <div className="relative">
          <div className="flex items-center gap-2 mb-2">
            <Swords className="w-6 h-6 text-red-400 animate-glow-pulse" />
            <span className="text-[10px] mono uppercase tracking-widest text-red-400 border border-red-500/50 bg-red-500/10 px-2 py-0.5">
              Weaponry v7.8 · Attack Wave
            </span>
          </div>
          <h1 className="text-2xl md:text-3xl font-display font-bold text-zinc-50">Advanced Attack Arsenal</h1>
          <p className="text-zinc-400 text-sm mt-2">
            HTTP Smuggling · Cache Poisoning · WAF-aware AI Payloads · Prototype Pollution · SSRF Deep · MFA Bypass.
          </p>
        </div>
      </header>

      <nav className="flex gap-1 flex-wrap border-b border-zinc-800 -mb-1">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button key={id}
            data-testid={`weaponry-tab-${id}`}
            onClick={() => setTab(id)}
            className={`flex items-center gap-2 px-3 py-2 border-b-2 mono text-xs uppercase tracking-widest transition-colors ${
              tab === id
                ? 'border-red-500 text-red-300 bg-red-500/10'
                : 'border-transparent text-zinc-400 hover:text-zinc-200'
            }`}>
            <Icon className="w-3.5 h-3.5" /> {label}
          </button>
        ))}
      </nav>

      {tab === 'smuggling' && <UrlListPanel testid="smug" api={api.smugglingV2} accent="red"
        title="HTTP Request Smuggling v2" desc="CL.TE / TE.CL / TE.TE / HTTP2 downgrade detection matrix." />}
      {tab === 'cache' && <UrlListPanel testid="cache" api={api.cacheV2} accent="amber"
        title="Web Cache Poisoning + Deception" desc="Path-confusion caching + unkeyed-header poisoning." />}
      {tab === 'payload' && <PayloadGenPanel />}
      {tab === 'pp' && <UrlListPanel testid="pp" api={api.prototypePollution} accent="purple"
        title="Prototype Pollution + DOM Clobbering" desc="Reflected __proto__ / constructor / id-clobber tests." />}
      {tab === 'ssrf' && <SSRFDeepPanel />}
      {tab === 'mfa' && <MFAPanel />}
    </div>
  );
}

// ─────────────── Reusable URL-list panel ───────────────
function UrlListPanel({ testid, api: apiFn, accent, title, desc }) {
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [err, setErr] = useState('');

  const fire = async () => {
    setBusy(true); setErr(''); setResult(null);
    const urls = text.split('\n').map(s => s.trim()).filter(Boolean);
    if (!urls.length) { setErr('Add at least one URL'); setBusy(false); return; }
    try {
      const { data } = await apiFn(urls);
      setResult(data);
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message);
    }
    setBusy(false);
  };
  return (
    <section className="bg-zinc-900/50 border border-zinc-800 p-4 space-y-3">
      <div>
        <h3 className={`text-sm font-semibold text-${accent}-400 mono uppercase tracking-widest`}>{title}</h3>
        <p className="text-[11px] mono text-zinc-500 mt-1">{desc}</p>
      </div>
      <textarea rows={5} value={text} onChange={(e) => setText(e.target.value)}
        data-testid={`${testid}-urls`}
        className="w-full bg-zinc-950 border border-zinc-800 text-zinc-100 mono text-xs p-3"
        placeholder={'https://target.com/endpoint\nhttps://target.com/api'} />
      <div className="flex items-center gap-2">
        <button data-testid={`${testid}-fire`} onClick={fire} disabled={busy}
          className={`flex items-center gap-2 px-4 py-2 bg-${accent}-500 hover:bg-${accent}-400 text-zinc-950 font-bold mono text-xs uppercase tracking-widest disabled:opacity-40`}>
          <Play className="w-3 h-3" /> Fire
        </button>
        {err && <span className="text-red-400 text-xs mono">{err}</span>}
      </div>
      {busy && <LoadingBar color={accent} label="Probing..." />}
      {result && <FindingsList result={result} />}
    </section>
  );
}

// ─────────────── AI Payload Generator ───────────────
function PayloadGenPanel() {
  const [category, setCategory] = useState('xss');
  const [waf, setWaf] = useState('Cloudflare');
  const [count, setCount] = useState(30);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const CATS = ['xss','sqli','cmd','lfi','ssrf','ssti','nosqli','xxe'];
  const WAFS = ['None','Cloudflare','Akamai','Imperva','AWS WAF','F5 BIG-IP','ModSecurity (OWASP CRS)'];
  const fire = async () => {
    setBusy(true); setResult(null);
    try {
      const { data } = await api.aiPayloadGen({ category, waf, count });
      setResult(data);
    } catch { /* ignore */ }
    setBusy(false);
  };
  return (
    <section className="bg-zinc-900/50 border border-zinc-800 p-4 space-y-3">
      <div>
        <h3 className="text-sm font-semibold text-cyan-400 mono uppercase tracking-widest">AI Payload Generator</h3>
        <p className="text-[11px] mono text-zinc-500 mt-1">WAF-aware payloads synthesised by Claude — tuned for the exact WAF you select.</p>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
        <select value={category} onChange={(e) => setCategory(e.target.value)}
          data-testid="pg-category"
          className="bg-zinc-950 border border-zinc-800 text-zinc-100 mono text-xs p-2">
          {CATS.map((c) => <option key={c} value={c}>{c.toUpperCase()}</option>)}
        </select>
        <select value={waf} onChange={(e) => setWaf(e.target.value)}
          data-testid="pg-waf"
          className="bg-zinc-950 border border-zinc-800 text-zinc-100 mono text-xs p-2">
          {WAFS.map((w) => <option key={w} value={w}>{w}</option>)}
        </select>
        <input type="number" min={5} max={60} value={count} onChange={(e) => setCount(+e.target.value)}
          data-testid="pg-count"
          className="bg-zinc-950 border border-zinc-800 text-zinc-100 mono text-xs p-2 text-center" />
      </div>
      <button onClick={fire} disabled={busy}
        data-testid="pg-fire"
        className="flex items-center gap-2 px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-zinc-950 font-bold mono text-xs uppercase tracking-widest disabled:opacity-40">
        <Sparkles className="w-3 h-3" /> Generate
      </button>
      {busy && <LoadingBar color="cyan" label="Claude thinking..." />}
      {result && (
        <div className="mt-3 space-y-2">
          <div className="text-[10px] mono text-zinc-500 uppercase tracking-widest">
            {result.count} payloads · {result.reason}
          </div>
          <pre data-testid="pg-result" className="bg-zinc-950 border border-zinc-800 p-3 max-h-96 overflow-y-auto text-xs mono text-zinc-100 whitespace-pre-wrap">
            {(result.payloads || []).map((p, i) => `${i+1}. ${p}`).join('\n')}
          </pre>
        </div>
      )}
    </section>
  );
}

// ─────────────── SSRF Deep ───────────────
function SSRFDeepPanel() {
  const [tpl, setTpl] = useState('https://vuln.tld/fetch?url={PAYLOAD}');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [err, setErr] = useState('');
  const fire = async () => {
    if (!tpl.includes('{PAYLOAD}')) { setErr('URL must contain {PAYLOAD} placeholder'); return; }
    setBusy(true); setErr(''); setResult(null);
    try {
      const { data } = await api.ssrfDeep(tpl);
      setResult(data);
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message);
    }
    setBusy(false);
  };
  return (
    <section className="bg-zinc-900/50 border border-zinc-800 p-4 space-y-3">
      <div>
        <h3 className="text-sm font-semibold text-orange-400 mono uppercase tracking-widest">SSRF Deep Exploitation</h3>
        <p className="text-[11px] mono text-zinc-500 mt-1">Pivots an SSRF surface into cloud-metadata (AWS/GCP/Azure/DO/Alibaba) + Redis/Consul/etcd/K8s.</p>
      </div>
      <input value={tpl} onChange={(e) => setTpl(e.target.value)}
        data-testid="ssrf-tpl"
        className="w-full bg-zinc-950 border border-zinc-800 text-zinc-100 mono text-sm p-3"
        placeholder="https://vuln.tld/fetch?url={PAYLOAD}" />
      <div className="flex items-center gap-2">
        <button onClick={fire} disabled={busy}
          data-testid="ssrf-fire"
          className="flex items-center gap-2 px-4 py-2 bg-orange-500 hover:bg-orange-400 text-zinc-950 font-bold mono text-xs uppercase tracking-widest disabled:opacity-40">
          <Play className="w-3 h-3" /> Exploit
        </button>
        {err && <span className="text-red-400 text-xs mono">{err}</span>}
      </div>
      {busy && <LoadingBar color="amber" label="Probing internal endpoints..." />}
      {result && (
        <div>
          <div className="text-[10px] mono text-zinc-500 uppercase tracking-widest mb-2">
            Matches: {result.matches?.length || 0} / {result.total_tried || 0} endpoints tried
          </div>
          <FindingsList result={{ findings: result.matches || [] }} />
        </div>
      )}
    </section>
  );
}

// ─────────────── MFA Bypass ───────────────
function MFAPanel() {
  const [url, setUrl] = useState('');
  const [field, setField] = useState('code');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const fire = async () => {
    setBusy(true); setResult(null);
    try {
      const { data } = await api.mfaBypass({ url, form_field: field });
      setResult(data);
    } catch { /* ignore */ }
    setBusy(false);
  };
  return (
    <section className="bg-zinc-900/50 border border-zinc-800 p-4 space-y-3">
      <div>
        <h3 className="text-sm font-semibold text-emerald-400 mono uppercase tracking-widest">2FA / MFA Bypass Tester</h3>
        <p className="text-[11px] mono text-zinc-500 mt-1">Rate-limit + race-condition probes on the OTP endpoint.</p>
      </div>
      <input value={url} onChange={(e) => setUrl(e.target.value.trim())}
        data-testid="mfa-url"
        className="w-full bg-zinc-950 border border-zinc-800 text-zinc-100 mono text-sm p-3"
        placeholder="https://target.com/api/2fa/verify" />
      <div className="flex items-center gap-2">
        <input value={field} onChange={(e) => setField(e.target.value)}
          data-testid="mfa-field"
          className="w-40 bg-zinc-950 border border-zinc-800 text-zinc-100 mono text-xs p-2"
          placeholder="form field name" />
        <button onClick={fire} disabled={busy || !url}
          data-testid="mfa-fire"
          className="flex items-center gap-2 px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-zinc-950 font-bold mono text-xs uppercase tracking-widest disabled:opacity-40">
          <ShieldAlert className="w-3 h-3" /> Test
        </button>
      </div>
      {busy && <LoadingBar color="emerald" label="Firing OTP probes..." />}
      {result && <FindingsList result={result} />}
    </section>
  );
}

// ─────────────── Findings renderer ───────────────
function FindingsList({ result }) {
  const findings = result?.findings || [];
  if (findings.length === 0) {
    return (
      <div className="bg-emerald-950/20 border border-emerald-500/30 p-4 mono text-xs text-emerald-300 flex items-center gap-2 mt-3">
        <CheckCircle2 className="w-4 h-4" /> No findings on the tested targets.
      </div>
    );
  }
  return (
    <div className="mt-3 space-y-2" data-testid="findings-list">
      {findings.map((f, i) => (
        <div key={i} className={`border p-3 ${
          f.severity === 'critical' ? 'border-red-500/60 bg-red-950/30' :
          f.severity === 'high' ? 'border-red-500/40 bg-red-950/20' :
          f.severity === 'medium' ? 'border-amber-500/40 bg-amber-950/20' :
          'border-zinc-800 bg-zinc-900/40'
        }`}>
          <div className="flex items-center gap-2">
            <ShieldAlert className={`w-4 h-4 ${
              f.severity === 'critical' || f.severity === 'high' ? 'text-red-400' :
              f.severity === 'medium' ? 'text-amber-400' : 'text-zinc-400'
            }`} />
            <h4 className="text-sm mono uppercase tracking-widest font-semibold text-zinc-100">
              {f.subtype || f.type}
            </h4>
            <StatusPill status="completed" className="ml-auto" />
          </div>
          <div className="text-xs mono text-zinc-300 mt-2">{f.evidence}</div>
          <div className="text-[10px] mono text-zinc-500 mt-2">
            {f.url} · severity: {f.severity} · CVSS: {f.cvss} · confidence: {f.confidence}%
          </div>
        </div>
      ))}
    </div>
  );
}
