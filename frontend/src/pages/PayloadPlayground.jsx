import React, { useEffect, useState } from 'react';
import { Zap, RefreshCw, Sparkles, GitCompare, Download, Copy, Check } from 'lucide-react';
import api from '@/lib/api';

const WAFS = ['', 'cloudflare', 'akamai', 'awswaf', 'imperva', 'modsecurity', 'sucuri', 'f5', 'barracuda'];

export default function PayloadPlayground() {
  const [tab, setTab] = useState('mutate');   // mutate | craft | diff | wordlists
  const [payload, setPayload] = useState('<script>alert(1)</script>');
  const [waf, setWaf] = useState('cloudflare');
  const [mutations, setMutations] = useState([]);
  const [wafBypasses, setWafBypasses] = useState([]);
  const [craftResult, setCraftResult] = useState(null);
  const [craftType, setCraftType] = useState('xss');
  const [craftTech, setCraftTech] = useState('');
  const [craftOrig, setCraftOrig] = useState('<script>alert(1)</script>');
  const [diffA, setDiffA] = useState('');
  const [diffB, setDiffB] = useState('');
  const [diffResult, setDiffResult] = useState(null);
  const [wlStats, setWlStats] = useState(null);
  const [loading, setLoading] = useState(false);
  const [copiedIdx, setCopiedIdx] = useState(null);

  useEffect(() => {
    if (tab === 'wordlists') {
      api.wordlistsStats().then(r => setWlStats(r.data)).catch(() => setWlStats(null));
    }
  }, [tab]);

  const runMutate = async () => {
    setLoading(true);
    try {
      const r = await api.mutatePayload(payload, waf || null);
      setMutations(r.data.mutations || []);
      setWafBypasses(r.data.waf_bypasses || []);
    } catch (e) { /* silent */ }
    setLoading(false);
  };

  const runCraft = async () => {
    setLoading(true);
    try {
      const r = await api.aiCraftPayload({
        vulnerability_type: craftType, waf, tech: craftTech,
        original_payload: craftOrig,
      });
      setCraftResult(r.data);
    } catch (e) { setCraftResult({ error: e.message }); }
    setLoading(false);
  };

  const runDiff = async () => {
    setLoading(true);
    try {
      const r = await api.semanticDiff(diffA, diffB);
      setDiffResult(r.data);
    } catch (e) { setDiffResult({ error: e.message }); }
    setLoading(false);
  };

  const syncWordlists = async () => {
    setLoading(true);
    try {
      const r = await api.wordlistsSync(false);
      setWlStats({ counts: r.data.counts });
    } catch (e) { /* silent */ }
    setLoading(false);
  };

  const copyOne = (text, idx) => {
    navigator.clipboard?.writeText(text).then(() => {
      setCopiedIdx(idx);
      setTimeout(() => setCopiedIdx(null), 1200);
    });
  };

  const TABS = [
    { id: 'mutate', label: 'Mutations & WAF Bypass', icon: Zap },
    { id: 'craft', label: 'AI Payload Crafter', icon: Sparkles },
    { id: 'diff', label: 'Semantic Diff', icon: GitCompare },
    { id: 'wordlists', label: 'Wordlist Encyclopedia', icon: Download },
  ];

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-zinc-50 tracking-tight flex items-center gap-2">
          <Zap className="w-5 h-5 text-red-500" /> Payload Playground
        </h1>
        <p className="text-xs mono text-zinc-500 mt-1">
          v7.7 · جرّب الـ mutations، ولّد payloads بالذكاء الاصطناعي، وقارن الردود بدقة
        </p>
      </div>

      <div className="mb-4 flex gap-1 flex-wrap border-b border-zinc-800">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            data-testid={`pp-tab-${id}`}
            onClick={() => setTab(id)}
            className={`flex items-center gap-2 px-4 py-2 mono text-xs uppercase tracking-widest transition-colors border-b-2 ${
              tab === id
                ? 'border-red-500 text-red-400'
                : 'border-transparent text-zinc-500 hover:text-zinc-200'
            }`}
          >
            <Icon className="w-3 h-3" /> {label}
          </button>
        ))}
      </div>

      {/* MUTATE TAB */}
      {tab === 'mutate' && (
        <div className="space-y-4">
          <div className="grid md:grid-cols-3 gap-3">
            <div className="md:col-span-2">
              <label className="text-[10px] mono uppercase text-zinc-500">Base payload</label>
              <textarea
                data-testid="pp-payload-input"
                value={payload}
                onChange={(e) => setPayload(e.target.value)}
                className="w-full h-24 mt-1 p-2 bg-zinc-950 border border-zinc-800 mono text-xs text-zinc-100"
              />
            </div>
            <div>
              <label className="text-[10px] mono uppercase text-zinc-500">Target WAF</label>
              <select
                data-testid="pp-waf-select"
                value={waf}
                onChange={(e) => setWaf(e.target.value)}
                className="w-full mt-1 p-2 bg-zinc-950 border border-zinc-800 mono text-xs text-zinc-100"
              >
                {WAFS.map(w => <option key={w || 'none'} value={w}>{w || '— (any) —'}</option>)}
              </select>
              <button
                data-testid="pp-mutate-btn"
                onClick={runMutate}
                disabled={loading}
                className="w-full mt-3 px-4 py-2 bg-red-500 hover:bg-red-600 text-white font-bold mono text-xs uppercase tracking-widest disabled:opacity-40"
              >
                {loading ? <RefreshCw className="w-3 h-3 animate-spin inline" /> : 'Generate'}
              </button>
            </div>
          </div>
          {(mutations.length > 0 || wafBypasses.length > 0) && (
            <div className="grid md:grid-cols-2 gap-3">
              <VariantList title="Encoding Variants" items={mutations.map((m, i) => ({ ...m, key: i }))}
                copyOne={copyOne} copiedIdx={copiedIdx} prefix="mut" />
              <VariantList title={`${waf || 'Multi-WAF'} Bypasses`}
                items={wafBypasses.map((v, i) => ({ value: v, mutation: waf || 'multi', key: `w${i}` }))}
                copyOne={copyOne} copiedIdx={copiedIdx} prefix="waf" />
            </div>
          )}
        </div>
      )}

      {/* AI CRAFT TAB */}
      {tab === 'craft' && (
        <div className="space-y-4">
          <div className="grid md:grid-cols-4 gap-3">
            <div>
              <label className="text-[10px] mono uppercase text-zinc-500">Type</label>
              <select value={craftType} onChange={e => setCraftType(e.target.value)}
                className="w-full mt-1 p-2 bg-zinc-950 border border-zinc-800 mono text-xs text-zinc-100">
                {['xss','sqli','ssti','cmd','lfi','ssrf','xxe','open_redirect','nosqli','crlf'].map(t =>
                  <option key={t}>{t}</option>)}
              </select>
            </div>
            <div>
              <label className="text-[10px] mono uppercase text-zinc-500">WAF</label>
              <select value={waf} onChange={e => setWaf(e.target.value)}
                className="w-full mt-1 p-2 bg-zinc-950 border border-zinc-800 mono text-xs text-zinc-100">
                {WAFS.map(w => <option key={w || 'none'} value={w}>{w || 'any'}</option>)}
              </select>
            </div>
            <div>
              <label className="text-[10px] mono uppercase text-zinc-500">Tech hint</label>
              <input value={craftTech} onChange={e => setCraftTech(e.target.value)}
                placeholder="php / node / django"
                className="w-full mt-1 p-2 bg-zinc-950 border border-zinc-800 mono text-xs text-zinc-100" />
            </div>
            <div>
              <button data-testid="pp-craft-btn" onClick={runCraft} disabled={loading}
                className="w-full mt-5 px-4 py-2 bg-fuchsia-500 hover:bg-fuchsia-600 text-white font-bold mono text-xs uppercase tracking-widest disabled:opacity-40">
                <Sparkles className="w-3 h-3 inline mr-1" /> Craft
              </button>
            </div>
          </div>
          <textarea value={craftOrig} onChange={e => setCraftOrig(e.target.value)}
            placeholder="Original payload that got blocked..."
            className="w-full h-20 p-2 bg-zinc-950 border border-zinc-800 mono text-xs text-zinc-100" />
          {craftResult && (
            <div className="border border-fuchsia-500/30 bg-fuchsia-500/5 p-3">
              <div className="text-[10px] mono uppercase text-fuchsia-300 mb-2">
                source: {craftResult.source || 'unknown'} · {craftResult.payloads?.length || 0} payloads
              </div>
              {(craftResult.payloads || []).map((p, i) => (
                <div key={i} className="p-2 border-b border-zinc-800/50 last:border-0">
                  <div className="flex justify-between items-center">
                    <code className="text-xs text-zinc-100 break-all flex-1">{p.value}</code>
                    <button onClick={() => copyOne(p.value, `c${i}`)}
                      className="ml-2 p-1 text-zinc-500 hover:text-emerald-400">
                      {copiedIdx === `c${i}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </div>
                  <div className="text-[10px] mono text-zinc-500 mt-1">
                    {p.encoding && <span className="mr-2">enc:{p.encoding}</span>}{p.why}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* SEMANTIC DIFF TAB */}
      {tab === 'diff' && (
        <div className="space-y-3">
          <div className="grid md:grid-cols-2 gap-3">
            <textarea data-testid="pp-diff-a" value={diffA} onChange={e => setDiffA(e.target.value)}
              placeholder="Response A (baseline)..."
              className="h-40 p-2 bg-zinc-950 border border-zinc-800 mono text-xs text-zinc-100" />
            <textarea data-testid="pp-diff-b" value={diffB} onChange={e => setDiffB(e.target.value)}
              placeholder="Response B (with payload)..."
              className="h-40 p-2 bg-zinc-950 border border-zinc-800 mono text-xs text-zinc-100" />
          </div>
          <button data-testid="pp-diff-btn" onClick={runDiff} disabled={loading}
            className="px-4 py-2 bg-red-500 hover:bg-red-600 text-white font-bold mono text-xs uppercase tracking-widest disabled:opacity-40">
            Compare (semantic)
          </button>
          {diffResult && (
            <div className="border border-zinc-800 bg-zinc-950 p-3 mono text-xs text-zinc-300">
              <pre>{JSON.stringify(diffResult, null, 2)}</pre>
            </div>
          )}
        </div>
      )}

      {/* WORDLISTS TAB */}
      {tab === 'wordlists' && (
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <button data-testid="pp-sync-btn" onClick={syncWordlists} disabled={loading}
              className="px-4 py-2 bg-red-500 hover:bg-red-600 text-white font-bold mono text-xs uppercase tracking-widest disabled:opacity-40">
              {loading ? <RefreshCw className="w-3 h-3 animate-spin inline" /> : 'Sync from GitHub'}
            </button>
            <p className="text-xs mono text-zinc-500">
              يحمّل ~48K payload من SecLists / PayloadsAllTheThings / payloadbox
            </p>
          </div>
          {wlStats?.counts && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
              {Object.entries(wlStats.counts).map(([cat, n]) => (
                <div key={cat} className="border border-zinc-800 bg-zinc-950 p-3">
                  <div className="text-[10px] mono uppercase text-zinc-500">{cat}</div>
                  <div className="text-2xl mono text-emerald-400">{n.toLocaleString()}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function VariantList({ title, items, copyOne, copiedIdx, prefix }) {
  return (
    <div className="border border-zinc-800 bg-zinc-950">
      <div className="p-2 border-b border-zinc-800 text-[10px] mono uppercase text-zinc-500">
        {title} · {items.length}
      </div>
      <div className="max-h-96 overflow-y-auto">
        {items.map(({ value, mutation, key }, i) => {
          const k = `${prefix}${key}`;
          return (
            <div key={k} className="p-2 border-b border-zinc-900 flex items-start gap-2 hover:bg-zinc-900/40">
              <div className="flex-1 min-w-0">
                <code className="text-xs text-zinc-100 break-all">{value}</code>
                <div className="text-[9px] mono text-zinc-600 mt-0.5">{mutation}</div>
              </div>
              <button onClick={() => copyOne(value, k)} className="text-zinc-500 hover:text-emerald-400 shrink-0">
                {copiedIdx === k ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              </button>
            </div>
          );
        })}
        {items.length === 0 && <div className="p-4 text-center text-zinc-600 text-xs">—</div>}
      </div>
    </div>
  );
}
