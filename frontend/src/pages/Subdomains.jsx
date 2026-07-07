import React, { useState } from 'react';
import { Globe, Search, Loader2, Copy } from 'lucide-react';
import api from '@/lib/api';
import CopyButton from '@/components/CopyButton';

export default function SubdomainsPage() {
  const [domain, setDomain] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const run = async () => {
    const d = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!d) return;
    setLoading(true);
    setResult(null);
    try {
      const r = await api.discoverSubdomains(d);
      setResult(r.data);
    } catch (e) {
      setResult({ error: String(e) });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-4" data-testid="subdomains-page">
      <div className="flex items-center gap-3 mb-2">
        <Globe className="w-6 h-6 text-emerald-500" />
        <div>
          <h1 className="text-2xl font-bold text-zinc-50">Subdomain Discovery</h1>
          <p className="text-xs mono text-zinc-500">
            Passive OSINT via crt.sh · OTX · Wayback · HackerTarget · RapidDNS · ThreatMiner
          </p>
        </div>
      </div>

      <div className="flex gap-2">
        <input
          value={domain}
          onChange={e => setDomain(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && run()}
          data-testid="subdomain-input"
          placeholder="example.com"
          className="flex-1 bg-zinc-900 border border-zinc-800 px-4 py-3 mono text-sm text-zinc-100 focus:border-emerald-500 focus:outline-none"
        />
        <button onClick={run} disabled={loading || !domain} data-testid="subdomain-search"
                className="px-6 py-3 bg-emerald-500 hover:bg-emerald-600 disabled:opacity-50 text-black font-bold mono text-xs uppercase tracking-widest flex items-center gap-2">
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
          {loading ? 'Discovering...' : 'Discover'}
        </button>
      </div>

      {result?.error && (
        <div className="border border-red-500/40 bg-red-500/10 text-red-400 p-4 mono text-xs">
          {result.error}
        </div>
      )}

      {result && !result.error && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
            {Object.entries(result.sources || {}).map(([src, n]) => (
              <div key={src} className="border border-zinc-800 bg-zinc-950 p-3 text-xs mono">
                <div className="text-zinc-500 uppercase text-[10px] tracking-widest">{src}</div>
                <div className="text-emerald-500 text-lg font-bold">{n}</div>
              </div>
            ))}
          </div>

          <div className="border border-zinc-800 bg-zinc-950">
            <div className="p-3 border-b border-zinc-800 flex items-center justify-between">
              <div className="text-xs mono">
                <span className="text-emerald-500 font-bold text-lg">{result.total}</span>
                <span className="text-zinc-500 ml-2 uppercase tracking-widest text-[10px]">unique subdomains</span>
              </div>
              <CopyButton
                text={(result.unique || []).join('\n')}
                variant="button"
                label={`Copy ${result.total}`}
                testid="copy-all-subdomains"
              />
            </div>
            <div className="max-h-[500px] overflow-y-auto p-3 space-y-1">
              {(result.unique || []).map((s) => (
                <div key={s} className="flex items-center justify-between group text-xs mono py-1 px-2 hover:bg-zinc-900" data-testid={`subdomain-${s}`}>
                  <span className="text-zinc-300 select-all">{s}</span>
                  <div className="opacity-0 group-hover:opacity-100 flex gap-1">
                    <a href={`https://${s}`} target="_blank" rel="noreferrer" className="text-emerald-500 hover:text-emerald-400 text-[10px] uppercase tracking-widest">Open</a>
                    <CopyButton text={s} variant="icon" testid={`copy-sub-${s}`} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
