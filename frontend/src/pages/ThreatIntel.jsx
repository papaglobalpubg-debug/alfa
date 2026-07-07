import React, { useEffect, useState } from 'react';
import api from '@/lib/api';
import { ScrollText, RefreshCw, Radio, DollarSign, TrendingUp } from 'lucide-react';
import { LoadingBar, CountUp } from '@/components/Loaders';

export default function ThreatIntel() {
  const [brief, setBrief] = useState(null);
  const [cves, setCves] = useState([]);
  const [busy, setBusy] = useState(false);

  const load = async () => {
    setBusy(true);
    try {
      const [b, c] = await Promise.all([
        api.threatIntel().catch(() => ({ data: null })),
        api.cveFeedList(20).catch(() => ({ data: { items: [] } })),
      ]);
      setBrief(b.data);
      setCves(c.data?.items || []);
    } finally {
      setBusy(false);
    }
  };
  const sync = async () => {
    setBusy(true);
    try { await api.cveFeedSync(); await load(); } finally { setBusy(false); }
  };
  useEffect(() => { load(); }, []);

  return (
    <div data-testid="threat-intel-page" className="max-w-5xl mx-auto space-y-6 animate-fade-in-up">
      <header className="relative border border-cyan-500/40 bg-gradient-to-r from-cyan-950/40 via-zinc-950 to-zinc-950 p-6 overflow-hidden">
        <div className="relative flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <ScrollText className="w-6 h-6 text-cyan-400 animate-glow-pulse" />
              <span className="text-[10px] mono uppercase tracking-widest text-cyan-400 border border-cyan-500/50 bg-cyan-500/10 px-2 py-0.5">
                Threat Intelligence Feed
              </span>
            </div>
            <h1 className="text-2xl md:text-3xl font-display font-bold text-zinc-50">Weekly Intel Brief</h1>
            <p className="text-zinc-400 text-sm mt-2">
              AI-generated brief tailored to your recent targets · live NVD CVE feed.
            </p>
          </div>
          <div className="flex gap-2">
            <button onClick={sync} disabled={busy}
              data-testid="ti-sync"
              className="flex items-center gap-2 px-3 py-2 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/10 mono text-xs uppercase tracking-widest disabled:opacity-40">
              <RefreshCw className={`w-3 h-3 ${busy ? 'animate-spin' : ''}`} /> Sync CVEs
            </button>
          </div>
        </div>
      </header>

      {busy && <LoadingBar color="cyan" label="Loading intel..." />}

      {brief && (
        <section data-testid="brief" className="bg-zinc-900/50 border border-cyan-500/30 p-4 space-y-3">
          <div className="flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm mono uppercase tracking-widest font-semibold text-cyan-300">This Week's Headline</h3>
          </div>
          <p className="text-zinc-200 text-sm">{brief.headline}</p>

          {brief.cve_watchlist?.length > 0 && (
            <div className="mt-3">
              <div className="text-[10px] mono uppercase tracking-widest text-zinc-500 mb-2">CVE Watchlist</div>
              <div className="space-y-1">
                {brief.cve_watchlist.map((c, i) => (
                  <div key={i} className="p-2 bg-zinc-950 border border-zinc-800 text-xs mono">
                    <span className="text-red-400 font-bold">{c.cve}</span>
                    <span className="text-zinc-400"> · {c.why}</span>
                    <span className="text-amber-400"> · {c.impact}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {brief.writeup_ideas?.length > 0 && (
            <div className="mt-3">
              <div className="text-[10px] mono uppercase tracking-widest text-zinc-500 mb-2">Writeup Ideas</div>
              <div className="space-y-1">
                {brief.writeup_ideas.map((w, i) => (
                  <div key={i} className="p-2 bg-zinc-950 border border-zinc-800 text-xs mono flex items-center gap-2">
                    <div className="flex-1">
                      <div className="text-zinc-100">{w.title}</div>
                      <div className="text-zinc-500 text-[10px] mt-0.5">{w.technique}</div>
                    </div>
                    <span className="text-emerald-400 font-bold flex items-center gap-1">
                      <DollarSign className="w-3 h-3" />{w.expected_bounty?.replace(/^\$/, '')}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {brief.top_techniques_to_try?.length > 0 && (
            <div className="mt-3">
              <div className="text-[10px] mono uppercase tracking-widest text-zinc-500 mb-2">Top Techniques to Try</div>
              <ul className="text-xs mono text-zinc-300 space-y-0.5">
                {brief.top_techniques_to_try.map((t, i) => (
                  <li key={i}>· {t}</li>
                ))}
              </ul>
            </div>
          )}
        </section>
      )}

      <section className="bg-zinc-900/50 border border-zinc-800">
        <div className="flex items-center justify-between p-4 border-b border-zinc-800">
          <h3 className="text-sm mono uppercase tracking-widest font-semibold text-red-400 flex items-center gap-2">
            <Radio className="w-4 h-4" /> Live CVE Feed · <CountUp value={cves.length} />
          </h3>
        </div>
        <div className="divide-y divide-zinc-800 max-h-96 overflow-y-auto">
          {cves.length === 0 ? (
            <div className="p-4 text-zinc-500 mono text-sm text-center">
              No CVEs synced yet.{' '}
              <button onClick={sync} className="text-cyan-400 underline">Sync now</button>
            </div>
          ) : cves.map((c, i) => (
            <div key={i} data-testid={`cve-${c.cve_id}`} className="p-3 text-xs mono">
              <div className="flex items-center gap-2 mb-1">
                <span className={`px-1.5 py-0.5 border text-[10px] mono ${
                  c.severity === 'critical' ? 'border-red-500 text-red-400' :
                  c.severity === 'high' ? 'border-orange-500 text-orange-400' : 'border-amber-500 text-amber-400'
                }`}>{c.cvss?.toFixed?.(1)}</span>
                <span className="text-red-400 font-bold">{c.cve_id}</span>
                <span className="text-zinc-600 ml-auto text-[10px]">{c.published?.slice(0, 10)}</span>
              </div>
              <div className="text-zinc-400 text-xs">{c.description}</div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
