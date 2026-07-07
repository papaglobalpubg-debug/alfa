import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import api from '@/lib/api';
import { scanLogClass } from '@/lib/uiHelpers';
import { PriorityBadge, StatusBadge, PulseDot, AsciiLoader } from '@/components/Badges';
import { SCAN_DETAIL } from '@/constants/testIds';
import {
  ArrowLeft, RefreshCw, Trash2, Download, ChevronDown, ChevronRight,
  ExternalLink, FileJson, FileText, FileSpreadsheet, FileCode, StopCircle,
  BookOpen, Copy, Check,
} from 'lucide-react';

function fmt(iso) {
  if (!iso) return '-';
  try { return new Date(iso).toLocaleString(); } catch (e) { return iso; }
}

function TerminalLog({ logs }) {
  const ref = useRef();
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [logs]);
  return (
    <div ref={ref} className="terminal" data-testid={SCAN_DETAIL.logsPanel}>
      {logs?.length ? logs.map((l, i) => {
        const isErr = /error/i.test(l);
        const isWarn = /warn|failed/i.test(l);
        const m = l.match(/^\[([\d:]+)\]\s*(.*)$/);
        const time = m ? m[1] : '';
        const msg = m ? m[2] : l;
        return (
          <div key={`${time}-${i}-${msg.slice(0, 20)}`}>
            {time && <span className="log-time">[{time}]</span>}{' '}
            <span className={scanLogClass({ isErr, isWarn })}>{msg}</span>
          </div>
        );
      }) : (
        <div className="text-zinc-700">
          <span className="blink">_</span> waiting for scan output...
        </div>
      )}
    </div>
  );
}

function ResultRow({ r, isNew, scanId, onOpenReport }) {
  const [expanded, setExpanded] = useState(false);
  const claim = r.claimable || r.verified_claimable;
  return (
    <>
      <tr
        data-testid={`result-row-${r.subdomain}`}
        onClick={() => setExpanded(!expanded)}
        className={`border-b border-zinc-900 hover:bg-zinc-800/30 cursor-pointer transition-colors ${isNew ? 'flash-new' : ''}`}
      >
        <td className="py-2 px-2 text-zinc-600">
          {expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
        </td>
        <td className="py-2 px-2">
          <div className="flex gap-1 items-center">
            <PriorityBadge priority={r.priority} />
            <StatusBadge status={r.classification} />
          </div>
        </td>
        <td className="py-2 px-2 font-mono text-zinc-50 text-xs break-all">
          {r.subdomain}
          {r.verified_claimable && <span className="ml-2 text-emerald-500">[VERIFIED]</span>}
        </td>
        <td className="py-2 px-2 font-mono text-xs text-zinc-400">{r.service_name || '-'}</td>
        <td className="py-2 px-2 font-mono text-xs text-zinc-500">{r.http_status || '-'}</td>
        <td className="py-2 px-2 font-mono text-xs text-zinc-500 max-w-[240px] truncate">
          {(r.cname_chain || []).join(' -> ') || '(direct)'}
        </td>
        <td className="py-2 px-2 text-xs text-right whitespace-nowrap">
          {claim && (
            <>
              <button
                data-testid={`report-btn-${r.subdomain}`}
                onClick={(e) => { e.stopPropagation(); onOpenReport(r); }}
                className="text-emerald-500 hover:text-emerald-400 inline-flex items-center gap-1 mr-2"
                title="Generate Bug Bounty report"
              >
                <BookOpen className="w-3 h-3" />
              </button>
              <a href={`https://${r.subdomain}`} target="_blank" rel="noreferrer"
                className="text-emerald-500 hover:text-emerald-400 inline-flex items-center gap-1"
                onClick={(e) => e.stopPropagation()}>
                <ExternalLink className="w-3 h-3" />
              </a>
            </>
          )}
        </td>
      </tr>
      {expanded && (
        <tr className="bg-zinc-950">
          <td colSpan={7} className="px-4 py-3 border-b border-zinc-800">
            <div className="grid grid-cols-2 gap-4 text-xs mono">
              <div>
                <div className="text-zinc-500 uppercase tracking-widest mb-1">DNS Details</div>
                <div className="text-zinc-400">
                  <div><span className="text-zinc-600">Final:</span> {r.final_target || '-'}</div>
                  <div><span className="text-zinc-600">A recs:</span> {(r.a_records || []).join(', ') || '-'}</div>
                  <div><span className="text-zinc-600">Chain:</span> {(r.cname_chain || []).join(' -> ') || '(direct)'}</div>
                  <div><span className="text-zinc-600">Wildcard:</span> {r.is_wildcard ? 'yes' : 'no'}</div>
                </div>
              </div>
              <div>
                <div className="text-zinc-500 uppercase tracking-widest mb-1">Takeover Info</div>
                <div className="text-zinc-400">
                  <div><span className="text-zinc-600">Service:</span> {r.service_name || '-'} ({r.service || '-'})</div>
                  <div><span className="text-zinc-600">Confidence:</span> {r.confidence || 0}%</div>
                  <div><span className="text-zinc-600">Method:</span> {r.claim_method || '-'}</div>
                  {r.evidence && <div><span className="text-zinc-600">Evidence:</span> {r.evidence}</div>}
                  {r.reason_dead && <div className="text-zinc-500"><span className="text-zinc-600">Note:</span> {r.reason_dead}</div>}
                  {r.verification && (
                    <div>
                      <span className="text-zinc-600">Verify:</span>{' '}
                      <span className={r.verification.available ? 'text-emerald-400' : 'text-zinc-400'}>
                        {r.verification.reason}
                      </span>
                    </div>
                  )}
                </div>
              </div>
              {r.http_body_sample && (
                <div className="col-span-2">
                  <div className="text-zinc-500 uppercase tracking-widest mb-1">HTTP Body Sample</div>
                  <div className="bg-black p-2 text-emerald-500/70 text-[11px] overflow-x-auto">
                    {r.http_body_sample.slice(0, 400)}
                  </div>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function BugBountyModal({ scanId, finding, onClose }) {
  const [data, setData] = useState(null);
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!finding) return;
    api.getBugBountyReport(scanId, finding.subdomain)
      .then(({ data }) => setData(data))
      .catch(() => setData({ error: 'Failed to load report' }));
  }, [scanId, finding]);
  const copy = async () => {
    await navigator.clipboard.writeText(data.markdown);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  if (!finding) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80" onClick={onClose}>
      <div className="bg-zinc-900 border border-zinc-800 max-w-4xl w-full max-h-[90vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}>
        <div className="p-4 border-b border-zinc-800 flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2">
              <BookOpen className="w-5 h-5 text-emerald-500" />
              <h2 className="text-lg font-display font-bold text-zinc-50">Bug Bounty Report</h2>
            </div>
            <div className="text-xs text-zinc-500 mono mt-1">{finding.subdomain}</div>
          </div>
          <div className="flex gap-2">
            {data?.markdown && (
              <button
                data-testid="report-copy-btn"
                onClick={copy}
                className="flex items-center gap-1 px-3 py-1.5 bg-emerald-500 text-zinc-950 font-semibold mono text-xs hover:bg-emerald-400"
              >
                {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                {copied ? 'Copied' : 'Copy Report'}
              </button>
            )}
            <button
              data-testid="report-close-btn"
              onClick={onClose}
              className="px-3 py-1.5 border border-zinc-800 text-zinc-400 hover:text-zinc-50 mono text-xs"
            >
              Close
            </button>
          </div>
        </div>
        <div className="flex-1 overflow-y-auto p-4">
          {!data ? (
            <div className="text-zinc-500 mono p-8 text-center">Generating report...</div>
          ) : data.error ? (
            <div className="text-red-400 mono p-4">{data.error}</div>
          ) : (
            <>
              {data.playbook && (
                <div className="mb-4 bg-zinc-950 border border-zinc-800 p-3">
                  <div className="flex gap-4 text-xs mono">
                    <span><span className="text-zinc-600">CVSS:</span> <span className="text-emerald-500 font-bold">{data.playbook.cvss_base}</span></span>
                    <span><span className="text-zinc-600">Severity:</span> <PriorityBadge priority={data.playbook.severity} /></span>
                    <span><span className="text-zinc-600">CWE:</span> {(data.playbook.cwe || []).join(', ')}</span>
                  </div>
                </div>
              )}
              <pre className="bg-black text-zinc-300 p-4 text-xs overflow-x-auto mono border border-zinc-800 whitespace-pre-wrap">
                {data.markdown}
              </pre>
              <div className="mt-4 text-xs text-zinc-600 mono">
                Tip: Paste into HackerOne/Bugcrowd. Replace <code>&lt;subdomain&gt;</code> placeholders (already filled in).
                See full Playbook <a href={`/playbooks?service=${finding.service}`} className="text-emerald-500 hover:underline">here</a>.
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

const CLASSES = [
  'CLAIMABLE', 'VERIFY_REQUIRED', 'SERVICE_ACTIVE', 'ALIVE', 'DEAD',
  'NXDOMAIN', 'WILDCARD', 'HTTP_ERROR', 'NO_MATCH',
];

export default function ScanDetail() {
  const { id } = useParams();
  const nav = useNavigate();
  const [scan, setScan] = useState(null);
  const [results, setResults] = useState([]);
  const [logs, setLogs] = useState([]);
  const [prevFindings, setPrevFindings] = useState(new Set());
  const [newFindings, setNewFindings] = useState(new Set());
  const [priority, setPriority] = useState('');
  const [cls, setCls] = useState('');
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [reportFinding, setReportFinding] = useState(null);

  const sortedSourceStats = useMemo(() => {
    if (!scan?.discovery?.stats) return [];
    return Object.entries(scan.discovery.stats).sort((a, b) => b[1] - a[1]);
  }, [scan]);

  const running = scan && ['pending', 'discovering', 'analyzing', 'verifying'].includes(scan.status);

  useEffect(() => {
    let mounted = true;
    const load = async () => {
      try {
        const [s, l] = await Promise.all([
          api.getScan(id),
          api.getScanLogs(id).catch(() => ({ data: { logs: [] } })),
        ]);
        if (!mounted) return;
        setScan(s.data);
        setLogs(l.data.logs || []);

        // Load results
        const r = await api.getScanResults(id, { priority, classification: cls, search });
        if (!mounted) return;
        // detect new findings
        const findings = new Set((r.data.results || [])
          .filter((x) => x.claimable || x.verified_claimable)
          .map((x) => x.subdomain));
        if (prevFindings.size > 0) {
          const added = [...findings].filter((f) => !prevFindings.has(f));
          if (added.length) {
            setNewFindings(new Set(added));
            setTimeout(() => setNewFindings(new Set()), 2000);
          }
        }
        setPrevFindings(findings);
        setResults(r.data.results || []);
      } catch (e) {
        if (mounted) setError(e?.message || 'Failed to load scan results');
      } finally {
        if (mounted) setLoading(false);
      }
    };
    load();
    const t = setInterval(load, running ? 2500 : 15000);
    return () => { mounted = false; clearInterval(t); };
  }, [id, priority, cls, search, running]);

  const del = async () => {
    if (!window.confirm(`Delete scan ${scan?.domain}?`)) return;
    await api.deleteScan(id);
    nav('/history');
  };

  const rescan = async () => {
    const { data } = await api.createScan({
      domain: scan.domain,
      sources: scan.options?.sources,
      threads: scan.options?.threads || 20,
      timeout: scan.options?.timeout || 15,
      verify: true,
      notify: false,
    });
    nav(`/scan/${data.scan_id}`);
  };

  if (loading || !scan) {
    return <div className="text-zinc-500 mono p-8">Loading scan...{error && <div className="text-red-400 mt-2 text-xs">{error}</div>}</div>;
  }

  const progress = scan.progress || {};
  const analyzed = progress.analyzed || 0;
  const analyzedTotal = progress.analyzed_total || 0;
  const analyzePct = analyzedTotal ? Math.round((analyzed / analyzedTotal) * 100) : 0;
  const sourcesDone = progress.sources_done || 0;
  const sourcesTotal = progress.sources_total || 0;
  const discoveryPct = sourcesTotal ? Math.round((sourcesDone / sourcesTotal) * 100) : 0;
  const summary = scan.summary || {};

  return (
    <div data-testid={SCAN_DETAIL.container} className="space-y-6 max-w-7xl">
      <button onClick={() => nav('/history')}
        className="flex items-center gap-1 text-xs text-zinc-500 hover:text-emerald-500 transition-colors mono">
        <ArrowLeft className="w-3 h-3" /> Back to history
      </button>

      <header data-testid={SCAN_DETAIL.header} className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-display font-bold text-zinc-50 tracking-tight flex items-center gap-3">
            <span className="text-emerald-500">&gt;</span>
            <span className="mono">{scan.domain}</span>
            {running && <span data-testid={SCAN_DETAIL.liveDot}><PulseDot /></span>}
          </h1>
          <div className="flex items-center gap-3 text-xs text-zinc-500 mono mt-2">
            <StatusBadge status={scan.status} />
            <span>Started {fmt(scan.started_at)}</span>
            {scan.duration && <span>Duration {scan.duration.toFixed(1)}s</span>}
            <span>ID {scan.id.slice(0, 8)}</span>
          </div>
        </div>
        <div className="flex gap-2 flex-wrap">
          <button
            data-testid="scan-graph-btn"
            onClick={() => nav(`/scan/${id}/graph`)}
            className="flex items-center gap-1 px-3 py-1.5 border border-emerald-500/50 text-emerald-400 hover:bg-emerald-500/10 mono text-xs transition-colors"
          >
            <BookOpen className="w-3 h-3" /> Graph
          </button>
          {running && (
            <button
              data-testid="scan-cancel-btn"
              onClick={async () => {
                if (!window.confirm('Cancel this running scan?')) return;
                await api.cancelScan(id);
              }}
              className="flex items-center gap-1 px-3 py-1.5 border border-amber-500/50 text-amber-400 hover:bg-amber-500/10 mono text-xs transition-colors"
            >
              <StopCircle className="w-3 h-3" /> Cancel
            </button>
          )}
          <button
            data-testid={SCAN_DETAIL.rescanBtn}
            onClick={rescan}
            className="flex items-center gap-1 px-3 py-1.5 border border-zinc-800 text-zinc-400 hover:text-zinc-50 hover:border-zinc-700 mono text-xs transition-colors"
          >
            <RefreshCw className="w-3 h-3" /> Rescan
          </button>
          <button
            data-testid={SCAN_DETAIL.deleteBtn}
            onClick={del}
            className="flex items-center gap-1 px-3 py-1.5 border border-red-500/30 text-red-400 hover:bg-red-500/10 mono text-xs transition-colors"
          >
            <Trash2 className="w-3 h-3" /> Delete
          </button>
        </div>
      </header>

      {running && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-zinc-900 border border-zinc-800 p-4">
            <div className="text-xs uppercase tracking-widest text-zinc-500 mono mb-2">
              Discovery {sourcesDone}/{sourcesTotal}
            </div>
            <div className="text-emerald-500 mono text-lg" data-testid={SCAN_DETAIL.progressBar}>
              <AsciiLoader progress={discoveryPct} />
            </div>
          </div>
          <div className="bg-zinc-900 border border-zinc-800 p-4">
            <div className="text-xs uppercase tracking-widest text-zinc-500 mono mb-2">
              Analysis {analyzed}/{analyzedTotal}
            </div>
            <div className="text-emerald-500 mono text-lg">
              <AsciiLoader progress={analyzePct} />
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-6 gap-2">
        {[
          ['Verified', summary.verified_claimable, 'text-red-400'],
          ['Claimable', summary.claimable, 'text-emerald-400'],
          ['Verify Req', summary.verify_required, 'text-amber-400'],
          ['Dead', summary.dead, 'text-zinc-500'],
          ['Alive', (summary.service_active || 0) + (summary.alive || 0), 'text-blue-400'],
          ['Total', summary.total_analyzed, 'text-zinc-50'],
        ].map(([label, v, col]) => (
          <div key={label} className="bg-zinc-900 border border-zinc-800 p-3">
            <div className={`text-2xl font-semibold mono ${col}`}>{v || 0}</div>
            <div className="text-[10px] uppercase tracking-widest text-zinc-500 mono">{label}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 bg-zinc-900 border border-zinc-800 p-4">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
            <h3 className="text-sm uppercase tracking-widest text-zinc-500 mono">
              Results ({results.length})
            </h3>
            <div className="flex gap-2 items-center">
              <input
                data-testid={SCAN_DETAIL.filterSearch}
                type="text"
                placeholder="filter subdomain..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="px-2 py-1 bg-black border border-zinc-800 mono text-xs text-zinc-300 focus:outline-none focus:border-emerald-500 w-40"
              />
              <select
                data-testid={SCAN_DETAIL.filterPriority}
                value={priority}
                onChange={(e) => setPriority(e.target.value)}
                className="px-2 py-1 bg-black border border-zinc-800 mono text-xs text-zinc-300 focus:outline-none focus:border-emerald-500"
              >
                <option value="">All priorities</option>
                <option>critical</option><option>high</option><option>medium</option><option>low</option>
              </select>
              <select
                data-testid={SCAN_DETAIL.filterClass}
                value={cls}
                onChange={(e) => setCls(e.target.value)}
                className="px-2 py-1 bg-black border border-zinc-800 mono text-xs text-zinc-300 focus:outline-none focus:border-emerald-500"
              >
                <option value="">All classes</option>
                {CLASSES.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
          </div>

          <div className="overflow-auto max-h-[70vh]">
            <table data-testid={SCAN_DETAIL.resultsTable} className="w-full text-sm">
              <thead className="sticky top-0 bg-zinc-900">
                <tr className="text-left text-zinc-500 text-[10px] uppercase tracking-widest border-b border-zinc-800">
                  <th className="py-2 px-2 w-6"></th>
                  <th className="py-2 px-2 font-medium">Badge</th>
                  <th className="py-2 px-2 font-medium">Subdomain</th>
                  <th className="py-2 px-2 font-medium">Service</th>
                  <th className="py-2 px-2 font-medium">HTTP</th>
                  <th className="py-2 px-2 font-medium">CNAME Chain</th>
                  <th className="py-2 px-2 font-medium"></th>
                </tr>
              </thead>
              <tbody>
                {results.length === 0 ? (
                  <tr><td colSpan={7} className="py-8 text-center text-zinc-600 mono text-xs">
                    {running ? 'Waiting for results...' : 'No results match filters.'}
                  </td></tr>
                ) : results.map((r) => (
                  <ResultRow key={r.subdomain + (r.classification || '')} r={r}
                    isNew={newFindings.has(r.subdomain)}
                    scanId={id}
                    onOpenReport={setReportFinding} />
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="space-y-4">
          <div>
            <h3 className="text-sm uppercase tracking-widest text-zinc-500 mono mb-2">Terminal</h3>
            <TerminalLog logs={logs} />
          </div>

          <div className="bg-zinc-900 border border-zinc-800 p-4">
            <h3 className="text-sm uppercase tracking-widest text-zinc-500 mono mb-3">Export</h3>
            <div className="grid grid-cols-2 gap-2">
              {[
                ['json', 'JSON', FileJson, SCAN_DETAIL.exportJson],
                ['html', 'HTML', FileCode, SCAN_DETAIL.exportHtml],
                ['csv', 'CSV', FileSpreadsheet, SCAN_DETAIL.exportCsv],
                ['txt', 'TXT', FileText, SCAN_DETAIL.exportTxt],
              ].map(([fmt, label, Icon, tid]) => (
                <a key={fmt}
                  data-testid={tid}
                  href={api.exportScanUrl(id, fmt)}
                  target="_blank" rel="noreferrer"
                  className="flex items-center gap-1.5 px-3 py-1.5 border border-zinc-800 text-zinc-400 hover:text-emerald-500 hover:border-emerald-500/50 mono text-xs transition-colors"
                >
                  <Icon className="w-3 h-3" /> {label}
                </a>
              ))}
            </div>
          </div>

          {scan.discovery?.stats && Object.keys(scan.discovery.stats).length > 0 && (
            <div className="bg-zinc-900 border border-zinc-800 p-4">
              <h3 className="text-sm uppercase tracking-widest text-zinc-500 mono mb-3">
                Sources Stats
              </h3>
              <ul className="space-y-1 mono text-xs">
                {sortedSourceStats.map(([s, n]) => (
                  <li key={s} className="flex justify-between">
                    <span className="text-zinc-500">{s}</span>
                    <span className="text-zinc-300">{n}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
      <BugBountyModal scanId={id} finding={reportFinding} onClose={() => setReportFinding(null)} />
    </div>
  );
}
