import React, { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Bomb, ShieldAlert, AlertCircle, ChevronRight, Download, Copy, Terminal as TerminalIcon, ExternalLink, Sparkles, FileText, Camera, StopCircle, Brain, Target as TargetIcon } from 'lucide-react';
import api from '@/lib/api';
import { scanStatusColor, logLineColor } from '@/lib/uiHelpers';
import CopyButton, { Copyable } from '@/components/CopyButton';
import AIExplainModal from '@/components/AIExplainModal';
import LogViewer from '@/components/LogViewer';

const SEVERITY_COLORS = {
  critical: 'text-red-500 border-red-500/40 bg-red-500/5',
  high: 'text-orange-400 border-orange-500/40 bg-orange-500/5',
  medium: 'text-yellow-400 border-yellow-500/40 bg-yellow-500/5',
  low: 'text-blue-400 border-blue-500/40 bg-blue-500/5',
  info: 'text-zinc-400 border-zinc-700 bg-zinc-800/50',
  unknown: 'text-zinc-500 border-zinc-700 bg-zinc-900/50',
};

function severityBadge(sev) {
  const cls = SEVERITY_COLORS[sev] || SEVERITY_COLORS.info;
  return (
    <span className={`inline-block px-2 py-0.5 text-[10px] mono uppercase tracking-widest border ${cls}`}>
      {sev || 'info'}
    </span>
  );
}

function FindingCard({ f, idx, scanId, onExplain, onCopyCurl, fpScore }) {
  const [expanded, setExpanded] = useState(false);
  // v7.6 · Inline FP-score badge — one glance to know "trust it or triage it"
  const fpBadge = (fpScore != null) ? (() => {
    const pct = Math.round((fpScore || 0) * 100);
    const tone = pct >= 70 ? 'bg-red-500/10 border-red-500/40 text-red-400'
                : pct >= 40 ? 'bg-amber-500/10 border-amber-500/40 text-amber-400'
                : 'bg-emerald-500/10 border-emerald-500/40 text-emerald-400';
    const label = pct >= 70 ? 'likely FP' : pct >= 40 ? 'review' : 'likely real';
    return (
      <span
        className={`inline-block px-2 py-0.5 text-[10px] mono uppercase tracking-widest border ${tone}`}
        data-testid={`fp-badge-${idx}`}
        title={`False-positive score: ${pct}% — ${label}`}
      >
        FP {pct}%
      </span>
    );
  })() : null;
  return (
    <div
      data-testid={`finding-card-${idx}`}
      className="border border-zinc-800 bg-zinc-950 hover:border-zinc-700 transition-colors"
    >
      <div className="w-full p-4 flex items-start justify-between gap-4 text-left">
        <button
          onClick={() => setExpanded(!expanded)}
          className="flex-1 min-w-0 text-left"
        >
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            {severityBadge(f.severity)}
            {f.verified === true && (
              <span
                className="inline-block px-2 py-0.5 text-[10px] mono uppercase tracking-widest border border-emerald-500/50 bg-emerald-500/10 text-emerald-400"
                data-testid={`verified-badge-${idx}`}
                title="Verified — multi-signal evidence confirmed"
              >
                ✓ verified
              </span>
            )}
            {f.verified === false && (
              <span
                className="inline-block px-2 py-0.5 text-[10px] mono uppercase tracking-widest border border-yellow-500/40 bg-yellow-500/5 text-yellow-400"
                title="Requires manual verification"
              >
                unverified
              </span>
            )}
            <span className="text-[10px] mono text-zinc-500 uppercase tracking-widest">
              {f.type}{f.subtype && ` · ${f.subtype}`}
            </span>
            {f.cvss > 0 && (
              <span className="text-[10px] mono text-emerald-500">CVSS {f.cvss}</span>
            )}
            {f.confidence > 0 && (
              <span className="text-[10px] mono text-zinc-500">conf {f.confidence}%</span>
            )}
            {fpBadge}
            {f.cve && f.cve !== 'N/A' && (
              <span className="text-[10px] mono text-red-400">{f.cve}</span>
            )}
          </div>
          <div className="text-sm text-zinc-100 mb-1">{f.name || `${f.type} on ${f.param || 'baseline'}`}</div>
          <div className="text-xs mono text-zinc-500 truncate">{f.url}</div>
        </button>
        <div className="flex flex-col items-end gap-1 shrink-0">
          {f.url && (
            <CopyButton
              text={f.url}
              variant="button"
              label="URL"
              testid={`copy-url-${idx}`}
            />
          )}
          {f.payload && (
            <CopyButton
              text={f.payload}
              variant="inline"
              label="Payload"
              testid={`copy-payload-${idx}`}
            />
          )}
          {f.url && f.url.startsWith('http') && (
            <a
              href={f.url}
              target="_blank"
              rel="noopener noreferrer"
              onClick={(e) => e.stopPropagation()}
              className="inline-flex items-center gap-1 text-[10px] mono uppercase tracking-widest text-zinc-500 hover:text-red-400 transition-colors"
              data-testid={`open-target-${idx}`}
            >
              <ExternalLink className="w-3 h-3" /> Open
            </a>
          )}
          <button
            onClick={(e) => { e.stopPropagation(); onExplain?.(idx, f); }}
            className="inline-flex items-center gap-1 text-[10px] mono uppercase tracking-widest text-emerald-400 hover:text-emerald-300 border border-emerald-500/30 hover:border-emerald-500/60 px-2 py-0.5 transition-colors"
            data-testid={`ai-explain-${idx}`}
            title="AI-powered explanation (Arabic/English)"
          >
            <Sparkles className="w-3 h-3" /> AI Explain
          </button>
          {f.url && (
            <button
              onClick={(e) => { e.stopPropagation(); onCopyCurl?.(f); }}
              className="inline-flex items-center gap-1 text-[10px] mono uppercase tracking-widest text-zinc-400 hover:text-emerald-300 border border-zinc-800 hover:border-emerald-500/40 px-2 py-0.5 transition-colors"
              data-testid={`copy-curl-${idx}`}
              title="Copy as curl command for manual verification"
            >
              <TerminalIcon className="w-3 h-3" /> cURL
            </button>
          )}
          <button
            onClick={() => setExpanded(!expanded)}
            className="p-1 text-zinc-500 hover:text-emerald-400"
            aria-label="Expand"
          >
            <ChevronRight className={`w-4 h-4 transition-transform ${expanded ? 'rotate-90' : ''}`} />
          </button>
        </div>
      </div>
      {expanded && (
        <div className="p-4 pt-0 border-t border-zinc-900 space-y-3 text-xs mono">
          {f.url && (
            <div>
              <div className="flex items-center justify-between mb-1">
                <div className="text-[10px] uppercase tracking-widest text-zinc-500">Target URL</div>
                <CopyButton text={f.url} variant="inline" label="Copy" testid={`detail-copy-url-${idx}`} />
              </div>
              <div className="bg-zinc-900 border border-zinc-800 p-2 text-red-300 break-all select-all">{f.url}</div>
            </div>
          )}
          {f.payload && (
            <div>
              <div className="flex items-center justify-between mb-1">
                <div className="text-[10px] uppercase tracking-widest text-zinc-500">Payload</div>
                <CopyButton text={f.payload} variant="inline" label="Copy" testid={`detail-copy-payload-${idx}`} />
              </div>
              <div className="bg-zinc-900 border border-zinc-800 p-2 text-emerald-400 break-all select-all">{f.payload}</div>
            </div>
          )}
          {f.param && (
            <div>
              <div className="text-[10px] uppercase tracking-widest text-zinc-500 mb-1">Parameter</div>
              <div className="text-zinc-300 select-all">{f.param}</div>
            </div>
          )}
          {f.evidence && (
            <div>
              <div className="flex items-center justify-between mb-1">
                <div className="text-[10px] uppercase tracking-widest text-zinc-500">Evidence</div>
                <CopyButton text={f.evidence} variant="inline" label="Copy" testid={`detail-copy-evidence-${idx}`} />
              </div>
              <div className="bg-zinc-900 border border-zinc-800 p-2 text-zinc-400 whitespace-pre-wrap break-all max-h-40 overflow-y-auto select-all">{f.evidence}</div>
            </div>
          )}
          {f.delay && <div><span className="text-zinc-500">Delay: </span><span className="text-orange-400 select-all">{f.delay}</span></div>}
          {f.secret_type && <div><span className="text-zinc-500">Secret type: </span><span className="text-red-400 select-all">{f.secret_type}</span></div>}
          {f.value_snippet && (
            <div>
              <div className="flex items-center justify-between mb-1">
                <div className="text-[10px] uppercase tracking-widest text-zinc-500">Secret value</div>
                <CopyButton text={f.value_snippet} variant="inline" label="Copy" testid={`detail-copy-secret-${idx}`} />
              </div>
              <div className="bg-zinc-900 border border-zinc-800 p-2 text-red-400 break-all select-all">{f.value_snippet}</div>
            </div>
          )}
          {f.csp_value && (
            <div>
              <div className="text-[10px] uppercase tracking-widest text-zinc-500 mb-1">CSP header</div>
              <div className="bg-zinc-900 border border-zinc-800 p-2 text-yellow-300 break-all select-all">{f.csp_value}</div>
            </div>
          )}
          {f.desc && <div className="text-zinc-400 select-text">{f.desc}</div>}
          {f.note && <div className="text-zinc-400 italic select-text">{f.note}</div>}
        </div>
      )}
    </div>
  );
}

export default function VulnScanDetail() {
  const { id } = useParams();
  const nav = useNavigate();
  const [scan, setScan] = useState(null);
  const [findings, setFindings] = useState([]);
  const [chains, setChains] = useState([]);
  const [verification, setVerification] = useState({});
  const [reconSummary, setReconSummary] = useState({});
  const [ports, setPorts] = useState([]);
  const [logs, setLogs] = useState([]);
  const [filter, setFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState('');
  const [verifiedOnly, setVerifiedOnly] = useState(false);
  const [tab, setTab] = useState('findings');
  const [aiExplain, setAiExplain] = useState(null);  // {idx, finding} or null

  const refresh = useCallback(async () => {
    try {
      const scanR = await api.getVulnScan(id);
      setScan(scanR.data);
      const logR = await api.getVulnScanLogs(id);
      setLogs(logR.data.logs || []);
      const fR = await api.getVulnScanFindings(id, { limit: 500 });
      setFindings(fR.data.findings || []);
      setChains(fR.data.attack_chains || []);
      setVerification(fR.data.verification || {});
      setReconSummary(fR.data.recon_summary || {});
      setPorts(fR.data.ports || []);
    } catch (e) {
      // Silent — polling will retry; transient network failures should not spam
    }
  }, [id]);

  useEffect(() => {
    refresh();
    const iv = setInterval(refresh, 3000);
    return () => clearInterval(iv);
  }, [refresh]);

  const filtered = findings.filter((f) => {
    if (filter !== 'all' && (f.severity || 'info') !== filter) return false;
    if (typeFilter && (f.type || '').toLowerCase() !== typeFilter.toLowerCase()) return false;
    if (verifiedOnly && !f.verified) return false;
    return true;
  });

  const summary = scan?.summary || {};
  const typeSet = Array.from(new Set(findings.map(f => f.type).filter(Boolean))).sort();

  const running = scan && !['completed', 'failed'].includes(scan.status);

  const exportJson = () => {
    const blob = new Blob([JSON.stringify({ scan, findings, ports, recon_summary: reconSummary }, null, 2)],
                          { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `vulnscan-${id.slice(0,8)}.json`; a.click();
    URL.revokeObjectURL(url);
  };

  // v7.6 · CSV export for bug-bounty triage — spreadsheet-friendly.
  const exportCsv = () => {
    const cols = ['severity', 'type', 'subtype', 'verified', 'confidence',
                  'url', 'param', 'payload', 'evidence', 'cvss'];
    const rows = [cols.join(',')];
    for (const f of filtered) {
      const line = cols.map((k) => {
        let v = f[k];
        if (v === null || v === undefined) v = '';
        if (typeof v === 'object') v = JSON.stringify(v);
        v = String(v).replace(/\r?\n/g, ' ').replace(/"/g, '""');
        return `"${v}"`;
      }).join(',');
      rows.push(line);
    }
    const blob = new Blob([rows.join('\n')], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `vulnscan-${id.slice(0,8)}.csv`; a.click();
    URL.revokeObjectURL(url);
  };

  // v7.6 · Copy-as-cURL for a single finding — quick manual verification.
  const copyAsCurl = (f) => {
    if (!f?.url) return;
    let cmd = `curl -sk -X ${f.method || 'GET'} '${f.url.replace(/'/g, "'\\''")}'`;
    // Add JWT / cookies if the scan used any
    if (scan?.options?.jwt_token) {
      cmd += ` \\\n  -H 'Authorization: Bearer ${scan.options.jwt_token}'`;
    }
    if (scan?.options?.session_cookies) {
      cmd += ` \\\n  -H 'Cookie: ${scan.options.session_cookies.replace(/'/g, "'\\''")}'`;
    }
    if (f.param && f.payload) {
      cmd += ` \\\n  --data-urlencode '${f.param}=${String(f.payload).replace(/'/g, "'\\''")}'`;
    }
    navigator.clipboard?.writeText(cmd).catch(() => { /* clipboard may be unavailable */ });
  };

  // v7.5 — AI False-Positive Predictor
  const [fpResult, setFpResult] = useState(null);
  const [fpLoading, setFpLoading] = useState(false);

  // v7.7 — AI Triage / Chains v2
  const [aiTriage, setAiTriage] = useState(null);
  const [aiTriageLoading, setAiTriageLoading] = useState(false);
  const [aiChains, setAiChains] = useState(null);
  const [aiChainsLoading, setAiChainsLoading] = useState(false);

  const runAiTriage = async () => {
    setAiTriageLoading(true);
    try {
      const r = await api.aiTriage(id);
      setAiTriage(r.data);
    } catch (e) {
      alert('AI Triage failed: ' + (e?.response?.data?.detail || e.message));
    }
    setAiTriageLoading(false);
  };

  const runAiChains = async () => {
    setAiChainsLoading(true);
    try {
      const r = await api.aiChainsV2(id, 'ar');
      setAiChains(r.data);
    } catch (e) {
      alert('AI Chains failed: ' + (e?.response?.data?.detail || e.message));
    }
    setAiChainsLoading(false);
  };
  const runFpPredict = async (useLlm) => {
    setFpLoading(true);
    try {
      const r = await api.predictFalsePositives(id, useLlm);
      setFpResult(r.data);
    } catch (e) {
      alert('FP predictor failed: ' + (e?.response?.data?.detail || e.message));
    }
    setFpLoading(false);
  };

  return (
    <div>
      <button onClick={() => nav('/vuln/history')} className="mb-4 flex items-center gap-2 text-xs mono text-zinc-500 hover:text-emerald-500">
        <ArrowLeft className="w-3 h-3" /> Back
      </button>

      <div className="mb-4 flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Bomb className="w-5 h-5 text-red-500" />
            <h1 className="text-xl font-bold text-zinc-50 tracking-tight" data-testid="vuln-detail-target">{scan?.target}</h1>
            {scan?.target && (
              <CopyButton text={scan.target} variant="icon" testid="copy-scan-target" />
            )}
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[10px] mono uppercase tracking-widest text-zinc-500">Status:</span>
            <span
              data-testid="vuln-scan-status"
              className={`text-[10px] mono uppercase tracking-widest ${scanStatusColor(scan?.status, { running })}`}
            >
              {scan?.status || '...'}
            </span>
            {running && <span className="text-[10px] mono text-zinc-500">| live_logs: {scan?.live_logs_count || 0}</span>}
          </div>
        </div>
        <div className="flex gap-2 flex-wrap justify-end">
          {running && (
            <button
              data-testid="detail-stop-scan-btn"
              onClick={async () => {
                if (!window.confirm('Stop this scan immediately?')) return;
                try { await api.cancelVulnScan(id); } catch (e) { /* best-effort */ }
              }}
              className="px-3 py-2 border border-amber-500/40 text-amber-400 hover:bg-amber-500/10 mono text-xs flex items-center gap-2 uppercase tracking-widest"
            >
              <StopCircle className="w-3 h-3" /> Stop
            </button>
          )}
          {filtered.length > 0 && (
            <CopyButton
              text={filtered.map(f => f.url).filter(Boolean).join('\n')}
              variant="button"
              label={`Copy ${filtered.length} URLs`}
              testid="copy-all-urls"
            />
          )}
          {filtered.length > 0 && (
            <CopyButton
              text={filtered.map(f => `[${(f.severity||'').toUpperCase()}] ${f.type}${f.subtype?' · '+f.subtype:''} | ${f.url || ''} | param=${f.param||''} | payload=${f.payload||''}`).join('\n')}
              variant="button"
              label="Copy report"
              testid="copy-report"
            />
          )}
          <button onClick={exportJson} data-testid="export-json-btn" className="px-3 py-2 border border-zinc-800 text-zinc-400 hover:text-emerald-500 hover:border-emerald-500/40 mono text-xs flex items-center gap-2">
            <Download className="w-3 h-3" /> JSON
          </button>
          <button onClick={exportCsv} data-testid="export-csv-btn" className="px-3 py-2 border border-zinc-800 text-zinc-400 hover:text-emerald-500 hover:border-emerald-500/40 mono text-xs flex items-center gap-2">
            <Download className="w-3 h-3" /> CSV
          </button>
          <a href={api.reportMdUrl(id, false)} download={`report-${id.slice(0,8)}.md`}
             data-testid="download-report-md"
             className="px-3 py-2 border border-zinc-800 text-zinc-400 hover:text-emerald-500 hover:border-emerald-500/40 mono text-xs flex items-center gap-2">
            <FileText className="w-3 h-3" /> MD Report
          </a>
          <a href={api.reportHtmlUrl(id, false)} target="_blank" rel="noreferrer"
             data-testid="download-report-html"
             className="px-3 py-2 border border-zinc-800 text-zinc-400 hover:text-emerald-500 hover:border-emerald-500/40 mono text-xs flex items-center gap-2">
            <FileText className="w-3 h-3" /> HTML Report
          </a>
          {findings.length > 0 && (
            <button
              onClick={() => runFpPredict(false)}
              disabled={fpLoading}
              data-testid="fp-predict-btn"
              className="px-3 py-2 border border-purple-500/40 text-purple-400 hover:bg-purple-500/10 mono text-xs flex items-center gap-2 uppercase tracking-widest disabled:opacity-40"
            >
              <Brain className="w-3 h-3" /> FP Predict
            </button>
          )}
          {findings.length > 0 && (
            <button
              onClick={() => runFpPredict(true)}
              disabled={fpLoading}
              data-testid="fp-predict-llm-btn"
              className="px-3 py-2 border border-fuchsia-500/40 text-fuchsia-400 hover:bg-fuchsia-500/10 mono text-xs flex items-center gap-2 uppercase tracking-widest disabled:opacity-40"
            >
              <Sparkles className="w-3 h-3" /> FP + AI
            </button>
          )}
          {findings.length > 0 && (
            <button
              onClick={runAiTriage}
              disabled={aiTriageLoading}
              data-testid="ai-triage-btn"
              className="px-3 py-2 border border-red-500/40 text-red-400 hover:bg-red-500/10 mono text-xs flex items-center gap-2 uppercase tracking-widest disabled:opacity-40"
            >
              <TargetIcon className="w-3 h-3" /> AI Triage
            </button>
          )}
          {findings.length > 0 && (
            <button
              onClick={runAiChains}
              disabled={aiChainsLoading}
              data-testid="ai-chains-v2-btn"
              className="px-3 py-2 border border-amber-500/40 text-amber-400 hover:bg-amber-500/10 mono text-xs flex items-center gap-2 uppercase tracking-widest disabled:opacity-40"
            >
              <Sparkles className="w-3 h-3" /> AI Chains
            </button>
          )}
          {findings.length > 0 && (
            <a
              href={api.burpProject(id)}
              data-testid="burp-download-btn"
              className="px-3 py-2 border border-orange-500/40 text-orange-400 hover:bg-orange-500/10 mono text-xs flex items-center gap-2 uppercase tracking-widest"
              title="Download Burp Suite project ZIP"
            >
              <Download className="w-3 h-3" /> Burp
            </a>
          )}
        </div>
      </div>

      {/* AI Triage panel */}
      {aiTriage && (
        <div data-testid="ai-triage-panel" className="mb-4 border border-red-500/30 bg-red-500/5 p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs mono uppercase tracking-widest text-red-300 flex items-center gap-2">
              <TargetIcon className="w-4 h-4" /> AI Triage · source: {aiTriage.source}
            </span>
            <button onClick={() => setAiTriage(null)} className="text-xs mono text-zinc-500 hover:text-zinc-200">close</button>
          </div>
          <div className="max-h-72 overflow-y-auto text-xs mono">
            {(aiTriage.triage || []).slice(0, 40).map((t) => (
              <div key={t.id} className="flex items-start gap-2 py-1 border-b border-zinc-800/50">
                <span className={`shrink-0 w-10 text-right ${
                  t.tier === 'P0' ? 'text-red-400' : t.tier === 'P1' ? 'text-orange-400'
                    : t.tier === 'P2' ? 'text-yellow-400' : 'text-zinc-500'}`}>{t.tier}</span>
                <span className="shrink-0 w-14 text-zinc-500">#{t.rank}</span>
                <span className="shrink-0 w-14 text-emerald-400">{t.exploitability}%</span>
                <span className="text-zinc-400 truncate flex-1">{t.rationale}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* AI Chains-v2 panel */}
      {aiChains && (
        <div data-testid="ai-chains-v2-panel" className="mb-4 border border-amber-500/30 bg-amber-500/5 p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs mono uppercase tracking-widest text-amber-300 flex items-center gap-2">
              <Sparkles className="w-4 h-4" /> AI Attack Chains · source: {aiChains.source}
            </span>
            <button onClick={() => setAiChains(null)} className="text-xs mono text-zinc-500 hover:text-zinc-200">close</button>
          </div>
          {(aiChains.chains || []).map((c, i) => (
            <div key={i} className="p-3 border border-zinc-800 bg-zinc-950 mb-2">
              <div className="flex items-center justify-between mb-1">
                <span className="text-sm text-zinc-100">{c.name}</span>
                <span className="text-[10px] mono uppercase text-red-400">{c.severity}</span>
              </div>
              <ol className="text-xs mono text-zinc-400 list-decimal list-inside space-y-1">
                {(c.steps || []).map((s, j) => <li key={j}>{s}</li>)}
              </ol>
              {c.impact && <div className="text-[10px] mono text-amber-300 mt-2">impact: {c.impact}</div>}
            </div>
          ))}
          {(!aiChains.chains || aiChains.chains.length === 0) && (
            <div className="text-xs mono text-zinc-500">No exploitable chains generated for the current findings.</div>
          )}
        </div>
      )}

      {/* FP Predictor result panel */}
      {fpResult && (
        <div
          data-testid="fp-result-panel"
          className="mb-4 border border-purple-500/30 bg-purple-500/5 p-4"
        >
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Brain className="w-4 h-4 text-purple-400" />
              <span className="text-xs mono uppercase tracking-widest text-purple-300">
                False-Positive Prediction · {fpResult.used_llm ? 'AI + Heuristic' : 'Heuristic'}
              </span>
            </div>
            <button
              onClick={() => setFpResult(null)}
              className="text-xs mono text-zinc-500 hover:text-zinc-200"
            >
              close
            </button>
          </div>
          <div className="grid grid-cols-3 gap-2 mb-3">
            <div className="p-2 border border-emerald-500/30 bg-emerald-500/5">
              <div className="text-[10px] mono uppercase text-emerald-400">Likely Real</div>
              <div className="text-2xl mono text-emerald-300">{fpResult.buckets.likely_real}</div>
            </div>
            <div className="p-2 border border-amber-500/30 bg-amber-500/5">
              <div className="text-[10px] mono uppercase text-amber-400">Manual Review</div>
              <div className="text-2xl mono text-amber-300">{fpResult.buckets.review}</div>
            </div>
            <div className="p-2 border border-red-500/30 bg-red-500/5">
              <div className="text-[10px] mono uppercase text-red-400">Likely FP</div>
              <div className="text-2xl mono text-red-300">{fpResult.buckets.likely_fp}</div>
            </div>
          </div>
          <div className="max-h-64 overflow-y-auto text-xs mono">
            {fpResult.scores.slice(0, 40).map((s) => (
              <div
                key={s.id}
                className="flex items-start gap-2 py-1 border-b border-zinc-800/50"
              >
                <span className={`shrink-0 w-14 text-right ${
                  s.bucket === 'likely_fp' ? 'text-red-400'
                    : s.bucket === 'review' ? 'text-amber-400'
                    : 'text-emerald-400'
                }`}>{(s.fp_score * 100).toFixed(0)}%</span>
                <span className="shrink-0 w-14 text-zinc-500 uppercase">{s.severity}</span>
                <span className="shrink-0 w-24 text-zinc-300 truncate">{s.type}</span>
                <span className="text-zinc-500 truncate flex-1">{s.fp_reason}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Summary grid */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-2 mb-4">
        {['critical','high','medium','low','info','unknown'].map(s => (
          <button
            key={s}
            onClick={() => setFilter(s === filter ? 'all' : s)}
            data-testid={`sev-filter-${s}`}
            className={`p-3 border transition-colors text-left ${
              filter === s
                ? `${SEVERITY_COLORS[s]} border-2`
                : 'border-zinc-800 bg-zinc-950 hover:border-zinc-700'
            }`}
          >
            <div className={`text-2xl font-bold mono ${filter === s ? '' : 'text-zinc-100'}`}>{summary[s] || 0}</div>
            <div className={`text-[9px] mono uppercase tracking-widest ${filter === s ? '' : 'text-zinc-500'}`}>{s}</div>
          </button>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-2 mb-4 border-b border-zinc-800 flex-wrap">
        {[
          { k: 'findings', l: `Findings (${filtered.length})` },
          { k: 'chains', l: `Attack Chains (${chains.length})` },
          { k: 'logs', l: `Logs (${logs.length})` },
          { k: 'recon', l: 'Recon & Ports' },
        ].map(t => (
          <button
            key={t.k}
            onClick={() => setTab(t.k)}
            data-testid={`tab-${t.k}`}
            className={`px-4 py-2 text-xs mono uppercase tracking-widest border-b-2 -mb-px ${
              tab === t.k ? 'border-emerald-500 text-emerald-500' : 'border-transparent text-zinc-500 hover:text-zinc-300'
            }`}
          >
            {t.l}
          </button>
        ))}
      </div>

      {tab === 'findings' && (
        <>
          <div className="flex items-center gap-3 mb-3 text-[10px] mono">
            <button
              onClick={() => setVerifiedOnly(!verifiedOnly)}
              data-testid="toggle-verified-only"
              className={`px-3 py-1 border uppercase tracking-widest ${
                verifiedOnly
                  ? 'border-emerald-500 bg-emerald-500/10 text-emerald-400'
                  : 'border-zinc-800 text-zinc-500 hover:text-zinc-300'
              }`}
            >
              {verifiedOnly ? '✓ Verified only' : '⚠ Showing all (incl. unverified)'}
            </button>
            {verification.total > 0 && (
              <span className="text-zinc-500">
                <span className="text-emerald-400">{verification.verified}</span> verified ·{' '}
                <span className="text-yellow-400">{verification.unverified}</span> unverified ·{' '}
                <span className="text-zinc-400">{verification.total}</span> total
              </span>
            )}
          </div>
          {typeSet.length > 0 && (
            <div className="flex flex-wrap gap-2 mb-3">
              <button
                onClick={() => setTypeFilter('')}
                className={`px-2 py-1 text-[10px] mono uppercase tracking-widest border ${
                  !typeFilter ? 'border-emerald-500 text-emerald-500' : 'border-zinc-800 text-zinc-500 hover:text-zinc-300'
                }`}
              >
                all types
              </button>
              {typeSet.map(t => (
                <button
                  key={t}
                  onClick={() => setTypeFilter(t === typeFilter ? '' : t)}
                  className={`px-2 py-1 text-[10px] mono uppercase tracking-widest border ${
                    typeFilter === t ? 'border-emerald-500 text-emerald-500' : 'border-zinc-800 text-zinc-500 hover:text-zinc-300'
                  }`}
                >
                  {t}
                </button>
              ))}
            </div>
          )}
          <div className="space-y-2" data-testid="findings-list">
            {filtered.length === 0 ? (
              <div className="border border-zinc-800 bg-zinc-950 p-8 text-center text-xs mono text-zinc-500">
                {running ? 'Scan running — findings will appear here in real time...' : 'No findings match current filter.'}
              </div>
            ) : (
              filtered.map((f, i) => {
                // v7.6.1 · Match FP score by stable content key (type+subtype+url+param)
                // — positional indices break when the backend dedupes findings.
                let fpScore = null;
                if (fpResult && Array.isArray(fpResult.scores)) {
                  const contentKey = [
                    f.type || '', f.subtype || '', f.url || '', f.param || '',
                  ].join('|');
                  const hit = fpResult.scores.find((s) => s.key === contentKey);
                  if (hit) fpScore = hit.fp_score;
                }
                return (
                  <FindingCard
                    key={`${f.type || 'x'}-${f.subtype || ''}-${f.url || ''}-${f.param || ''}-${i}`}
                    f={f}
                    idx={i}
                    scanId={id}
                    fpScore={fpScore}
                    onExplain={(fi, ff) => setAiExplain({ idx: fi, finding: ff })}
                    onCopyCurl={copyAsCurl}
                  />
                );
              })
            )}
          </div>
        </>
      )}

      {tab === 'logs' && (
        <LogViewer logs={logs} emptyText="No logs yet." />
      )}

      {tab === 'chains' && (
        <div className="space-y-4" data-testid="attack-chains">
          {chains.length === 0 ? (
            <div className="border border-zinc-800 bg-zinc-950 p-8 text-center text-xs mono text-zinc-500">
              No attack chains detected. Chains form when multiple related VERIFIED findings combine into a realistic exploitation sequence.
            </div>
          ) : (
            chains.map((c, i) => (
              <div key={c.id} data-testid={`chain-${c.id}`} className="border border-red-500/40 bg-gradient-to-br from-red-500/10 via-zinc-950 to-zinc-950 p-5">
                <div className="flex items-start justify-between gap-4 flex-wrap mb-3">
                  <div>
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <span className="inline-block px-2 py-0.5 text-[10px] mono uppercase tracking-widest border border-red-500/50 text-red-400 bg-red-500/10">
                        {c.severity}
                      </span>
                      <span className="text-[10px] mono text-emerald-500">CVSS {c.cvss}</span>
                      <span className="text-[10px] mono text-zinc-500">conf {c.confidence}%</span>
                    </div>
                    <h3 className="text-base font-semibold text-zinc-50">{c.name}</h3>
                  </div>
                  <CopyButton
                    text={`${c.name}\n\nSteps:\n${c.steps.map((s, j) => `${j + 1}. ${s}`).join('\n')}\n\nMitigation:\n${c.mitigation.map(m => `- ${m}`).join('\n')}`}
                    variant="button"
                    label="Copy chain"
                    testid={`copy-chain-${c.id}`}
                  />
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs mono">
                  <div className="md:col-span-2 space-y-3">
                    <div>
                      <div className="text-[10px] uppercase tracking-widest text-emerald-500 mb-2">Exploit Sequence</div>
                      <ol className="space-y-2">
                        {c.steps.map((s, si) => (
                          <li key={si} className="flex gap-3">
                            <span className="shrink-0 w-6 h-6 border border-red-500/40 bg-red-500/10 text-red-400 flex items-center justify-center text-[10px] font-bold">
                              {si + 1}
                            </span>
                            <span className="text-zinc-300 leading-relaxed pt-0.5">{s}</span>
                          </li>
                        ))}
                      </ol>
                    </div>
                    <div>
                      <div className="text-[10px] uppercase tracking-widest text-emerald-500 mb-2">Mitigation</div>
                      <ul className="space-y-1 pl-2 border-l border-emerald-500/20">
                        {c.mitigation.map((m, mi) => (
                          <li key={mi} className="text-zinc-400 leading-relaxed">→ {m}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] uppercase tracking-widest text-emerald-500 mb-2">Triggering findings ({c.triggering_findings.length})</div>
                    <div className="space-y-2">
                      {c.triggering_findings.map((t, ti) => (
                        <div key={ti} className="border border-zinc-800 bg-zinc-950 p-2 text-[10px]">
                          <div className="text-red-400 mb-0.5">{t.type} · {t.subtype || 'n/a'}</div>
                          <div className="text-zinc-500 truncate">{t.url}</div>
                          {t.param && <div className="text-zinc-400">param: {t.param}</div>}
                        </div>
                      ))}
                    </div>
                    {c.boosters?.length > 0 && (
                      <>
                        <div className="text-[10px] uppercase tracking-widest text-yellow-500 mb-2 mt-3">Boosters ({c.boosters.length})</div>
                        <div className="space-y-1">
                          {c.boosters.map((b, bi) => (
                            <div key={bi} className="text-[10px] text-yellow-400/80 border border-yellow-500/20 bg-yellow-500/5 p-1.5">
                              {b.type} · {b.subtype || 'n/a'}
                            </div>
                          ))}
                        </div>
                      </>
                    )}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {tab === 'recon' && (
        <div className="space-y-4">
          <div className="border border-zinc-800 bg-zinc-950 p-4">
            <div className="text-xs mono uppercase tracking-widest text-emerald-500 mb-3">Fingerprint</div>
            {scan?.fingerprint ? (
              <div className="text-xs mono text-zinc-300 space-y-1">
                <div>WAF: <span className="text-red-400">{scan.fingerprint.waf || 'none'}</span></div>
                <div>Server: <span className="text-zinc-100">{scan.fingerprint.server || 'unknown'}</span></div>
                <div>CMS: <span className="text-zinc-100">{scan.fingerprint.cms || 'none'}</span></div>
                <div>Cloud: <span className="text-zinc-100">{scan.fingerprint.cloud || 'unknown'}</span></div>
                <div>Frameworks: <span className="text-emerald-500">{(scan.fingerprint.frameworks || []).join(', ') || 'none'}</span></div>
                <div>JS libs: <span className="text-emerald-500">{(scan.fingerprint.js_libs || []).join(', ') || 'none'}</span></div>
                <div>Techs: <span className="text-zinc-400">{(scan.fingerprint.techs || []).join(', ') || '—'}</span></div>
                <div>DBMS guess: <span className="text-yellow-400">{(scan.fingerprint.probable_dbms || []).join(', ') || 'unknown'}</span></div>
              </div>
            ) : (
              <div className="text-xs mono text-zinc-500">no fingerprint yet</div>
            )}
          </div>
          <div className="border border-zinc-800 bg-zinc-950 p-4">
            <div className="text-xs mono uppercase tracking-widest text-emerald-500 mb-3">Recon Summary</div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs mono">
              <div>URLs discovered: <span className="text-emerald-500">{reconSummary.urls_discovered || 0}</span></div>
              <div>Content paths: <span className="text-emerald-500">{reconSummary.content_discovery || 0}</span></div>
              <div>JS secrets: <span className="text-red-400">{reconSummary.js_findings_secrets || 0}</span></div>
              <div>Forms: <span className="text-emerald-500">{reconSummary.forms_count || 0}</span></div>
              <div>Crawler pages: <span className="text-emerald-500">{reconSummary.crawler_pages || 0}</span></div>
              <div>Crawler endpoints: <span className="text-emerald-500">{reconSummary.crawler_endpoints || 0}</span></div>
              <div>Crawler params: <span className="text-emerald-500">{reconSummary.crawler_params || 0}</span></div>
              <div>Sitemap URLs: <span className="text-emerald-500">{reconSummary.sitemap_urls || 0}</span></div>
            </div>
          </div>
          {ports.length > 0 && (
            <div className="border border-zinc-800 bg-zinc-950 p-4">
              <div className="text-xs mono uppercase tracking-widest text-emerald-500 mb-3">Open Ports</div>
              <div className="flex flex-wrap gap-2">
                {ports.map(p => (
                  <span key={p} className="px-2 py-1 border border-emerald-500/40 bg-emerald-500/5 text-emerald-500 mono text-xs">
                    {p}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {aiExplain && (
        <AIExplainModal
          scanId={id}
          findingIndex={aiExplain.idx}
          finding={aiExplain.finding}
          onClose={() => setAiExplain(null)}
        />
      )}
    </div>
  );
}
