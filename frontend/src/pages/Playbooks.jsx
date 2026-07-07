import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import api from '@/lib/api';
import { PriorityBadge } from '@/components/Badges';
import { BookOpen, ExternalLink, Copy, Check, Terminal, ShieldAlert } from 'lucide-react';

function CopyButton({ text, testid }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <button
      data-testid={testid}
      onClick={copy}
      className="px-2 py-1 text-[10px] mono border border-zinc-800 text-zinc-400 hover:text-emerald-500 hover:border-emerald-500/50 transition-colors"
    >
      {copied ? <Check className="w-3 h-3 inline" /> : <Copy className="w-3 h-3 inline" />}
      {copied ? ' Copied' : ' Copy'}
    </button>
  );
}

export default function Playbooks() {
  const [items, setItems] = useState([]);
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState(null);
  const [q, setQ] = useState('');
  const [loading, setLoading] = useState(true);
  const [searchParams] = useSearchParams();
  const nav = useNavigate();

  useEffect(() => {
    api.listPlaybooks().then(({ data }) => {
      setItems(data.playbooks || []);
      setLoading(false);
      const svcParam = searchParams.get('service');
      if (svcParam) setSelected(svcParam);
      else if (data.playbooks?.length) setSelected(data.playbooks[0].key);
    });
  }, []);

  useEffect(() => {
    if (!selected) return;
    setDetail(null);
    api.getPlaybook(selected).then(({ data }) => setDetail(data));
  }, [selected]);

  const filtered = items.filter(
    (i) => !q || i.service_name.toLowerCase().includes(q.toLowerCase()) || i.key.toLowerCase().includes(q.toLowerCase())
  );

  return (
    <div data-testid="playbooks-container" className="space-y-6 max-w-7xl">
      <header>
        <h1 className="text-2xl font-display font-bold text-zinc-50 tracking-tight flex items-center gap-3">
          <BookOpen className="w-6 h-6 text-emerald-500" strokeWidth={1.5} />
          Exploitation Playbooks
        </h1>
        <p className="text-zinc-500 text-sm mt-1 mono">
          {items.length} attack playbooks with PoC, CVSS scoring, and Bug Bounty report templates
        </p>
      </header>

      {loading ? (
        <div className="text-zinc-600 mono p-8">Loading playbooks...</div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
          {/* Sidebar list */}
          <div className="lg:col-span-1 bg-zinc-900 border border-zinc-800 p-3 max-h-[80vh] overflow-y-auto">
            <input
              data-testid="playbooks-search"
              type="text"
              placeholder="filter..."
              value={q}
              onChange={(e) => setQ(e.target.value)}
              className="w-full px-2 py-1 bg-black border border-zinc-800 mono text-xs text-zinc-300 focus:outline-none focus:border-emerald-500 mb-3"
            />
            <ul className="space-y-1">
              {filtered.map((p) => (
                <li key={p.key}>
                  <button
                    data-testid={`playbook-item-${p.key}`}
                    onClick={() => setSelected(p.key)}
                    className={`w-full text-left px-2 py-1.5 mono text-xs transition-colors ${
                      selected === p.key
                        ? 'bg-emerald-500/10 text-emerald-400 border-l-2 border-emerald-500'
                        : 'text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800 border-l-2 border-transparent'
                    }`}
                  >
                    <div className="flex justify-between items-center">
                      <span className="truncate">{p.service_name}</span>
                      <PriorityBadge priority={p.severity} />
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          </div>

          {/* Detail */}
          <div className="lg:col-span-3 space-y-4">
            {detail ? (
              <>
                <div className="bg-zinc-900 border border-zinc-800 p-5">
                  <div className="flex items-center justify-between mb-2">
                    <h2 className="text-xl font-display font-bold text-zinc-50 tracking-tight flex items-center gap-2">
                      <ShieldAlert className="w-5 h-5 text-red-500" strokeWidth={1.5} />
                      {detail.service_name}
                    </h2>
                    <PriorityBadge priority={detail.severity} />
                  </div>
                  <div className="flex gap-4 mono text-xs text-zinc-400 mb-3">
                    <span><span className="text-zinc-600">CVSS:</span> <span className="text-emerald-500">{detail.cvss_base}</span></span>
                    <span><span className="text-zinc-600">CWE:</span> {detail.cwe.join(', ')}</span>
                    <span><span className="text-zinc-600">Vector:</span> {detail.cvss_vector}</span>
                  </div>
                  <div className="text-zinc-300 text-sm bg-red-500/10 border-l-2 border-red-500 p-3 mono">
                    <b>Impact:</b> {detail.impact_summary}
                  </div>
                </div>

                <div className="bg-zinc-900 border border-zinc-800 p-5">
                  <h3 className="text-sm uppercase tracking-widest text-zinc-500 mono mb-3 flex items-center gap-2">
                    <BookOpen className="w-4 h-4" /> Explanation
                  </h3>
                  <div className="prose prose-invert prose-sm max-w-none mono text-xs text-zinc-300 whitespace-pre-wrap">
                    {detail.explanation}
                  </div>
                </div>

                <div className="bg-zinc-900 border border-zinc-800 p-5">
                  <h3 className="text-sm uppercase tracking-widest text-zinc-500 mono mb-3 flex items-center gap-2">
                    <Terminal className="w-4 h-4" /> Exploitation Steps
                  </h3>
                  <ol className="space-y-4">
                    {(detail.exploitation_steps || []).map((s, i) => (
                      <li key={`step-${i}-${(s.title || '').slice(0, 30)}`} className="border-l-2 border-emerald-500/40 pl-4">
                        <div className="flex items-center justify-between mb-1">
                          <div className="text-sm text-zinc-50 font-semibold mono">{s.title}</div>
                          {s.command && <CopyButton text={s.command} testid={`copy-step-${i}`} />}
                        </div>
                        {s.command && (
                          <pre className="bg-black text-emerald-500 p-3 text-xs overflow-x-auto mono border border-zinc-800">
                            {s.command}
                          </pre>
                        )}
                        {s.expected_output && (
                          <div className="text-xs mono text-zinc-500 mt-1">
                            <span className="text-zinc-600">expected:</span> {s.expected_output}
                          </div>
                        )}
                        {s.notes && (
                          <div className="text-xs mono text-zinc-500 mt-1 italic">// {s.notes}</div>
                        )}
                      </li>
                    ))}
                  </ol>
                </div>

                {Object.keys(detail.poc_snippets || {}).length > 0 && (
                  <div className="bg-zinc-900 border border-zinc-800 p-5">
                    <h3 className="text-sm uppercase tracking-widest text-zinc-500 mono mb-3">
                      PoC Snippets
                    </h3>
                    {Object.entries(detail.poc_snippets).map(([tool, code]) => (
                      <div key={tool} className="mb-3">
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-xs text-emerald-500 mono uppercase">{tool}</span>
                          <CopyButton text={code} testid={`copy-poc-${tool}`} />
                        </div>
                        <pre className="bg-black text-emerald-500 p-3 text-xs overflow-x-auto mono border border-zinc-800 whitespace-pre-wrap">
                          {code}
                        </pre>
                      </div>
                    ))}
                  </div>
                )}

                <div className="bg-zinc-900 border border-zinc-800 p-5">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-sm uppercase tracking-widest text-zinc-500 mono">
                      Bug Bounty Report Template
                    </h3>
                    <CopyButton text={detail.report_template} testid="copy-report" />
                  </div>
                  <pre className="bg-black text-zinc-300 p-3 text-xs overflow-x-auto mono border border-zinc-800 whitespace-pre-wrap max-h-96 overflow-y-auto">
                    {detail.report_template}
                  </pre>
                </div>

                <div className="bg-zinc-900 border border-zinc-800 p-5">
                  <h3 className="text-sm uppercase tracking-widest text-zinc-500 mono mb-3">
                    Remediation (for defenders)
                  </h3>
                  <div className="mono text-xs text-zinc-300 whitespace-pre-wrap bg-emerald-500/5 border-l-2 border-emerald-500 p-3">
                    {detail.remediation}
                  </div>
                </div>

                <div className="bg-zinc-900 border border-zinc-800 p-5">
                  <h3 className="text-sm uppercase tracking-widest text-zinc-500 mono mb-3">References</h3>
                  <ul className="space-y-2">
                    {(detail.references || []).map((r, i) => (
                      <li key={`ref-${i}-${r.url || r.title || ''}`}>
                        <a href={r.url} target="_blank" rel="noreferrer"
                          className="flex items-center gap-1 text-emerald-500 hover:text-emerald-400 mono text-xs">
                          <ExternalLink className="w-3 h-3" /> {r.title}
                        </a>
                      </li>
                    ))}
                  </ul>
                </div>
              </>
            ) : (
              <div className="text-zinc-600 mono p-8 text-center bg-zinc-900 border border-zinc-800">
                Loading playbook...
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
