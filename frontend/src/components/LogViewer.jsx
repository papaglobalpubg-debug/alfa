import React, { useState, useMemo, useRef, useEffect } from 'react';
import { Search, Download, Pause, Play, Filter } from 'lucide-react';

const LEVEL_PATTERNS = [
  { key: 'error',   label: 'Errors',   match: /ERROR|\[!\]|FATAL|CRITICAL/i, color: 'text-red-400 bg-red-500/5' },
  { key: 'warn',    label: 'Warnings', match: /\bWARN|WARNING|timeout|timed out/i, color: 'text-yellow-300 bg-yellow-500/5' },
  { key: 'success', label: 'Success',  match: /\[\+\]|OK|completed|saved/i, color: 'text-emerald-400 bg-emerald-500/5' },
  { key: 'info',    label: 'Info',     match: /\[\*\]|recon|fingerprint|scanning|launched/i, color: 'text-zinc-300' },
];

function detectLevel(line) {
  for (const p of LEVEL_PATTERNS) {
    if (p.match.test(line)) return p.key;
  }
  return 'info';
}

function levelColor(level) {
  const p = LEVEL_PATTERNS.find(x => x.key === level);
  return p ? p.color : 'text-zinc-300';
}

export default function LogViewer({ logs = [], emptyText = 'No logs yet.' }) {
  const [query, setQuery] = useState('');
  const [levelFilter, setLevelFilter] = useState('all');
  const [autoScroll, setAutoScroll] = useState(true);
  const containerRef = useRef(null);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return logs.filter(line => {
      if (q && !line.toLowerCase().includes(q)) return false;
      if (levelFilter !== 'all' && detectLevel(line) !== levelFilter) return false;
      return true;
    });
  }, [logs, query, levelFilter]);

  useEffect(() => {
    if (!autoScroll || !containerRef.current) return;
    containerRef.current.scrollTop = containerRef.current.scrollHeight;
  }, [filtered, autoScroll]);

  const copyAll = async () => {
    try { await navigator.clipboard.writeText(filtered.join('\n')); } catch (_e) {}
  };

  const downloadTxt = () => {
    const blob = new Blob([filtered.join('\n')], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cyberscope-logs-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="border border-zinc-800 bg-zinc-950" data-testid="enhanced-log-viewer">
      <div className="flex flex-wrap items-center gap-2 p-2 border-b border-zinc-800 bg-zinc-900/40">
        <div className="relative flex-1 min-w-[180px]">
          <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-zinc-500" />
          <input type="text" value={query} onChange={e => setQuery(e.target.value)}
            placeholder="Search logs..."
            className="w-full pl-7 pr-2 py-1.5 bg-zinc-950 border border-zinc-800 text-xs text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-zinc-600"
            data-testid="log-search" />
        </div>
        <div className="flex items-center gap-1">
          <Filter className="w-3.5 h-3.5 text-zinc-500" />
          <button onClick={() => setLevelFilter('all')}
            className={`px-2 py-1 text-[10px] mono uppercase tracking-wider border ${levelFilter === 'all' ? 'border-zinc-400 text-zinc-200 bg-zinc-800' : 'border-zinc-800 text-zinc-500 hover:text-zinc-300'}`}
            data-testid="log-filter-all">All</button>
          {LEVEL_PATTERNS.map(p => (
            <button key={p.key} onClick={() => setLevelFilter(p.key)}
              className={`px-2 py-1 text-[10px] mono uppercase tracking-wider border ${levelFilter === p.key ? 'border-zinc-400 text-zinc-200 bg-zinc-800' : 'border-zinc-800 text-zinc-500 hover:text-zinc-300'}`}
              data-testid={`log-filter-${p.key}`}>{p.label}</button>
          ))}
        </div>
        <div className="flex items-center gap-1">
          <button onClick={() => setAutoScroll(v => !v)}
            className={`px-2 py-1 text-[10px] mono uppercase tracking-wider border ${autoScroll ? 'border-emerald-500/50 text-emerald-400 bg-emerald-500/10' : 'border-zinc-800 text-zinc-500 hover:text-zinc-300'}`}
            data-testid="log-autoscroll">
            {autoScroll ? <Play className="w-3 h-3 inline" /> : <Pause className="w-3 h-3 inline" />}
            <span className="ml-1">{autoScroll ? 'Live' : 'Paused'}</span>
          </button>
          <button onClick={copyAll} className="px-2 py-1 text-[10px] mono uppercase tracking-wider border border-zinc-800 text-zinc-500 hover:text-zinc-300" data-testid="log-copy">Copy</button>
          <button onClick={downloadTxt} className="px-2 py-1 text-[10px] mono uppercase tracking-wider border border-zinc-800 text-zinc-500 hover:text-zinc-300" data-testid="log-download"><Download className="w-3 h-3 inline" /><span className="ml-1">Save</span></button>
        </div>
      </div>
      <div className="flex items-center gap-3 px-3 py-1 text-[10px] mono text-zinc-600 border-b border-zinc-900 bg-zinc-950">
        <span data-testid="log-count">{filtered.length} / {logs.length} lines</span>
        {query && <span>query: "{query}"</span>}
        {levelFilter !== 'all' && <span>filter: {levelFilter}</span>}
      </div>
      <div ref={containerRef} className="p-3 mono text-xs max-h-[600px] overflow-y-auto space-y-0.5" data-testid="log-lines">
        {filtered.length === 0 ? (
          <div className="text-zinc-600">{emptyText}</div>
        ) : (
          filtered.map((l, i) => {
            const level = detectLevel(l);
            return <div key={`log-${i}-${l.slice(0, 20)}`} className={`${levelColor(level)} px-1`}>{l}</div>;
          })
        )}
      </div>
    </div>
  );
}
