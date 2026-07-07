import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '@/lib/api';
import { NEW_SCAN } from '@/constants/testIds';
import { Zap, ChevronDown } from 'lucide-react';

const DEFAULT_SRC = [
  'crt', 'hackertarget', 'otx', 'rapiddns', 'urlscan', 'commoncrawl',
  'bufferover', 'anubis', 'jldc', 'wayback', 'certspotter', 'digitorus',
  'threatminer', 'dnsdumpster', 'bruteforce', 'permutation', 'tls_san',
];

export default function NewScan() {
  const nav = useNavigate();
  const [domain, setDomain] = useState('');
  const [threads, setThreads] = useState(20);
  const [timeout, setTimeoutS] = useState(15);
  const [verify, setVerify] = useState(true);
  const [notify, setNotify] = useState(false);
  const [wordlist, setWordlist] = useState('');
  const [sources, setSources] = useState([]);
  const [freeSrc, setFreeSrc] = useState([]);
  const [keySrc, setKeySrc] = useState([]);
  const [advanced, setAdvanced] = useState(false);
  const [selected, setSelected] = useState(new Set(DEFAULT_SRC));
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    api.sources().then(({ data }) => {
      setFreeSrc(data.free || []);
      setKeySrc(data.with_api_key || []);
      setSources([...(data.free || []), ...(data.with_api_key || [])]);
    });
  }, []);

  const toggleSrc = (s) => {
    setSelected((prev) => {
      const n = new Set(prev);
      if (n.has(s)) n.delete(s);
      else n.add(s);
      return n;
    });
  };

  const submit = async (e) => {
    e.preventDefault();
    if (!domain.trim()) {
      setError('Domain is required');
      return;
    }
    setError('');
    setSubmitting(true);
    try {
      const payload = {
        domain: domain.trim().toLowerCase(),
        sources: Array.from(selected),
        threads: Number(threads),
        timeout: Number(timeout),
        verify,
        notify,
        wordlist_content: wordlist.trim() || null,
      };
      const { data } = await api.createScan(payload);
      nav(`/scan/${data.scan_id}`);
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || 'Failed to create scan');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div data-testid={NEW_SCAN.container} className="max-w-4xl space-y-6">
      <header>
        <h1 className="text-2xl font-display font-bold text-zinc-50 tracking-tight">
          <span className="text-emerald-500">&gt;</span> New Scan
        </h1>
        <p className="text-zinc-500 text-sm mt-1 mono">
          Launch subdomain reconnaissance and takeover detection
        </p>
      </header>

      <form onSubmit={submit} className="space-y-4">
        <div className="bg-zinc-900 border border-zinc-800 p-5">
          <label className="block">
            <div className="text-xs uppercase tracking-widest text-zinc-500 mono mb-2">
              Target Domain
            </div>
            <input
              data-testid={NEW_SCAN.domainInput}
              type="text"
              autoFocus
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="example.com"
              className="w-full px-3 py-2 bg-black border border-zinc-800 text-zinc-50 mono focus:outline-none focus:border-emerald-500 transition-colors placeholder:text-zinc-700"
            />
            <p className="text-xs text-zinc-600 mono mt-2">
              Do not include http(s)://, port, or path. Wildcards not required.
            </p>
          </label>
        </div>

        <div className="bg-zinc-900 border border-zinc-800 p-5">
          <div className="text-xs uppercase tracking-widest text-zinc-500 mono mb-3">
            Discovery Sources ({selected.size} / {sources.length})
          </div>

          <div className="mb-3">
            <div className="text-xs text-zinc-400 mb-1">Free Sources</div>
            <div className="flex flex-wrap gap-1.5">
              {freeSrc.map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => toggleSrc(s)}
                  data-testid={`src-${s}`}
                  className={`px-2 py-1 text-xs mono border transition-colors ${
                    selected.has(s)
                      ? 'bg-emerald-500/10 border-emerald-500/50 text-emerald-400'
                      : 'bg-zinc-950 border-zinc-800 text-zinc-500 hover:text-zinc-300 hover:border-zinc-700'
                  }`}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>

          <div>
            <div className="text-xs text-zinc-400 mb-1">API-key Required (configure in Settings)</div>
            <div className="flex flex-wrap gap-1.5">
              {keySrc.map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => toggleSrc(s)}
                  data-testid={`src-${s}`}
                  className={`px-2 py-1 text-xs mono border transition-colors ${
                    selected.has(s)
                      ? 'bg-blue-500/10 border-blue-500/50 text-blue-400'
                      : 'bg-zinc-950 border-zinc-800 text-zinc-500 hover:text-zinc-300 hover:border-zinc-700'
                  }`}
                >
                  {s} <span className="text-zinc-700">*</span>
                </button>
              ))}
            </div>
          </div>

          <div className="mt-4 pt-4 border-t border-zinc-800 flex gap-2">
            <button type="button"
              onClick={() => setSelected(new Set(sources))}
              className="text-xs px-2 py-1 border border-zinc-800 text-zinc-400 hover:text-zinc-50 hover:border-zinc-700 mono">
              Select all
            </button>
            <button type="button"
              onClick={() => setSelected(new Set(DEFAULT_SRC))}
              className="text-xs px-2 py-1 border border-zinc-800 text-zinc-400 hover:text-zinc-50 hover:border-zinc-700 mono">
              Recommended
            </button>
            <button type="button"
              onClick={() => setSelected(new Set())}
              className="text-xs px-2 py-1 border border-zinc-800 text-zinc-400 hover:text-zinc-50 hover:border-zinc-700 mono">
              Clear
            </button>
          </div>
        </div>

        <div className="bg-zinc-900 border border-zinc-800">
          <button type="button"
            onClick={() => setAdvanced(!advanced)}
            className="w-full text-left px-5 py-3 flex items-center justify-between hover:bg-zinc-800/50 transition-colors">
            <span className="text-xs uppercase tracking-widest text-zinc-400 mono">
              Advanced Options
            </span>
            <ChevronDown className={`w-4 h-4 text-zinc-500 transition-transform ${advanced ? 'rotate-180' : ''}`} />
          </button>
          {advanced && (
            <div className="p-5 border-t border-zinc-800 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <label className="block">
                  <div className="text-xs uppercase tracking-widest text-zinc-500 mono mb-2">
                    Threads
                  </div>
                  <input
                    data-testid={NEW_SCAN.threadsInput}
                    type="number" min="1" max="100" value={threads}
                    onChange={(e) => setThreads(e.target.value)}
                    className="w-full px-3 py-2 bg-black border border-zinc-800 text-zinc-50 mono focus:outline-none focus:border-emerald-500"
                  />
                </label>
                <label className="block">
                  <div className="text-xs uppercase tracking-widest text-zinc-500 mono mb-2">
                    Timeout (s)
                  </div>
                  <input
                    data-testid={NEW_SCAN.timeoutInput}
                    type="number" min="1" max="60" value={timeout}
                    onChange={(e) => setTimeoutS(e.target.value)}
                    className="w-full px-3 py-2 bg-black border border-zinc-800 text-zinc-50 mono focus:outline-none focus:border-emerald-500"
                  />
                </label>
              </div>

              <div className="flex gap-6">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    data-testid={NEW_SCAN.verifyToggle}
                    type="checkbox" checked={verify}
                    onChange={(e) => setVerify(e.target.checked)}
                    className="w-4 h-4 accent-emerald-500"
                  />
                  <span className="text-sm text-zinc-300 mono">Active verification</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    data-testid={NEW_SCAN.notifyToggle}
                    type="checkbox" checked={notify}
                    onChange={(e) => setNotify(e.target.checked)}
                    className="w-4 h-4 accent-emerald-500"
                  />
                  <span className="text-sm text-zinc-300 mono">Webhook notifications</span>
                </label>
              </div>

              <label className="block">
                <div className="text-xs uppercase tracking-widest text-zinc-500 mono mb-2">
                  Custom Wordlist (one prefix per line)
                </div>
                <textarea
                  data-testid={NEW_SCAN.wordlistTextarea}
                  value={wordlist}
                  onChange={(e) => setWordlist(e.target.value)}
                  rows={6}
                  placeholder={"admin\napi\nstaging\n..."}
                  className="w-full px-3 py-2 bg-black border border-zinc-800 text-zinc-300 mono text-xs focus:outline-none focus:border-emerald-500"
                />
              </label>
            </div>
          )}
        </div>

        {error && (
          <div className="bg-red-500/10 border border-red-500/30 text-red-400 px-4 py-2 mono text-sm">
            {error}
          </div>
        )}

        <div className="flex justify-end gap-2">
          <button
            data-testid={NEW_SCAN.cancelBtn}
            type="button"
            onClick={() => nav('/')}
            className="px-4 py-2 border border-zinc-800 text-zinc-400 hover:text-zinc-50 hover:border-zinc-700 mono text-sm transition-colors"
          >
            Cancel
          </button>
          <button
            data-testid={NEW_SCAN.submitBtn}
            type="submit"
            disabled={submitting || !domain.trim()}
            className="flex items-center gap-2 px-6 py-2 bg-emerald-500 text-zinc-950 font-semibold hover:bg-emerald-400 disabled:opacity-50 disabled:cursor-not-allowed mono text-sm transition-colors"
          >
            <Zap className="w-4 h-4" />
            {submitting ? 'Starting...' : 'Start Scan'}
          </button>
        </div>
      </form>
    </div>
  );
}
