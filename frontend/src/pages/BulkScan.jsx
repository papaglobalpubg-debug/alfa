import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '@/lib/api';
import { Upload, Zap, X, Plus } from 'lucide-react';

export default function BulkScan() {
  const nav = useNavigate();
  const [text, setText] = useState('');
  const [threads, setThreads] = useState(20);
  const [timeout, setTimeoutS] = useState(15);
  const [verify, setVerify] = useState(true);
  const [notify, setNotify] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  const domains = Array.from(new Set(
    text.split('\n').map((l) => l.trim().toLowerCase())
      .filter((l) => l && !l.startsWith('#') && /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(l))
  ));

  const submit = async (e) => {
    e.preventDefault();
    if (!domains.length) {
      setError('No valid domains found');
      return;
    }
    setError('');
    setSubmitting(true);
    try {
      const { data } = await api.createBulkScan({
        domains, threads: Number(threads), timeout: Number(timeout),
        verify, notify,
      });
      nav(`/history?bulk=${data.scan_ids.slice(0, 3).join(',')}`);
    } catch (err) {
      setError(err?.response?.data?.detail || err.message);
    } finally {
      setSubmitting(false);
    }
  };

  const onFile = (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = () => setText(String(reader.result || ''));
    reader.readAsText(f);
  };

  return (
    <div data-testid="bulk-scan-container" className="max-w-4xl space-y-6">
      <header>
        <h1 className="text-2xl font-display font-bold text-zinc-50 tracking-tight">
          <span className="text-emerald-500">&gt;</span> Bulk Scan
        </h1>
        <p className="text-zinc-500 text-sm mt-1 mono">
          Scan up to 100 domains in parallel. One domain per line.
        </p>
      </header>

      <form onSubmit={submit} className="space-y-4">
        <div className="bg-zinc-900 border border-zinc-800 p-5">
          <div className="flex items-center justify-between mb-2">
            <div className="text-xs uppercase tracking-widest text-zinc-500 mono">
              Domains ({domains.length} valid)
            </div>
            <label className="flex items-center gap-1 text-xs text-zinc-400 hover:text-emerald-500 cursor-pointer mono">
              <Upload className="w-3 h-3" />
              Upload .txt
              <input data-testid="bulk-scan-file-input" type="file" accept=".txt,.csv" onChange={onFile} className="hidden" />
            </label>
          </div>
          <textarea
            data-testid="bulk-scan-domains-textarea"
            value={text}
            onChange={(e) => setText(e.target.value)}
            rows={12}
            placeholder={"example.com\nsubcompany.example.com\nanother-target.com\n..."}
            className="w-full px-3 py-2 bg-black border border-zinc-800 text-zinc-300 mono text-xs focus:outline-none focus:border-emerald-500"
          />
          {domains.length > 100 && (
            <div className="text-red-400 mono text-xs mt-2">
              ! Max 100 domains allowed. Only first 100 will be scanned.
            </div>
          )}
        </div>

        <div className="bg-zinc-900 border border-zinc-800 p-5 grid grid-cols-2 gap-4">
          <label className="block">
            <div className="text-xs uppercase tracking-widest text-zinc-500 mono mb-2">
              Threads (per scan)
            </div>
            <input
              data-testid="bulk-scan-threads"
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
              data-testid="bulk-scan-timeout"
              type="number" min="1" max="60" value={timeout}
              onChange={(e) => setTimeoutS(e.target.value)}
              className="w-full px-3 py-2 bg-black border border-zinc-800 text-zinc-50 mono focus:outline-none focus:border-emerald-500"
            />
          </label>
          <label className="flex items-center gap-2 cursor-pointer col-span-2">
            <input data-testid="bulk-scan-verify" type="checkbox" checked={verify}
              onChange={(e) => setVerify(e.target.checked)} className="w-4 h-4 accent-emerald-500" />
            <span className="text-sm text-zinc-300 mono">Active verification</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer col-span-2">
            <input data-testid="bulk-scan-notify" type="checkbox" checked={notify}
              onChange={(e) => setNotify(e.target.checked)} className="w-4 h-4 accent-emerald-500" />
            <span className="text-sm text-zinc-300 mono">Webhook notifications on findings</span>
          </label>
        </div>

        {error && (
          <div className="bg-red-500/10 border border-red-500/30 text-red-400 px-4 py-2 mono text-sm">
            {error}
          </div>
        )}

        <div className="flex justify-end gap-2">
          <button
            data-testid="bulk-scan-cancel"
            type="button" onClick={() => nav('/')}
            className="px-4 py-2 border border-zinc-800 text-zinc-400 hover:text-zinc-50 hover:border-zinc-700 mono text-sm"
          >
            Cancel
          </button>
          <button
            data-testid="bulk-scan-submit"
            type="submit"
            disabled={submitting || !domains.length}
            className="flex items-center gap-2 px-6 py-2 bg-emerald-500 text-zinc-950 font-semibold hover:bg-emerald-400 disabled:opacity-50 mono text-sm"
          >
            <Zap className="w-4 h-4" />
            {submitting ? 'Queuing...' : `Launch ${domains.length} scan${domains.length !== 1 ? 's' : ''}`}
          </button>
        </div>
      </form>
    </div>
  );
}
