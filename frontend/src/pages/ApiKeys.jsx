import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import api from '@/lib/api';
import HelpTip from '@/components/HelpTip';
import {
  KeyRound, Plus, Trash2, Copy, ShieldCheck, XCircle, Download,
  Lock, CheckCircle2,
} from 'lucide-react';

export default function ApiKeys() {
  const { t } = useTranslation();
  const [keys, setKeys] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [name, setName] = useState('');
  const [justCreated, setJustCreated] = useState(null);

  const refresh = async () => {
    setLoading(true); setError('');
    try {
      const { data } = await api.apiKeysList();
      setKeys(data.keys || []);
    } catch (e) {
      setError(e.response?.data?.detail || 'Failed to load keys');
    } finally { setLoading(false); }
  };
  useEffect(() => { refresh(); }, []);

  const create = async () => {
    if (!name.trim()) return;
    setError(''); setJustCreated(null);
    try {
      const { data } = await api.apiKeysCreate({ name: name.trim() });
      setJustCreated(data);
      setName('');
      refresh();
    } catch (e) {
      setError(e.response?.data?.detail || 'Create failed');
    }
  };

  const revoke = async (id) => {
    if (!window.confirm('Revoke this key? Any tools using it will stop working.')) return;
    try {
      await api.apiKeysRevoke(id);
      refresh();
    } catch (e) {
      setError(e.response?.data?.detail || 'Revoke failed');
    }
  };

  const downloadSdk = (lang) => {
    const path = lang === 'py' ? 'python' : 'javascript';
    window.location.href = `${process.env.REACT_APP_BACKEND_URL}/api/downloads/sdk/${path}`;
  };

  const isTierError = /enterprise or lifetime/i.test(error || '');

  return (
    <div data-testid="apikeys-page" className="max-w-4xl mx-auto space-y-6 animate-fade-in-up">
      <header className="border border-cyan-500/40 bg-gradient-to-r from-cyan-950/30 via-zinc-950 to-zinc-950 p-6">
        <div className="flex items-center gap-2 mb-2">
          <KeyRound className="w-5 h-5 text-cyan-400" />
          <span className="text-[10px] mono uppercase tracking-widest text-cyan-400 border border-cyan-500/50 bg-cyan-500/10 px-2 py-0.5">
            Public API · v7.9.2
          </span>
          <HelpTip
            title="API Keys"
            body="Generate scoped keys to use the CyberScope REST API from your CI/CD, IDE plugins, or Python/JS scripts. Available on Enterprise & Lifetime plans."
            testId="apikeys-help"
          />
        </div>
        <h1 className="text-2xl md:text-3xl font-display font-bold text-zinc-50">
          API keys &amp; SDKs
        </h1>
        <p className="text-zinc-400 text-sm mt-2">
          Programmatically launch scans, poll results, and run AI triage from any environment.
        </p>
      </header>

      {error && !isTierError && (
        <div className="border border-red-500/40 bg-red-500/10 text-red-300 px-4 py-2 text-sm flex items-center gap-2" data-testid="apikeys-error">
          <XCircle className="w-4 h-4" /> {error}
        </div>
      )}
      {isTierError && (
        <div className="border border-amber-500/40 bg-amber-500/10 text-amber-200 px-4 py-3 text-sm flex items-center gap-2" data-testid="apikeys-locked">
          <Lock className="w-4 h-4" />
          API keys are only available on <b className="mono">Enterprise</b> and <b className="mono">Lifetime</b> plans.{' '}
          <a href="/pricing" className="underline underline-offset-4 hover:text-amber-100">Upgrade →</a>
        </div>
      )}

      {/* Create */}
      {!isTierError && (
        <div className="border border-zinc-800 bg-zinc-900/40 p-5">
          <div className="text-xs mono uppercase tracking-widest text-zinc-500 mb-3 flex items-center gap-1">
            <Plus className="w-3.5 h-3.5" /> Create API key
          </div>
          <div className="flex flex-wrap gap-2">
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. CI pipeline · IDE plugin · security bot"
              data-testid="apikey-name"
              className="flex-1 min-w-[240px] bg-zinc-950 border border-zinc-800 px-3 py-2 text-sm focus:outline-none focus:border-cyan-500"
            />
            <button
              onClick={create}
              disabled={!name.trim()}
              data-testid="apikey-create"
              className="bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-zinc-950 font-mono text-xs font-semibold px-4 py-2"
            >
              Generate
            </button>
          </div>

          {justCreated && (
            <div className="mt-4 border border-emerald-500/40 bg-emerald-500/5 p-3 text-xs">
              <div className="flex items-center gap-1.5 text-emerald-300 mb-2">
                <CheckCircle2 className="w-3.5 h-3.5" /> Key created — copy it now. It will NEVER be shown again.
              </div>
              <div className="flex items-center gap-2">
                <code className="mono text-emerald-200 bg-zinc-950 px-2 py-1.5 break-all flex-1" data-testid="apikey-value">
                  {justCreated.key}
                </code>
                <button
                  onClick={() => navigator.clipboard.writeText(justCreated.key)}
                  className="text-zinc-400 hover:text-zinc-100 shrink-0"
                  title="Copy"
                  data-testid="apikey-copy"
                >
                  <Copy className="w-3.5 h-3.5" />
                </button>
              </div>
              <div className="text-[10px] mono text-zinc-500 mt-2">
                Header: <code className="text-zinc-300">X-API-Key: {justCreated.preview}</code>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Keys list */}
      {!isTierError && (
        <div className="border border-zinc-800 bg-zinc-900/40">
          <div className="px-5 py-3 border-b border-zinc-800 text-xs mono uppercase tracking-widest text-zinc-500 flex items-center justify-between">
            <span>Your keys ({keys.length}) {loading && '· loading…'}</span>
          </div>
          <div className="divide-y divide-zinc-800">
            {keys.map((k) => (
              <div key={k.id} className="px-5 py-3 flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="text-sm text-zinc-100 truncate">{k.name}</div>
                  <div className="text-[10px] mono text-zinc-500">
                    {k.preview} · {k.requests || 0} requests · created {new Date(k.created_at).toLocaleDateString()}
                  </div>
                </div>
                <button
                  onClick={() => revoke(k.id)}
                  data-testid={`apikey-revoke-${k.id}`}
                  className="text-red-400 hover:text-red-300 text-xs mono flex items-center gap-1"
                >
                  <Trash2 className="w-3.5 h-3.5" /> Revoke
                </button>
              </div>
            ))}
            {!loading && keys.length === 0 && (
              <div className="px-5 py-8 text-center text-xs text-zinc-500">
                No API keys yet. Generate one above.
              </div>
            )}
          </div>
        </div>
      )}

      {/* SDK downloads */}
      <div className="border border-zinc-800 bg-zinc-900/40 p-5">
        <div className="text-xs mono uppercase tracking-widest text-zinc-500 mb-3 flex items-center gap-2">
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" /> Official SDKs
          <HelpTip
            title="SDKs"
            body="Drop-in single-file clients. Copy your API key, install the SDK, and call scan() / triage() from any language."
          />
        </div>
        <div className="grid md:grid-cols-2 gap-3">
          <button
            onClick={() => downloadSdk('py')}
            data-testid="sdk-python"
            className="border border-emerald-500/40 hover:bg-emerald-500/10 p-3 text-start"
          >
            <div className="text-sm text-emerald-300 font-mono flex items-center gap-2">
              <Download className="w-3.5 h-3.5" /> cyberscope_sdk.py
            </div>
            <div className="text-[11px] text-zinc-500 mt-1">Python 3.8+ · requires `requests`</div>
          </button>
          <button
            onClick={() => downloadSdk('js')}
            data-testid="sdk-javascript"
            className="border border-amber-500/40 hover:bg-amber-500/10 p-3 text-start"
          >
            <div className="text-sm text-amber-300 font-mono flex items-center gap-2">
              <Download className="w-3.5 h-3.5" /> cyberscope-sdk.js
            </div>
            <div className="text-[11px] text-zinc-500 mt-1">Node 18+ / modern browsers · native fetch</div>
          </button>
        </div>
        <pre className="mt-4 bg-zinc-950 border border-zinc-800 p-3 text-[11px] mono text-zinc-300 overflow-x-auto">
{`# Python
from cyberscope_sdk import CyberScope
cs = CyberScope(api_key="cs_...", base="https://your-cyberscope-instance.com")
scan = cs.scan("https://target.example.com", depth="deep")
print(cs.wait(scan["scan_id"]))
print(cs.triage(scan["scan_id"]))  # AI triple-vote triage`}
        </pre>
      </div>
    </div>
  );
}
