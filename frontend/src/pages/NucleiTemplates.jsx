import React, { useState, useEffect } from 'react';
import { Package, Upload, Trash2, Loader2 } from 'lucide-react';
import api from '@/lib/api';

const SAMPLE = `id: exposed-git-config
info:
  name: Exposed .git/config
  severity: critical
  tags: cve-2020-git,exposure
http:
  - method: GET
    path:
      - {{BaseURL}}/.git/config
    matchers:
      - type: word
        words: ["[core]", "repositoryformatversion"]
      - type: status
        status: [200]
`;

export default function NucleiPage() {
  const [items, setItems] = useState([]);
  const [yaml, setYaml] = useState(SAMPLE);
  const [importing, setImporting] = useState(false);
  const [result, setResult] = useState(null);

  const load = () =>
    api.listNucleiTemplates().then(r => setItems(r.data.templates || [])).catch(() => {});
  useEffect(() => { load(); }, []);

  const doImport = async () => {
    setImporting(true); setResult(null);
    try {
      const r = await api.importNucleiText(yaml);
      setResult(r.data);
      if (r.data.imported > 0) load();
    } catch (e) {
      setResult({ error: String(e?.message || e) });
    } finally {
      setImporting(false);
    }
  };

  const del = async (id) => {
    if (!window.confirm('Delete this template?')) return;
    await api.deleteNucleiTemplate(id);
    load();
  };

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-4" data-testid="nuclei-page">
      <div className="flex items-center gap-3 mb-2">
        <Package className="w-6 h-6 text-emerald-500" />
        <div>
          <h1 className="text-2xl font-bold text-zinc-50">Nuclei Templates</h1>
          <p className="text-xs mono text-zinc-500">
            Import Nuclei YAML templates — supports 10,000+ community templates from ProjectDiscovery.
          </p>
        </div>
      </div>

      <div className="border border-zinc-800 bg-zinc-950 p-4">
        <div className="text-xs mono uppercase tracking-widest text-emerald-500 mb-2">Paste YAML Template</div>
        <textarea
          value={yaml}
          onChange={e => setYaml(e.target.value)}
          data-testid="nuclei-yaml-input"
          rows={15}
          className="w-full bg-black border border-zinc-800 px-3 py-2 mono text-xs text-zinc-100 focus:border-emerald-500 focus:outline-none"
        />
        <div className="flex gap-2 mt-3">
          <button onClick={doImport} disabled={importing} data-testid="import-nuclei-btn"
                  className="px-4 py-2 bg-emerald-500 hover:bg-emerald-600 disabled:opacity-50 text-black font-bold mono text-xs uppercase tracking-widest flex items-center gap-2">
            {importing ? <Loader2 className="w-3 h-3 animate-spin" /> : <Upload className="w-3 h-3" />}
            {importing ? 'Importing...' : 'Import Template'}
          </button>
          <a href="https://github.com/projectdiscovery/nuclei-templates" target="_blank" rel="noreferrer"
             className="px-4 py-2 border border-zinc-700 text-zinc-300 hover:text-emerald-400 mono text-xs uppercase tracking-widest">
            Browse Nuclei Templates
          </a>
        </div>
        {result && (
          <div className="mt-3 border border-zinc-800 bg-zinc-900 p-3 mono text-xs" data-testid="import-result">
            {result.imported > 0 ? (
              <span className="text-emerald-400">✅ Imported {result.imported} template(s). ID: {result.template?.id}</span>
            ) : (
              <span className="text-red-400">❌ {result.error || 'Import failed'}</span>
            )}
          </div>
        )}
      </div>

      <div className="border border-zinc-800 bg-zinc-950">
        <div className="p-3 border-b border-zinc-800 text-xs mono">
          <span className="text-emerald-500 font-bold">{items.length}</span>
          <span className="text-zinc-500 uppercase tracking-widest text-[10px] ml-2">imported templates</span>
        </div>
        <div className="max-h-[500px] overflow-y-auto">
          {items.length === 0 ? (
            <div className="p-8 text-center text-xs mono text-zinc-500">
              No templates imported yet.
            </div>
          ) : items.map(t => (
            <div key={t.id} data-testid={`template-row-${t.id}`}
                 className="p-3 border-b border-zinc-900 flex items-center justify-between hover:bg-zinc-900">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className={`text-[10px] mono uppercase tracking-widest px-2 py-0.5 border ${
                    t.severity === 'critical' ? 'border-red-500/40 text-red-400 bg-red-500/10' :
                    t.severity === 'high' ? 'border-orange-500/40 text-orange-400 bg-orange-500/10' :
                    'border-zinc-700 text-zinc-400'
                  }`}>{t.severity}</span>
                  <span className="text-sm text-zinc-100">{t.name}</span>
                  {t.cve && <span className="text-[10px] mono text-emerald-400">{t.cve}</span>}
                </div>
                <div className="text-[10px] mono text-zinc-500 truncate">
                  {(t.paths || []).join(' | ')} · {(t.match_body || []).length} match(es)
                </div>
              </div>
              <button onClick={() => del(t.id)} className="p-1.5 text-zinc-500 hover:text-red-400"
                      data-testid={`delete-template-${t.id}`}>
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
