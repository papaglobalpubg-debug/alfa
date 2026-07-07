import React, { useState, useEffect } from 'react';
import { Zap, Plus, Trash2 } from 'lucide-react';
import api from '@/lib/api';

const CATEGORIES = ['xss', 'sqli', 'ssrf', 'lfi', 'cmd', 'ssti', 'xxe',
                     'nosqli', 'crlf', 'open_redirect', 'graphql', 'cache_poisoning'];

export default function CustomPayloadsPage() {
  const [items, setItems] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ category: 'xss', name: '', payloads: '' });

  const load = () =>
    api.listCustomPayloads().then(r => setItems(r.data.items || [])).catch(() => {});
  useEffect(() => { load(); }, []);

  const submit = async () => {
    const payloads = form.payloads.split('\n').map(s => s.trim()).filter(Boolean);
    if (!form.name || !payloads.length) return;
    await api.addCustomPayload({ category: form.category, name: form.name, payloads });
    setForm({ category: 'xss', name: '', payloads: '' });
    setShowForm(false);
    load();
  };

  const del = async (id) => {
    if (!window.confirm('Delete this custom payload set?')) return;
    await api.deleteCustomPayload(id);
    load();
  };

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-4" data-testid="custom-payloads-page">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Zap className="w-6 h-6 text-emerald-500" />
          <div>
            <h1 className="text-2xl font-bold text-zinc-50">Custom Payloads</h1>
            <p className="text-xs mono text-zinc-500">Add your own payloads to extend the scanner coverage.</p>
          </div>
        </div>
        <button onClick={() => setShowForm(!showForm)} data-testid="toggle-add-payload"
                className="px-4 py-2 bg-emerald-500 hover:bg-emerald-600 text-black font-bold mono text-xs uppercase tracking-widest flex items-center gap-2">
          <Plus className="w-3 h-3" /> Add
        </button>
      </div>

      {showForm && (
        <div className="border border-emerald-500/30 bg-zinc-950 p-4 space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <div className="text-[10px] mono uppercase tracking-widest text-zinc-500 mb-1">Category</div>
              <select value={form.category} onChange={e => setForm({ ...form, category: e.target.value })}
                      data-testid="new-payload-category"
                      className="w-full bg-zinc-900 border border-zinc-800 px-3 py-2 mono text-sm">
                {CATEGORIES.map(c => <option key={c}>{c}</option>)}
              </select>
            </div>
            <div>
              <div className="text-[10px] mono uppercase tracking-widest text-zinc-500 mb-1">Name</div>
              <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })}
                     data-testid="new-payload-name"
                     className="w-full bg-zinc-900 border border-zinc-800 px-3 py-2 mono text-sm"
                     placeholder="e.g. My WAF bypass collection " />
            </div>
          </div>
          <div>
            <div className="text-[10px] mono uppercase tracking-widest text-zinc-500 mb-1">Payloads (one per line)</div>
            <textarea value={form.payloads} onChange={e => setForm({ ...form, payloads: e.target.value })}
                      data-testid="new-payload-list"
                      rows={8}
                      className="w-full bg-zinc-900 border border-zinc-800 px-3 py-2 mono text-xs"
                      placeholder="<svg onload=alert(1)>\n<img src=x onerror=alert(1)>" />
          </div>
          <button onClick={submit} data-testid="submit-payload"
                  className="px-4 py-2 bg-emerald-500 hover:bg-emerald-600 text-black font-bold mono text-xs uppercase tracking-widest">
            Save
          </button>
        </div>
      )}

      <div className="space-y-2">
        {items.length === 0 ? (
          <div className="border border-zinc-800 bg-zinc-950 p-8 text-center text-xs mono text-zinc-500">
            No custom payloads yet. Add your first collection above.
          </div>
        ) : items.map(i => (
          <div key={i.id} className="border border-zinc-800 bg-zinc-950 p-3 flex items-center justify-between gap-4"
               data-testid={`payload-row-${i.id}`}>
            <div className="flex-1">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-[10px] mono uppercase tracking-widest text-emerald-500 border border-emerald-500/30 px-2 py-0.5">{i.category}</span>
                <span className="text-sm text-zinc-100">{i.name}</span>
                <span className="text-[10px] mono text-zinc-500">({i.payloads?.length || 0} payloads)</span>
              </div>
              <div className="text-[10px] mono text-zinc-500 truncate">{(i.payloads || [])[0] || ''}</div>
            </div>
            <button onClick={() => del(i.id)} className="p-1.5 text-zinc-500 hover:text-red-400" data-testid={`delete-payload-${i.id}`}>
              <Trash2 className="w-4 h-4" />
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
