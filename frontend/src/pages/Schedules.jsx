import React, { useState, useEffect } from 'react';
import { Clock, Plus, Trash2, Power } from 'lucide-react';
import api from '@/lib/api';

const SCHEDULES = ['hourly', 'daily', 'weekly', 'monthly', 'every 6h', 'every 12h', 'once'];

const SchedInput = (props) => (
  <input {...props}
    className="w-full bg-zinc-900 border border-zinc-800 px-3 py-2 mono text-sm text-zinc-100 focus:border-emerald-500 focus:outline-none" />
);

export default function SchedulesPage() {
  const [items, setItems] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ target: '', schedule: 'daily', depth: 'medium', name: '' });

  const load = () =>
    api.listSchedules().then(r => setItems(r.data.schedules || [])).catch(() => {});
  useEffect(() => { load(); }, []);

  const submit = async () => {
    if (!form.target) return;
    await api.createSchedule(form);
    setForm({ target: '', schedule: 'daily', depth: 'medium', name: '' });
    setShowForm(false);
    load();
  };

  const toggle = async (id) => {
    await api.toggleSchedule(id);
    load();
  };
  const del = async (id) => {
    if (!window.confirm('Delete this schedule?')) return;
    await api.deleteSchedule(id);
    load();
  };

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-4" data-testid="schedules-page">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Clock className="w-6 h-6 text-emerald-500" />
          <div>
            <h1 className="text-2xl font-bold text-zinc-50">Scheduled Scans</h1>
            <p className="text-xs mono text-zinc-500">Recurring scans — daily, weekly, hourly, or custom.</p>
          </div>
        </div>
        <button onClick={() => setShowForm(!showForm)} data-testid="toggle-add-schedule"
                className="px-4 py-2 bg-emerald-500 hover:bg-emerald-600 text-black font-bold mono text-xs uppercase tracking-widest flex items-center gap-2">
          <Plus className="w-3 h-3" /> Add Schedule
        </button>
      </div>

      {showForm && (
        <div className="border border-emerald-500/30 bg-zinc-950 p-4 space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <div className="text-[10px] mono uppercase tracking-widest text-zinc-500 mb-1">Target URL</div>
              <SchedInput value={form.target} onChange={e => setForm({ ...form, target: e.target.value })}
                     placeholder="https://example.com" data-testid="schedule-target" />
            </div>
            <div>
              <div className="text-[10px] mono uppercase tracking-widest text-zinc-500 mb-1">Name (optional)</div>
              <SchedInput value={form.name} onChange={e => setForm({ ...form, name: e.target.value })}
                     placeholder="Daily production scan" data-testid="schedule-name" />
            </div>
            <div>
              <div className="text-[10px] mono uppercase tracking-widest text-zinc-500 mb-1">Schedule</div>
              <select value={form.schedule} onChange={e => setForm({ ...form, schedule: e.target.value })}
                      data-testid="schedule-freq"
                      className="w-full bg-zinc-900 border border-zinc-800 px-3 py-2 mono text-sm">
                {SCHEDULES.map(s => <option key={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <div className="text-[10px] mono uppercase tracking-widest text-zinc-500 mb-1">Depth</div>
              <select value={form.depth} onChange={e => setForm({ ...form, depth: e.target.value })}
                      data-testid="schedule-depth"
                      className="w-full bg-zinc-900 border border-zinc-800 px-3 py-2 mono text-sm">
                <option value="shallow">shallow (fast)</option>
                <option value="medium">medium</option>
                <option value="deep">deep (slow but thorough)</option>
              </select>
            </div>
          </div>
          <button onClick={submit} data-testid="submit-schedule"
                  className="px-4 py-2 bg-emerald-500 hover:bg-emerald-600 text-black font-bold mono text-xs uppercase tracking-widest">
            Create Schedule
          </button>
        </div>
      )}

      <div className="space-y-2">
        {items.length === 0 ? (
          <div className="border border-zinc-800 bg-zinc-950 p-8 text-center text-xs mono text-zinc-500">
            No scheduled scans. Add one above to start automated monitoring.
          </div>
        ) : items.map(i => (
          <div key={i.id} data-testid={`schedule-row-${i.id}`}
               className="border border-zinc-800 bg-zinc-950 p-3 flex items-center justify-between gap-4">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1 flex-wrap">
                <span className={`text-[10px] mono uppercase tracking-widest px-2 py-0.5 border ${
                  i.enabled ? 'border-emerald-500/40 text-emerald-400 bg-emerald-500/10' :
                              'border-zinc-700 text-zinc-500'
                }`}>{i.enabled ? 'active' : 'paused'}</span>
                <span className="text-[10px] mono text-emerald-500">{i.schedule}</span>
                <span className="text-[10px] mono text-zinc-500">depth: {i.depth}</span>
                {i.name && <span className="text-sm text-zinc-100">{i.name}</span>}
              </div>
              <div className="text-[11px] mono text-zinc-400 truncate">{i.target}</div>
              <div className="text-[10px] mono text-zinc-500 mt-1">
                Next run: {i.next_run_at || '—'} · Last run: {i.last_run_at || '—'}
              </div>
            </div>
            <div className="flex gap-1">
              <button onClick={() => toggle(i.id)} data-testid={`toggle-schedule-${i.id}`}
                      className="p-1.5 text-zinc-500 hover:text-emerald-400">
                <Power className="w-4 h-4" />
              </button>
              <button onClick={() => del(i.id)} data-testid={`delete-schedule-${i.id}`}
                      className="p-1.5 text-zinc-500 hover:text-red-400">
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
