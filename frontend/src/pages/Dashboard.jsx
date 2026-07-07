import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import api from '@/lib/api';
import { StatusBadge } from '@/components/Badges';
import HelpTip from '@/components/HelpTip';
import { DASHBOARD } from '@/constants/testIds';
import {
  Activity, ShieldAlert, ShieldCheck, Radar, Zap, ArrowRight,
  Bomb, Target, StopCircle, Trash2, Square, CheckSquare,
  Shield, Skull, KeyRound, Waypoints, Radio, Bot,
  Eye, PlayCircle,
} from 'lucide-react';
import {
  ScanningLine, RippleDot, LoadingBar, Skeleton, MatrixLoader,
  RadarSweep, CountUp, StatusPill,
} from '@/components/Loaders';

const RUNNING = new Set(['pending', 'queued', 'running', 'discovering', 'analyzing', 'verifying', 'cancelling']);
const SEV_COLORS = {
  critical: 'text-red-500',   high: 'text-orange-400',
  medium:   'text-yellow-400', low:  'text-blue-400', info: 'text-zinc-400',
};

function fmtDate(iso) {
  if (!iso) return '-';
  try {
    return new Date(iso).toLocaleString(undefined, {
      month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit',
    });
  } catch { return iso; }
}

export default function Dashboard() {
  const [dashStats, setDashStats] = useState(null);
  const [takeoverStats, setTakeoverStats] = useState(null);
  const [security, setSecurity] = useState(null);
  const [monitors, setMonitors] = useState([]);
  const [selected, setSelected] = useState(new Set());
  const [busy, setBusy] = useState(false);
  const [flash, setFlash] = useState(null);
  const navigate = useNavigate();

  const load = async () => {
    const [ds, ts, sec, mon] = await Promise.all([
      api.request('/api/vuln/dashboard-stats').catch(() => ({ data: null })),
      api.stats().catch(() => ({ data: null })),
      api.securityStatus().catch(() => ({ data: null })),
      api.request('/api/vuln/monitors-v2').catch(() => ({ data: { monitors: [] } })),
    ]);
    setDashStats(ds.data);
    setTakeoverStats(ts.data);
    setSecurity(sec.data);
    setMonitors(mon.data?.monitors || []);
  };

  useEffect(() => {
    load();
    const t = setInterval(load, 4000);
    return () => clearInterval(t);
  }, []);

  const showFlash = (text, tone = 'ok') => {
    setFlash({ text, tone });
    setTimeout(() => setFlash(null), 2200);
  };

  const recent = dashStats?.recent_scans || [];
  const running = useMemo(() => recent.filter((s) => RUNNING.has(s.status)), [recent]);
  const runningSelected = useMemo(
    () => recent.filter((s) => selected.has(s.id) && RUNNING.has(s.status)),
    [recent, selected],
  );

  const toggleSelect = (id) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };
  const selectAll = () => {
    if (selected.size === recent.length) setSelected(new Set());
    else setSelected(new Set(recent.map((s) => s.id)));
  };
  const stopOne = async (id, e) => {
    if (e) e.stopPropagation();
    setBusy(true);
    try { await api.cancelVulnScan(id); showFlash('Stopped'); load(); }
    catch { showFlash('Stop failed', 'err'); }
    setBusy(false);
  };
  const stopAll = async () => {
    const ids = running.map((s) => s.id);
    if (!ids.length) return;
    if (!window.confirm(`Stop ${ids.length} running scan(s)?`)) return;
    setBusy(true);
    try {
      const r = await api.bulkCancelVulnScans(ids);
      showFlash(`Stopped ${r.data.count}`);
      load();
    } catch { showFlash('Stop failed', 'err'); }
    setBusy(false);
  };
  const bulkDelete = async () => {
    const ids = Array.from(selected);
    if (!ids.length) return;
    if (!window.confirm(`Delete ${ids.length} scan(s)?`)) return;
    setBusy(true);
    try {
      const r = await api.bulkDeleteVulnScans(ids);
      showFlash(`Deleted ${r.data.deleted}`);
      setSelected(new Set());
      load();
    } catch { showFlash('Delete failed', 'err'); }
    setBusy(false);
  };

  const sev = dashStats?.severities_last30 || {};
  const allSelected = recent.length > 0 && selected.size === recent.length;

  return (
    <div data-testid={DASHBOARD.container} className="space-y-6 max-w-7xl mx-auto animate-fade-in-up">

      {/* ══════════ SECTION 1 · Hero / Command Center ══════════ */}
      <section className="relative border border-red-500/40 bg-gradient-to-br from-red-950/40 via-zinc-950 to-zinc-950 overflow-hidden">
        <ScanningLine color="red" />
        <div className="absolute -top-16 -right-16 w-80 h-80 bg-red-500/10 blur-3xl rounded-full pointer-events-none" />
        <div className="absolute -bottom-16 -left-16 w-80 h-80 bg-emerald-500/5 blur-3xl rounded-full pointer-events-none" />
        <div className="relative p-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-3">
              <Skull className="w-6 h-6 text-red-500 animate-glow-pulse" />
              <span className="text-[10px] mono uppercase tracking-widest text-red-400 border border-red-500/50 bg-red-500/10 px-2 py-0.5">
                CyberScope v7.9.2 · Weaponized
              </span>
              <HelpTip title="Dashboard" body="Command center. Kick off scans, monitor progress in real time, and jump to the arsenal. Use AI Autopilot to let the LLM plan a full sweep for you." testId="dashboard-help" />
            </div>
            <h1 className="text-3xl md:text-4xl font-display font-bold text-zinc-50 tracking-tight">
              Offensive Web Auditor
            </h1>
            <p className="text-zinc-400 text-sm mt-3 max-w-2xl leading-relaxed">
              Deep BFS crawler · 200K+ payloads · 40+ modules · AI verification · zero false-positive layer.
            </p>
          </div>
          <div className="flex flex-wrap gap-2 shrink-0">
            <button
              data-testid="hero-autopilot-btn"
              onClick={() => navigate('/vuln/autopilot')}
              className="flex items-center gap-2 px-4 py-3 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/10 mono text-sm uppercase tracking-widest transition-all"
            >
              <Bot className="w-4 h-4" /> AI Autopilot
            </button>
            <button
              data-testid="hero-launch-vuln-btn"
              onClick={() => navigate('/vuln/new')}
              className="flex items-center gap-2 px-6 py-3 bg-red-500 hover:bg-red-600 text-white font-bold mono text-sm uppercase tracking-widest transition-all shadow-lg shadow-red-500/30 hover:shadow-red-500/50"
            >
              <Bomb className="w-4 h-4" /> Launch Attack
            </button>
          </div>
        </div>
      </section>

      {/* ══════════ SECTION 2 · Security Hardened Badge ══════════ */}
      {security && (
        <section className="border border-emerald-500/30 bg-emerald-500/5 px-4 py-2 flex items-center justify-between flex-wrap gap-2 animate-fade-in-up">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-emerald-400" />
            <span className="text-[10px] mono uppercase tracking-widest text-emerald-300">
              Security hardened · v{security.version}
            </span>
          </div>
          <div className="flex items-center gap-3 flex-wrap text-[10px] mono text-zinc-400">
            {Object.entries(security.guards || {}).map(([k, v]) => (
              <span key={k} className={`flex items-center gap-1 ${v ? 'text-emerald-400' : 'text-zinc-600'}`}>
                <span className="w-1.5 h-1.5 rounded-full bg-current" />{k}
              </span>
            ))}
          </div>
        </section>
      )}

      {/* ══════════ SECTION 3 · KPI Row ══════════ */}
      <section className="grid grid-cols-2 md:grid-cols-6 gap-3">
        <KPI testid="kpi-total" label="Total scans"  value={dashStats?.total_scans}      icon={Bomb}        accent="red"/>
        <KPI testid="kpi-running" label="Running now" value={dashStats?.running_count}   icon={Activity}    accent={dashStats?.running_count ? 'emerald' : 'zinc'} pulse={dashStats?.running_count > 0}/>
        <KPI testid="kpi-critical" label="Critical"   value={sev.critical}               icon={ShieldAlert} accent="red"/>
        <KPI testid="kpi-high" label="High"           value={sev.high}                   icon={Target}      accent="orange"/>
        <KPI testid="kpi-medium" label="Medium"       value={sev.medium}                 icon={ShieldCheck} accent="yellow"/>
        <KPI testid="kpi-monitors" label="Monitors"   value={dashStats?.monitors_count ?? monitors.length} icon={Radar} accent="cyan"/>
      </section>

      {/* ══════════ SECTION 4 · Live Operations ══════════ */}
      {running.length > 0 && (
        <section data-testid="live-ops-panel" className="border border-emerald-500/40 bg-gradient-to-r from-emerald-950/40 to-zinc-950 overflow-hidden animate-fade-in-up">
          <ScanningLine color="emerald" />
          <div className="p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <RippleDot color="emerald" />
                <h3 className="text-xs font-semibold text-emerald-400 mono uppercase tracking-widest">
                  Live · {running.length} scan{running.length !== 1 ? 's' : ''} running
                </h3>
              </div>
              <button
                data-testid="stop-all-running-btn"
                onClick={stopAll}
                disabled={busy}
                className="flex items-center gap-1 px-3 py-1.5 border border-amber-500/40 text-amber-400 hover:bg-amber-500/10 mono text-xs uppercase tracking-widest disabled:opacity-40"
              >
                <StopCircle className="w-3 h-3" /> Stop all
              </button>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {running.map((s) => (
                <div
                  key={s.id}
                  data-testid={`live-scan-${s.id}`}
                  onClick={() => navigate(`/vuln/scan/${s.id}`)}
                  className="p-3 bg-zinc-950/80 border border-zinc-800 hover:border-emerald-500/40 cursor-pointer transition-colors overflow-hidden"
                >
                  <div className="flex items-center justify-between gap-3">
                    <div className="min-w-0 flex-1">
                      <div className="text-sm text-zinc-100 mono truncate">{s.target}</div>
                      <div className="text-[10px] mono text-zinc-500 uppercase tracking-widest mt-1 flex items-center gap-2">
                        <StatusPill status={s.status} />
                        <span>{s.depth}</span>
                        <span>· {fmtDate(s.started_at)}</span>
                        {s.mode === 'autopilot' && (
                          <span className="text-cyan-400"><Bot className="inline w-3 h-3" /> autopilot</span>
                        )}
                      </div>
                    </div>
                    <button
                      data-testid={`stop-scan-${s.id}`}
                      onClick={(e) => stopOne(s.id, e)}
                      disabled={busy}
                      title="Stop immediately"
                      className="p-2 text-amber-400 hover:text-amber-300 hover:bg-amber-500/10 border border-amber-500/30 disabled:opacity-40 shrink-0"
                    >
                      <StopCircle className="w-4 h-4" />
                    </button>
                  </div>
                  <div className="mt-2">
                    <LoadingBar color="emerald" />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>
      )}

      {/* ══════════ SECTION 5 · Quick Launch — 6 tools ══════════ */}
      <section>
        <SectionHeading title="Quick Launch" icon={<Zap className="w-4 h-4 text-red-500" />} />
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-2">
          <QuickTool testid="ql-vuln"       label="Vuln Scan"     desc="Full audit"        icon={Bomb}      accent="red"     onClick={() => navigate('/vuln/new')}/>
          <QuickTool testid="ql-autopilot"  label="AI Autopilot"  desc="LLM-planned"       icon={Bot}       accent="cyan"    onClick={() => navigate('/vuln/autopilot')}/>
          <QuickTool testid="ql-jwt"        label="JWT Cracker"   desc="104K secrets"      icon={KeyRound}  accent="amber"   onClick={() => navigate('/vuln/jwt')}/>
          <QuickTool testid="ql-graphql"    label="GraphQL"       desc="Introspection"     icon={Waypoints} accent="purple"  onClick={() => navigate('/vuln/graphql')}/>
          <QuickTool testid="ql-race"       label="Race Condition" desc="Concurrent burst" icon={Radio}    accent="emerald" onClick={() => navigate('/vuln/race')}/>
          <QuickTool testid="ql-takeover"   label="Takeover"      desc="Subdomain recon"   icon={Radar}     accent="cyan"    onClick={() => navigate('/scan/new')}/>
        </div>
      </section>

      {/* ══════════ SECTION 6 · Recent Vuln Scans ══════════ */}
      <section className="bg-zinc-900/50 border border-red-500/20">
        <SectionHeading
          title="Recent Vuln Scans"
          icon={<Bomb className="w-4 h-4 text-red-500" />}
          right={
            <button onClick={() => navigate('/vuln/history')} className="text-xs text-zinc-500 hover:text-red-400 flex items-center gap-1 transition-colors">
              View all <ArrowRight className="w-3 h-3" />
            </button>
          }
        />
        {recent.length > 0 && (
          <div className={`flex items-center justify-between flex-wrap gap-2 px-4 py-2 border-b border-zinc-800 ${
            selected.size ? 'bg-red-500/5' : 'bg-zinc-950/50'
          }`}>
            <div className="flex items-center gap-3">
              <button
                data-testid="dash-select-all-btn"
                onClick={selectAll}
                className="flex items-center gap-2 text-xs mono text-zinc-300 hover:text-zinc-50"
              >
                {allSelected
                  ? <CheckSquare className="w-4 h-4 text-red-400" />
                  : <Square className="w-4 h-4" />}
                {allSelected ? 'Deselect all' : 'Select all'}
              </button>
              {selected.size > 0 && (
                <span className="text-xs mono text-zinc-500">
                  {selected.size} selected · {runningSelected.length} running
                </span>
              )}
            </div>
            <div className="flex items-center gap-2">
              {flash && (
                <span className={`text-xs mono px-2 py-1 border ${
                  flash.tone === 'err' ? 'border-red-500/40 text-red-400' : 'border-emerald-500/40 text-emerald-400'
                }`}>{flash.text}</span>
              )}
              <button
                data-testid="dash-bulk-delete-btn"
                onClick={bulkDelete}
                disabled={busy || selected.size === 0}
                className="flex items-center gap-1 px-3 py-1 border border-red-500/40 text-red-400 hover:bg-red-500/10 mono text-xs uppercase tracking-widest disabled:opacity-30 disabled:cursor-not-allowed"
              >
                <Trash2 className="w-3 h-3" /> Delete ({selected.size})
              </button>
            </div>
          </div>
        )}
        <div className="overflow-x-auto">
          {!dashStats ? (
            <div className="p-4 space-y-2">
              <Skeleton h="h-8" />
              <Skeleton h="h-8" />
              <Skeleton h="h-8" />
            </div>
          ) : recent.length === 0 ? (
            <div className="text-zinc-600 text-sm mono p-6 text-center border-t border-dashed border-zinc-800">
              No scans yet.{' '}
              <button onClick={() => navigate('/vuln/new')} className="text-red-400 hover:text-red-300 underline">
                Launch your first attack &gt;
              </button>
            </div>
          ) : (
            <table className="w-full text-sm mono">
              <thead>
                <tr className="text-left text-zinc-500 text-[10px] uppercase tracking-widest border-b border-zinc-800">
                  <th className="w-10 py-2 px-3"></th>
                  <th className="py-2 px-2 font-medium">Target</th>
                  <th className="py-2 px-2 font-medium">Status</th>
                  <th className="py-2 px-2 font-medium">Mode</th>
                  <th className="py-2 px-2 font-medium">Depth</th>
                  <th className="py-2 px-2 font-medium">Findings</th>
                  <th className="py-2 px-2 font-medium">Started</th>
                  <th className="py-2 px-2 font-medium text-right"></th>
                </tr>
              </thead>
              <tbody>
                {recent.map((s) => {
                  const isRunning = RUNNING.has(s.status);
                  const sum = s.summary || {};
                  const isSel = selected.has(s.id);
                  return (
                    <tr
                      key={s.id}
                      data-testid={`vuln-scan-dashrow-${s.id}`}
                      className={`border-b border-zinc-900 hover:bg-zinc-800/40 transition-colors ${isSel ? 'bg-red-500/5' : ''}`}
                    >
                      <td className="py-2 px-3">
                        <button
                          data-testid={`dash-select-${s.id}`}
                          onClick={(e) => { e.stopPropagation(); toggleSelect(s.id); }}
                          className="text-zinc-400 hover:text-red-400"
                        >
                          {isSel ? <CheckSquare className="w-4 h-4 text-red-400" /> : <Square className="w-4 h-4" />}
                        </button>
                      </td>
                      <td onClick={() => navigate(`/vuln/scan/${s.id}`)} className="py-2 px-2 text-zinc-50 truncate max-w-xs cursor-pointer">
                        {isRunning && <span className="mr-2"><RippleDot color="emerald" size="sm" /></span>}
                        {s.target}
                      </td>
                      <td className="py-2 px-2"><StatusPill status={s.status} /></td>
                      <td className="py-2 px-2 text-zinc-400 uppercase text-[10px]">
                        {s.mode === 'autopilot' ? (
                          <span className="text-cyan-400 flex items-center gap-1"><Bot className="w-3 h-3" /> AUTO</span>
                        ) : 'MANUAL'}
                      </td>
                      <td className="py-2 px-2 text-zinc-400 uppercase text-[10px]">{s.depth}</td>
                      <td className="py-2 px-2">
                        {sum.critical > 0 && <span className={`${SEV_COLORS.critical} mr-2`}>C:{sum.critical}</span>}
                        {sum.high > 0 && <span className={`${SEV_COLORS.high} mr-2`}>H:{sum.high}</span>}
                        {sum.medium > 0 && <span className={`${SEV_COLORS.medium} mr-2`}>M:{sum.medium}</span>}
                        {!sum.total && <span className="text-zinc-600">—</span>}
                      </td>
                      <td className="py-2 px-2 text-zinc-500">{fmtDate(s.started_at)}</td>
                      <td className="py-2 px-2 text-right">
                        <div className="flex gap-1 justify-end">
                          {isRunning && (
                            <button
                              data-testid={`dash-stop-${s.id}`}
                              onClick={(e) => stopOne(s.id, e)}
                              className="p-1 text-amber-400 hover:text-amber-300"
                              title="Stop"
                            >
                              <StopCircle className="w-4 h-4" />
                            </button>
                          )}
                          <button
                            onClick={() => navigate(`/vuln/scan/${s.id}`)}
                            className="p-1 text-zinc-600 hover:text-red-400"
                            title="View"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </section>

      {/* ══════════ SECTION 7 · Continuous Monitors ══════════ */}
      <section className="bg-zinc-900/50 border border-cyan-500/20">
        <SectionHeading
          title="Continuous Monitors"
          icon={<RadarSweep size={16} color="cyan" />}
          right={
            <button onClick={() => navigate('/vuln/monitors')} className="text-xs text-zinc-500 hover:text-cyan-400 flex items-center gap-1">
              Manage <ArrowRight className="w-3 h-3" />
            </button>
          }
        />
        {monitors.length === 0 ? (
          <div className="text-zinc-600 text-sm mono p-6 text-center">
            No monitors yet.{' '}
            <button onClick={() => navigate('/vuln/monitors')} className="text-cyan-400 hover:text-cyan-300 underline">
              Create your first monitor &gt;
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2 p-3">
            {monitors.slice(0, 6).map((m) => (
              <div key={m.id} className="p-3 bg-zinc-950 border border-zinc-800 hover:border-cyan-500/40 cursor-pointer transition-colors mono text-xs"
                onClick={() => navigate('/vuln/monitors')}>
                <div className="flex items-center justify-between">
                  <div className="text-zinc-100 truncate flex-1 flex items-center gap-2">
                    {m.active && <RippleDot color="cyan" size="sm" />}
                    {m.target}
                  </div>
                  <span className={`text-[10px] uppercase tracking-widest ${m.active ? 'text-cyan-400' : 'text-zinc-600'}`}>
                    {m.active ? 'ACTIVE' : 'PAUSED'}
                  </span>
                </div>
                <div className="text-[10px] text-zinc-500 mt-2">
                  every {m.interval_hours}h · {m.runs_count} run{m.runs_count === 1 ? '' : 's'}
                  {m.channels?.length ? ` · ${m.channels.join(', ')}` : ''}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* ══════════ SECTION 8 · Takeover Recon quick actions ══════════ */}
      <section className="bg-zinc-900/50 border border-emerald-500/20 p-4">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div>
            <h3 className="text-sm font-semibold text-zinc-50 mono uppercase tracking-tight flex items-center gap-2">
              <Radar className="w-4 h-4 text-emerald-500" /> Subdomain Takeover Recon
            </h3>
            <p className="text-[11px] mono text-zinc-500 mt-1">
              <CountUp value={takeoverStats?.total_scans ?? 0} /> scans ·{' '}
              <CountUp value={takeoverStats?.total_verified_claimable ?? 0} /> verified takeovers ·{' '}
              <CountUp value={takeoverStats?.available_services ?? 0} /> services covered
            </p>
          </div>
          <div className="flex gap-2">
            <button onClick={() => navigate('/scan/bulk')}
              data-testid="quick-bulk-btn"
              className="px-3 py-1.5 border border-zinc-800 text-zinc-300 hover:text-zinc-50 hover:border-zinc-700 mono text-xs">Bulk</button>
            <button
              data-testid={DASHBOARD.quickScanBtn}
              onClick={() => navigate('/scan/new')}
              className="flex items-center gap-2 px-3 py-1.5 bg-emerald-500 text-zinc-950 font-semibold hover:bg-emerald-400 transition-colors duration-150 text-xs">
              <PlayCircle className="w-3 h-3" /> Takeover Scan
            </button>
          </div>
        </div>
      </section>

      {/* ══════════ SECTION 9 · Legal Notice ══════════ */}
      <section className="border border-amber-500/20 bg-amber-500/5 p-4">
        <div className="flex items-start gap-3">
          <Shield className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
          <p className="text-xs mono text-zinc-400 leading-relaxed">
            <span className="text-amber-400 uppercase tracking-widest font-semibold">Legal:</span>{' '}
            Only scan systems you have explicit written authorization for.
            SSRF · BOLA · rate-limit guards are active — do not disable outside a lab.
          </p>
        </div>
      </section>

      {!dashStats && <MatrixLoader text="LOADING DASHBOARD..." />}
    </div>
  );
}

// ────────────────── local components ──────────────────

const ACCENT = {
  red:      { bar: 'from-red-500 to-red-600',        text: 'text-red-400',      border: 'border-red-500/30' },
  orange:   { bar: 'from-orange-500 to-orange-600',  text: 'text-orange-400',   border: 'border-orange-500/30' },
  amber:    { bar: 'from-amber-500 to-amber-600',    text: 'text-amber-400',    border: 'border-amber-500/30' },
  yellow:   { bar: 'from-yellow-500 to-yellow-600',  text: 'text-yellow-400',   border: 'border-yellow-500/30' },
  emerald:  { bar: 'from-emerald-500 to-emerald-600', text: 'text-emerald-400', border: 'border-emerald-500/30' },
  cyan:     { bar: 'from-cyan-500 to-cyan-600',      text: 'text-cyan-400',     border: 'border-cyan-500/30' },
  blue:     { bar: 'from-blue-500 to-blue-600',      text: 'text-blue-400',     border: 'border-blue-500/30' },
  purple:   { bar: 'from-purple-500 to-purple-600',  text: 'text-purple-400',   border: 'border-purple-500/30' },
  zinc:     { bar: 'from-zinc-500 to-zinc-600',      text: 'text-zinc-400',     border: 'border-zinc-700' },
};

function SectionHeading({ title, icon, right }) {
  return (
    <div className="flex items-center justify-between p-4 border-b border-zinc-800">
      <h3 className="text-sm font-semibold text-zinc-50 tracking-tight uppercase mono flex items-center gap-2">
        {icon} {title}
      </h3>
      {right}
    </div>
  );
}

function KPI({ testid, label, value, icon: Icon, accent = 'zinc', pulse = false }) {
  const s = ACCENT[accent] || ACCENT.zinc;
  return (
    <div data-testid={testid} className={`relative bg-zinc-950 border ${s.border} p-3 overflow-hidden`}>
      <div className={`absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r ${s.bar}`} />
      <div className="flex items-start justify-between">
        <div>
          <div className="text-[10px] mono uppercase tracking-widest text-zinc-500">{label}</div>
          <div className={`text-2xl mono font-bold mt-1 ${s.text}`}>
            <CountUp value={value || 0} />
          </div>
        </div>
        <Icon className={`w-5 h-5 ${s.text} ${pulse ? 'animate-glow-pulse' : ''}`} strokeWidth={1.5} />
      </div>
    </div>
  );
}

function QuickTool({ testid, label, desc, icon: Icon, accent, onClick }) {
  const s = ACCENT[accent] || ACCENT.zinc;
  return (
    <button
      data-testid={testid}
      onClick={onClick}
      className={`group relative bg-zinc-950 border ${s.border} p-4 text-left cursor-pointer transition-all hover:bg-zinc-900/80 hover:scale-[1.02] overflow-hidden`}
    >
      <div className={`absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r ${s.bar}`} />
      <Icon className={`w-5 h-5 ${s.text} group-hover:animate-glow-pulse`} strokeWidth={1.5} />
      <div className="text-sm font-semibold text-zinc-50 mt-2 mono uppercase tracking-tight">{label}</div>
      <div className="text-[10px] mono uppercase tracking-widest text-zinc-500 mt-0.5">{desc}</div>
    </button>
  );
}
