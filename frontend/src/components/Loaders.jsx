/**
 * CyberScope v7.7.2 · Shared loading / operations animations.
 *
 * All components are pure-CSS + tailwind — no motion library, no runtime cost.
 * Keep in one file so pages can grab them with a single import.
 */
import React from 'react';

// ─────────── Scanning line — infinite horizontal sweep ───────────
export function ScanningLine({ color = 'red' }) {
  const map = {
    red:     'from-transparent via-red-500 to-transparent',
    emerald: 'from-transparent via-emerald-500 to-transparent',
    cyan:    'from-transparent via-cyan-500 to-transparent',
    amber:   'from-transparent via-amber-500 to-transparent',
  };
  const grad = map[color] || map.red;
  return (
    <div className="relative h-0.5 w-full bg-zinc-800 overflow-hidden">
      <div className={`absolute inset-y-0 -left-1/3 w-1/3 bg-gradient-to-r ${grad} animate-scanline`} />
    </div>
  );
}

// ─────────── Ripple dot — running indicator ───────────
export function RippleDot({ color = 'emerald', size = 'md' }) {
  const sz = size === 'sm' ? 'w-2 h-2' : size === 'lg' ? 'w-4 h-4' : 'w-3 h-3';
  const cls = {
    emerald: 'bg-emerald-500 shadow-emerald-500/60',
    red:     'bg-red-500 shadow-red-500/60',
    amber:   'bg-amber-400 shadow-amber-400/60',
    cyan:    'bg-cyan-400 shadow-cyan-400/60',
  }[color] || 'bg-emerald-500 shadow-emerald-500/60';
  return (
    <span className={`relative inline-flex ${sz}`}>
      <span className={`absolute inset-0 rounded-full ${cls} opacity-40 animate-ripple`} />
      <span className={`relative rounded-full ${cls} shadow-lg ${sz}`} />
    </span>
  );
}

// ─────────── Loading bar — indeterminate progress ───────────
export function LoadingBar({ color = 'red', label = '' }) {
  const map = {
    red:     'from-red-500 via-red-400 to-red-500',
    emerald: 'from-emerald-500 via-emerald-400 to-emerald-500',
    cyan:    'from-cyan-500 via-cyan-400 to-cyan-500',
    amber:   'from-amber-500 via-amber-400 to-amber-500',
  };
  const grad = map[color] || map.red;
  return (
    <div>
      {label && <div className="text-[10px] mono uppercase tracking-widest text-zinc-500 mb-1">{label}</div>}
      <div className="relative h-1 w-full bg-zinc-800 overflow-hidden">
        <div className={`absolute inset-y-0 w-1/3 bg-gradient-to-r ${grad} animate-loading-slide`} />
      </div>
    </div>
  );
}

// ─────────── Skeleton block ───────────
export function Skeleton({ w = 'w-full', h = 'h-4', className = '' }) {
  return (
    <div className={`${w} ${h} bg-zinc-800/60 animate-pulse ${className}`} />
  );
}

// ─────────── Matrix-rain text loader ───────────
export function MatrixLoader({ text = 'SCANNING' }) {
  return (
    <div className="flex items-center gap-2 mono text-xs">
      <span className="text-emerald-400 animate-pulse">▓</span>
      <span className="text-emerald-400 tracking-widest">{text}</span>
      <span className="flex gap-0.5">
        <span className="w-1 h-1 rounded-full bg-emerald-400 animate-bounce" style={{ animationDelay: '0ms' }} />
        <span className="w-1 h-1 rounded-full bg-emerald-400 animate-bounce" style={{ animationDelay: '120ms' }} />
        <span className="w-1 h-1 rounded-full bg-emerald-400 animate-bounce" style={{ animationDelay: '240ms' }} />
      </span>
    </div>
  );
}

// ─────────── Radar sweep ring ───────────
export function RadarSweep({ size = 40, color = 'emerald' }) {
  const c = { emerald: '#10b981', red: '#ef4444', cyan: '#06b6d4' }[color] || '#10b981';
  return (
    <div className="relative" style={{ width: size, height: size }}>
      <div className="absolute inset-0 rounded-full border border-current opacity-30" style={{ color: c }} />
      <div className="absolute inset-2 rounded-full border border-current opacity-40" style={{ color: c }} />
      <div className="absolute inset-4 rounded-full border border-current opacity-60" style={{ color: c }} />
      <div className="absolute inset-0 rounded-full animate-radar-spin" style={{
        background: `conic-gradient(from 0deg, transparent 90%, ${c}, transparent)`,
      }} />
    </div>
  );
}

// ─────────── Typing dots (used inline in logs) ───────────
export function TypingDots({ color = 'emerald' }) {
  const c = { emerald: 'bg-emerald-400', red: 'bg-red-500', cyan: 'bg-cyan-400' }[color] || 'bg-emerald-400';
  return (
    <span className="inline-flex gap-0.5 items-center align-middle">
      <span className={`w-1 h-1 rounded-full ${c} animate-bounce`} style={{ animationDelay: '0ms' }} />
      <span className={`w-1 h-1 rounded-full ${c} animate-bounce`} style={{ animationDelay: '140ms' }} />
      <span className={`w-1 h-1 rounded-full ${c} animate-bounce`} style={{ animationDelay: '280ms' }} />
    </span>
  );
}

// ─────────── Number counter — smooth roll-up ───────────
export function CountUp({ value, className = '' }) {
  const [display, setDisplay] = React.useState(0);
  React.useEffect(() => {
    if (!Number.isFinite(value) || value === display) return;
    const start = display;
    const diff = value - start;
    const dur = 500;
    const t0 = performance.now();
    let raf;
    const tick = (now) => {
      const p = Math.min(1, (now - t0) / dur);
      setDisplay(Math.round(start + diff * p));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [value]);  // eslint-disable-line react-hooks/exhaustive-deps
  return <span className={`mono ${className}`}>{display.toLocaleString()}</span>;
}

// ─────────── Live status pill — for scan status ───────────
const STATUS_STYLES = {
  running:      { color: 'emerald', pulse: true, label: 'RUNNING' },
  pending:      { color: 'amber',   pulse: true, label: 'PENDING' },
  queued:       { color: 'amber',   pulse: true, label: 'QUEUED' },
  discovering:  { color: 'cyan',    pulse: true, label: 'CRAWLING' },
  analyzing:    { color: 'cyan',    pulse: true, label: 'ANALYZE' },
  verifying:    { color: 'cyan',    pulse: true, label: 'VERIFY' },
  cancelling:   { color: 'amber',   pulse: true, label: 'STOPPING' },
  completed:    { color: 'emerald', pulse: false, label: 'DONE' },
  failed:       { color: 'red',     pulse: false, label: 'FAILED' },
  cancelled:    { color: 'zinc',    pulse: false, label: 'CANCELLED' },
};
const STATUS_TXT = {
  emerald: 'text-emerald-300 border-emerald-500/40 bg-emerald-500/10',
  amber:   'text-amber-300 border-amber-500/40 bg-amber-500/10',
  cyan:    'text-cyan-300 border-cyan-500/40 bg-cyan-500/10',
  red:     'text-red-300 border-red-500/40 bg-red-500/10',
  zinc:    'text-zinc-400 border-zinc-700 bg-zinc-800/50',
};
export function StatusPill({ status, className = '' }) {
  const conf = STATUS_STYLES[status] || STATUS_STYLES.pending;
  const cls = STATUS_TXT[conf.color];
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 border mono text-[10px] uppercase tracking-widest ${cls} ${className}`}>
      {conf.pulse && <RippleDot color={conf.color} size="sm" />}
      {conf.label}
    </span>
  );
}
