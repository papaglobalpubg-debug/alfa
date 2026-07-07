import React from 'react';

const PRIO_STYLES = {
  critical: 'bg-red-500/10 text-red-400 border-red-500/30',
  high: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
  medium: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
  low: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
};

const CLASS_STYLES = {
  CLAIMABLE: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
  VERIFY_REQUIRED: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
  SERVICE_ACTIVE: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
  DEAD: 'bg-zinc-500/10 text-zinc-500 border-zinc-500/30',
  ALIVE: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
  NXDOMAIN: 'bg-zinc-800 text-zinc-500 border-zinc-700',
  WILDCARD: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
  HTTP_ERROR: 'bg-red-500/10 text-red-400 border-red-500/30',
  NO_MATCH: 'bg-zinc-800 text-zinc-500 border-zinc-700',
  pending: 'bg-zinc-800 text-zinc-400 border-zinc-700',
  discovering: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
  analyzing: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
  verifying: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
  completed: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
  failed: 'bg-red-500/10 text-red-400 border-red-500/30',
};

export function PriorityBadge({ priority, testid }) {
  if (!priority) return null;
  const key = priority.toLowerCase();
  const style = PRIO_STYLES[key] || 'bg-zinc-800 text-zinc-400 border-zinc-700';
  return (
    <span
      data-testid={testid}
      className={`inline-block px-2 py-0.5 mono text-[10px] font-semibold uppercase tracking-wider border ${style}`}
    >
      {priority}
    </span>
  );
}

export function StatusBadge({ status, testid }) {
  if (!status) return null;
  const style = CLASS_STYLES[status] || 'bg-zinc-800 text-zinc-400 border-zinc-700';
  return (
    <span
      data-testid={testid}
      className={`inline-block px-2 py-0.5 mono text-[10px] font-semibold uppercase tracking-wider border ${style}`}
    >
      {status.replace('_', ' ')}
    </span>
  );
}

export function StatCard({ label, value, tone = 'default', icon: Icon, testid }) {
  const toneMap = {
    default: 'text-zinc-50',
    critical: 'text-red-400',
    success: 'text-emerald-400',
    warning: 'text-amber-400',
    info: 'text-blue-400',
    muted: 'text-zinc-500',
  };
  return (
    <div
      data-testid={testid}
      className="bg-zinc-900 border border-zinc-800 p-4 hover:border-zinc-700 transition-colors duration-150"
    >
      <div className="flex items-start justify-between">
        <div>
          <div className={`text-3xl font-semibold mono ${toneMap[tone]}`}>
            {value}
          </div>
          <div className="text-[10px] uppercase tracking-widest text-zinc-500 mt-1 mono">
            {label}
          </div>
        </div>
        {Icon && <Icon className="w-4 h-4 text-zinc-600" strokeWidth={1.5} />}
      </div>
    </div>
  );
}

export function AsciiLoader({ progress }) {
  const width = 20;
  const filled = Math.max(0, Math.min(width, Math.round((progress / 100) * width)));
  const bar = '#'.repeat(filled) + '.'.repeat(width - filled);
  return (
    <span className="ascii-loader">
      [{bar}] {progress}%
    </span>
  );
}

export function PulseDot() {
  return <span className="pulse-dot" />;
}
