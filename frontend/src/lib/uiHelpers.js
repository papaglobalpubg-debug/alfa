// Presentation helpers — extract nested ternaries into named functions
// to improve readability and testability.

/**
 * Return Tailwind classes for a scan status badge.
 * Terminal states use static colors, running states pulse.
 */
export function scanStatusColor(status, { running = null } = {}) {
  if (status === 'completed') return 'text-emerald-500';
  if (status === 'failed') return 'text-red-500';
  const isRunning = running !== null ? running : !['completed', 'failed'].includes(status);
  return isRunning ? 'text-yellow-400 animate-pulse' : 'text-zinc-500';
}

/**
 * Return Tailwind color for a single log line based on its severity markers.
 */
export function logLineColor(line) {
  if (!line) return 'text-zinc-500';
  if (line.includes('ERROR') || line.includes('[!]')) return 'text-red-400';
  if (line.includes('[+]')) return 'text-emerald-500';
  if (line.includes('[*]')) return 'text-zinc-400';
  return 'text-zinc-500';
}

/**
 * Return the CSS class for a takeover-scan log line.
 */
export function scanLogClass({ isErr, isWarn }) {
  if (isErr) return 'log-err';
  if (isWarn) return 'log-warn';
  return '';
}

/**
 * Return graph node radius based on group.
 */
export function graphNodeSize(group) {
  if (group === 'verified' || group === 'claimable') return 8;
  if (group === 'verify' || group === 'active') return 6;
  return 4;
}
