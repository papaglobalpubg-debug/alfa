import React, { useEffect, useState } from 'react';
import { AlertCircle, RefreshCw } from 'lucide-react';
import api from '@/lib/api';

/**
 * Health banner — visible ONLY when backend is unreachable.
 * Auto-hides once the backend responds.
 */
export default function BackendHealthBanner() {
  const [status, setStatus] = useState('checking'); // 'checking' | 'ok' | 'unreachable'
  const [detail, setDetail] = useState('');

  const check = async () => {
    try {
      const r = await api.health();
      if (r?.data?.ok) {
        setStatus('ok');
      } else {
        setStatus('unreachable');
        setDetail('Backend responded but not healthy');
      }
    } catch (e) {
      setStatus('unreachable');
      setDetail(e?.message || 'Network Error');
    }
  };

  useEffect(() => {
    check();
    const iv = setInterval(check, 15000);
    return () => clearInterval(iv);
  }, []);

  if (status !== 'unreachable') return null;

  const backendUrl = process.env.REACT_APP_BACKEND_URL || '(not configured)';

  return (
    <div className="fixed top-[22px] left-0 right-0 z-[55] bg-red-500/95 text-white p-3 shadow-lg" data-testid="backend-unreachable-banner">
      <div className="max-w-5xl mx-auto flex items-start gap-3">
        <AlertCircle className="w-5 h-5 flex-shrink-0 mt-0.5" />
        <div className="flex-1 text-xs mono">
          <div className="font-bold text-sm mb-1">⚠ Backend Unreachable — Network Error</div>
          <div className="opacity-90">
            Trying: <span className="underline">{backendUrl}/api/health</span> &nbsp;·&nbsp; {detail}
          </div>
          <div className="mt-2 opacity-90">
            <strong>Fixes:</strong> {' '}
            (1) Is the backend running? Run <code className="bg-black/30 px-1">./start.sh</code> {' '}
            (2) Check port 8001 is open {' '}
            (3) Run <code className="bg-black/30 px-1">./diagnose.sh</code> for a full checkup
          </div>
        </div>
        <button
          onClick={check}
          data-testid="retry-health-btn"
          className="flex items-center gap-1 px-3 py-1.5 bg-white/20 hover:bg-white/30 border border-white/40 mono text-xs uppercase tracking-wider transition-colors"
        >
          <RefreshCw className="w-3 h-3" /> Retry
        </button>
      </div>
    </div>
  );
}
