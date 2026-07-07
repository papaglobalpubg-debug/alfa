import React, { useState, useRef, useEffect } from 'react';
import { HelpCircle, X } from 'lucide-react';

/**
 * HelpTip — tiny hover/click info popover.
 * Usage:  <HelpTip title="Dashboard" body="..." />
 */
export default function HelpTip({ title, body, testId, className = '' }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    const h = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, []);

  return (
    <span ref={ref} className={`relative inline-block ${className}`}>
      <button
        type="button"
        onClick={() => setOpen(!open)}
        data-testid={testId || 'help-tip'}
        className="inline-flex items-center justify-center w-5 h-5 text-zinc-500 hover:text-emerald-400 transition-colors"
        aria-label="Help"
      >
        <HelpCircle className="w-4 h-4" strokeWidth={1.75} />
      </button>
      {open && (
        <div className="absolute z-50 top-6 start-0 w-72 bg-zinc-900 border border-zinc-700 shadow-xl p-3 text-start">
          <div className="flex items-start justify-between gap-2 mb-1.5">
            <div className="text-xs mono uppercase tracking-widest text-emerald-400">{title}</div>
            <button onClick={() => setOpen(false)} className="text-zinc-500 hover:text-zinc-200">
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
          <div className="text-xs text-zinc-300 leading-5">{body}</div>
        </div>
      )}
    </span>
  );
}
