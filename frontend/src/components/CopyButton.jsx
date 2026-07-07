import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';

/**
 * Universal copy-to-clipboard button.
 * Usage:
 *   <CopyButton text="..." label="Copy URL" />
 *   <CopyButton text="..." variant="icon" /> // icon-only
 */
export default function CopyButton({
  text,
  label,
  variant = 'icon',   // 'icon' | 'button' | 'inline'
  className = '',
  testid,
  onCopy,
}) {
  const [copied, setCopied] = useState(false);

  const doCopy = async (e) => {
    e?.stopPropagation?.();
    e?.preventDefault?.();
    if (!text) return;
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(String(text));
      } else {
        // Fallback for http/localhost
        const ta = document.createElement('textarea');
        ta.value = String(text);
        ta.style.position = 'fixed'; ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.focus(); ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      }
      setCopied(true);
      onCopy?.(text);
      setTimeout(() => setCopied(false), 1300);
    } catch (err) {
      // Silent
    }
  };

  const commonProps = {
    onClick: doCopy,
    'data-testid': testid || 'copy-btn',
    title: copied ? 'Copied!' : (label || 'Copy'),
    disabled: !text,
  };

  if (variant === 'inline') {
    return (
      <button
        {...commonProps}
        className={`inline-flex items-center gap-1 text-[10px] mono uppercase tracking-widest ${
          copied ? 'text-emerald-400' : 'text-zinc-500 hover:text-emerald-400'
        } transition-colors ${className}`}
      >
        {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
        {label && <span>{copied ? 'Copied' : label}</span>}
      </button>
    );
  }

  if (variant === 'button') {
    return (
      <button
        {...commonProps}
        className={`inline-flex items-center gap-2 px-3 py-1.5 border ${
          copied
            ? 'border-emerald-500/50 text-emerald-400 bg-emerald-500/10'
            : 'border-zinc-800 text-zinc-400 hover:text-emerald-400 hover:border-emerald-500/40'
        } mono text-xs transition-colors ${className}`}
      >
        {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
        {copied ? 'Copied' : (label || 'Copy')}
      </button>
    );
  }

  // icon variant (default)
  return (
    <button
      {...commonProps}
      className={`p-1 rounded-sm ${
        copied ? 'text-emerald-400' : 'text-zinc-500 hover:text-emerald-400 hover:bg-zinc-900'
      } transition-colors ${className}`}
    >
      {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  );
}

/**
 * Copyable wrapper — wraps any text-like content so clicking copies it.
 * Better UX for URLs, payloads, evidence blobs.
 */
export function Copyable({ children, text, className = '', testid }) {
  const [copied, setCopied] = useState(false);
  const doCopy = async (e) => {
    e.stopPropagation();
    if (!text) return;
    try {
      await navigator.clipboard.writeText(String(text));
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch (err) {
      /* silent */
    }
  };
  return (
    <span
      role="button"
      tabIndex={0}
      onClick={doCopy}
      onKeyDown={(e) => { if (e.key === 'Enter') doCopy(e); }}
      data-testid={testid || 'copyable-text'}
      className={`cursor-copy hover:text-emerald-400 transition-colors relative group ${className}`}
      title={copied ? 'Copied!' : 'Click to copy'}
    >
      {children}
      <span className={`ml-1 inline-block align-middle transition-opacity ${copied ? 'opacity-100' : 'opacity-0 group-hover:opacity-70'}`}>
        {copied ? <Check className="w-3 h-3 text-emerald-400 inline" /> : <Copy className="w-3 h-3 text-zinc-500 inline" />}
      </span>
    </span>
  );
}
