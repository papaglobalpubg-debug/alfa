import React, { useState } from 'react';
import { Sparkles, X, Loader2, AlertCircle } from 'lucide-react';
import api from '@/lib/api';
import CopyButton from '@/components/CopyButton';

/**
 * AI-powered explanation modal for a single finding.
 * Uses Claude Sonnet 4.6 via Emergent LLM key.
 */
export default function AIExplainModal({ scanId, findingIndex, finding, onClose }) {
  const [lang, setLang] = useState('ar');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const run = async (targetLang) => {
    setLoading(true);
    setResult(null);
    try {
      const r = await api.explainFinding(scanId, findingIndex, targetLang || lang);
      setResult(r.data);
    } catch (e) {
      setResult({ error: String(e?.message || e) });
    } finally {
      setLoading(false);
    }
  };

  React.useEffect(() => {
    run(lang);
  }, []);

  return (
    <div className="fixed inset-0 z-[100] bg-black/70 backdrop-blur-sm flex items-center justify-center p-4"
         onClick={onClose} data-testid="ai-explain-modal">
      <div className="bg-zinc-950 border border-emerald-500/40 max-w-3xl w-full max-h-[85vh] overflow-hidden flex flex-col"
           onClick={e => e.stopPropagation()}>
        <div className="p-4 border-b border-zinc-800 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-emerald-500" />
            <div>
              <div className="text-sm font-bold text-zinc-50">AI Vulnerability Analysis</div>
              <div className="text-[10px] mono text-zinc-500 uppercase tracking-widest">
                {finding.type}·{finding.subtype || ''} · Claude Sonnet 4.6
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={() => { setLang('ar'); run('ar'); }}
                    className={`px-3 py-1 text-xs mono uppercase tracking-widest border ${
                      lang === 'ar' ? 'border-emerald-500 text-emerald-400 bg-emerald-500/10' :
                                      'border-zinc-800 text-zinc-500 hover:text-zinc-300'
                    }`}>عربي</button>
            <button onClick={() => { setLang('en'); run('en'); }}
                    className={`px-3 py-1 text-xs mono uppercase tracking-widest border ${
                      lang === 'en' ? 'border-emerald-500 text-emerald-400 bg-emerald-500/10' :
                                      'border-zinc-800 text-zinc-500 hover:text-zinc-300'
                    }`}>English</button>
            <button onClick={onClose} className="p-1 text-zinc-500 hover:text-red-400" data-testid="close-ai-modal">
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-6">
          {loading && (
            <div className="flex items-center justify-center py-16 text-zinc-500 mono text-sm gap-3">
              <Loader2 className="w-6 h-6 animate-spin text-emerald-500" />
              {lang === 'ar' ? 'الذكاء الاصطناعي يحلّل الثغرة...' : 'AI is analyzing the vulnerability...'}
            </div>
          )}

          {result?.error && (
            <div className="border border-red-500/40 bg-red-500/10 p-4 mono text-xs text-red-400 flex gap-3">
              <AlertCircle className="w-5 h-5 shrink-0" />
              <div className="whitespace-pre-wrap break-words">{result.error}</div>
            </div>
          )}

          {result?.explanation && (
            <div className="prose prose-invert prose-sm max-w-none"
                 dir={lang === 'ar' ? 'rtl' : 'ltr'}
                 style={{ fontFamily: lang === 'ar' ? 'system-ui, sans-serif' : 'monospace' }}
                 dangerouslySetInnerHTML={{ __html: mdToHtml(result.explanation) }}
            />
          )}
        </div>

        {result?.explanation && (
          <div className="p-3 border-t border-zinc-800 flex justify-between items-center shrink-0">
            <div className="text-[10px] mono text-zinc-500">
              Model: {result.model || 'claude-sonnet-4-6'}
            </div>
            <CopyButton text={result.explanation} variant="button" label="Copy analysis" testid="copy-ai-analysis" />
          </div>
        )}
      </div>
    </div>
  );
}

function mdToHtml(md) {
  if (!md) return '';
  let h = md
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/```([a-z]*)\n([\s\S]*?)```/g, '<pre class="bg-zinc-900 p-3 border border-zinc-800 my-2 overflow-x-auto text-emerald-400"><code>$2</code></pre>')
    .replace(/`([^`]+)`/g, '<code class="bg-zinc-900 px-1 text-emerald-400">$1</code>')
    .replace(/^### (.+)$/gm, '<h3 class="text-base font-bold text-emerald-400 mt-4 mb-2">$1</h3>')
    .replace(/^## (.+)$/gm, '<h2 class="text-lg font-bold text-red-400 mt-5 mb-2 border-b border-zinc-800 pb-1">$1</h2>')
    .replace(/^# (.+)$/gm, '<h1 class="text-xl font-bold text-zinc-50 mt-6 mb-3">$1</h1>')
    .replace(/\*\*(.+?)\*\*/g, '<strong class="text-zinc-100">$1</strong>')
    .replace(/^- (.+)$/gm, '<li class="ml-4 text-zinc-300">$1</li>')
    .replace(/^\d+\.\s(.+)$/gm, '<li class="ml-4 text-zinc-300">$1</li>')
    .replace(/\n\n/g, '</p><p class="text-zinc-300 my-2">')
    .replace(/^(?!<[hplc])/gm, '<p class="text-zinc-300 my-2">');
  return h;
}
