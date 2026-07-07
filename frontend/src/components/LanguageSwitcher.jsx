import React, { useState, useRef, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { Globe, ChevronDown, Check } from 'lucide-react';

const LANGS = [
  { code: 'en', label: 'English', flag: 'EN' },
  { code: 'ar', label: 'العربية',  flag: 'ع' },
  { code: 'fr', label: 'Français', flag: 'FR' },
];

export default function LanguageSwitcher({ compact = false, alignRight = true }) {
  const { i18n } = useTranslation();
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    const h = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, []);

  const current = LANGS.find((l) => l.code === i18n.language) || LANGS[0];

  const pick = (code) => {
    i18n.changeLanguage(code);
    setOpen(false);
  };

  return (
    <div ref={ref} className="relative inline-block">
      <button
        onClick={() => setOpen(!open)}
        data-testid="language-switcher"
        className={`flex items-center gap-1.5 border border-zinc-700 hover:border-zinc-500 text-zinc-100 mono text-xs ${
          compact ? 'px-2 py-1' : 'px-3 py-1.5'
        }`}
      >
        <Globe className="w-3.5 h-3.5" />
        {!compact && <span>{current.flag}</span>}
        <ChevronDown className="w-3 h-3 opacity-60" />
      </button>
      {open && (
        <div
          data-testid="language-menu"
          className={`absolute z-50 mt-1 min-w-[140px] bg-zinc-900 border border-zinc-700 shadow-lg ${
            alignRight ? 'right-0' : 'left-0'
          }`}
        >
          {LANGS.map((l) => (
            <button
              key={l.code}
              onClick={() => pick(l.code)}
              data-testid={`lang-option-${l.code}`}
              className={`w-full text-start flex items-center justify-between gap-2 px-3 py-2 text-sm hover:bg-zinc-800 ${
                current.code === l.code ? 'text-emerald-400' : 'text-zinc-100'
              }`}
            >
              <span className="flex items-center gap-2">
                <span className="mono text-[10px] text-zinc-500 w-4">{l.flag}</span>
                {l.label}
              </span>
              {current.code === l.code && <Check className="w-3.5 h-3.5" />}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
