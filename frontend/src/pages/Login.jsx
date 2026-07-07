import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useAuth } from '@/lib/auth';
import LanguageSwitcher from '@/components/LanguageSwitcher';
import { Radar, LogIn, Mail, KeyRound, ArrowLeft, ShieldCheck, Sparkles, Bug } from 'lucide-react';

export default function Login() {
  const { t } = useTranslation();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const { login, error } = useAuth();
  const nav = useNavigate();

  const submit = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    const res = await login(email, password);
    setSubmitting(false);
    if (res.ok) nav('/dashboard');
  };

  return (
    <div data-testid="login-page" className="min-h-screen bg-zinc-950 text-zinc-100 flex flex-col md:flex-row">
      {/* Left panel — brand + benefits */}
      <div className="relative md:w-1/2 flex flex-col p-6 md:p-12 border-b md:border-b-0 md:border-e border-zinc-900 overflow-hidden">
        <div className="absolute inset-0 pointer-events-none">
          <div className="absolute top-0 start-1/3 w-96 h-96 bg-emerald-500/10 blur-3xl rounded-full" />
          <div className="absolute bottom-0 end-1/4 w-96 h-96 bg-red-500/10 blur-3xl rounded-full" />
        </div>
        <div className="relative flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2 font-display font-bold text-zinc-100" data-testid="login-logo">
            <Radar className="w-6 h-6 text-emerald-500" strokeWidth={1.5} />
            <span className="text-xl">CYBER<span className="text-emerald-500">.</span>SCOPE</span>
            <span className="text-[10px] mono text-zinc-500 ms-1">{t('brand.version')}</span>
          </Link>
          <LanguageSwitcher />
        </div>

        <div className="relative flex-1 flex flex-col justify-center max-w-md">
          <div className="inline-flex items-center gap-2 text-[10px] mono uppercase tracking-widest text-emerald-400 border border-emerald-500/40 bg-emerald-500/10 px-2 py-1 mb-6 w-fit">
            <Sparkles className="w-3 h-3" /> {t('brand.tagline')}
          </div>
          <h1 className="text-3xl md:text-4xl font-display font-bold leading-tight">
            {t('auth.signin.title')}
          </h1>
          <p className="mt-3 text-zinc-400 text-sm">{t('auth.signin.subtitle')}</p>

          <div className="mt-10 space-y-4">
            {[
              { icon: Bug,         text: '54 attack modules · deep crawler v2 · AI Autopilot' },
              { icon: ShieldCheck, text: 'SSRF-guarded · owner-scoped · rate-limited' },
              { icon: Sparkles,    text: 'Triple-model AI verification (Claude · GPT · Gemini)' },
            ].map((f, i) => (
              <div key={i} className="flex items-start gap-3 text-sm text-zinc-300">
                <f.icon className="w-4 h-4 text-emerald-400 mt-0.5 shrink-0" />
                <span>{f.text}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="relative text-[11px] mono text-zinc-600 mt-8">
          <Link to="/" className="hover:text-zinc-400 inline-flex items-center gap-1" data-testid="login-back-home">
            <ArrowLeft className="w-3 h-3" /> {t('nav.home')}
          </Link>
        </div>
      </div>

      {/* Right panel — form */}
      <div className="md:w-1/2 flex items-center justify-center p-6 md:p-12">
        <form
          onSubmit={submit}
          data-testid="login-form"
          className="w-full max-w-sm space-y-5"
        >
          <div>
            <div className="text-[10px] mono uppercase tracking-widest text-zinc-500 mb-1">// {t('nav.signin')}</div>
            <h2 className="text-2xl font-display font-bold text-zinc-50">{t('auth.signin.submit')}</h2>
          </div>

          <label className="block">
            <div className="text-xs uppercase tracking-widest text-zinc-500 mono mb-1.5 flex items-center gap-1">
              <Mail className="w-3 h-3" /> {t('auth.signin.email')}
            </div>
            <input
              data-testid="login-email-input"
              type="email"
              required
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-3 py-2.5 bg-zinc-900 border border-zinc-800 text-zinc-50 mono focus:outline-none focus:border-emerald-500 transition-colors"
            />
          </label>

          <label className="block">
            <div className="text-xs uppercase tracking-widest text-zinc-500 mono mb-1.5 flex items-center gap-1">
              <KeyRound className="w-3 h-3" /> {t('auth.signin.password')}
            </div>
            <input
              data-testid="login-password-input"
              type="password"
              required
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-3 py-2.5 bg-zinc-900 border border-zinc-800 text-zinc-50 mono focus:outline-none focus:border-emerald-500 transition-colors"
            />
          </label>

          {error && (
            <div
              data-testid="login-error"
              className="bg-red-500/10 border border-red-500/30 text-red-400 px-3 py-2 mono text-xs"
            >
              {error}
            </div>
          )}

          <button
            data-testid="login-submit"
            type="submit"
            disabled={submitting}
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-emerald-500 text-zinc-950 font-semibold hover:bg-emerald-400 disabled:opacity-50 mono text-sm transition-colors"
          >
            <LogIn className="w-4 h-4" /> {submitting ? t('auth.signin.loading') : t('auth.signin.submit')}
          </button>

          <div className="text-center text-xs text-zinc-500 mono pt-4 border-t border-zinc-800">
            {t('auth.signin.noAccount')}{' '}
            <Link
              to="/register"
              data-testid="link-register"
              className="text-emerald-500 hover:underline"
            >
              {t('auth.signin.createAccount')}
            </Link>
          </div>
        </form>
      </div>
    </div>
  );
}
