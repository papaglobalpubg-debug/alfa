import React, { useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useAuth } from '@/lib/auth';
import LanguageSwitcher from '@/components/LanguageSwitcher';
import { Radar, UserPlus, User, KeyRound, Mail, ArrowLeft, CheckCircle2 } from 'lucide-react';

export default function Register() {
  const { t } = useTranslation();
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [password2, setPassword2] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [localErr, setLocalErr] = useState('');
  const { register, error } = useAuth();
  const nav = useNavigate();
  const [params] = useSearchParams();
  const next = params.get('next') || '/dashboard';

  const submit = async (e) => {
    e.preventDefault();
    setLocalErr('');
    if (password.length < 8) {
      setLocalErr(t('auth.signup.passwordTooShort'));
      return;
    }
    if (password !== password2) {
      setLocalErr(t('auth.signup.passwordMismatch'));
      return;
    }
    setSubmitting(true);
    const res = await register(email, password, name);
    setSubmitting(false);
    if (res.ok) nav(next);
  };

  const displayErr = localErr || error;

  return (
    <div data-testid="register-page" className="min-h-screen bg-zinc-950 text-zinc-100 flex flex-col md:flex-row">
      {/* Left brand panel */}
      <div className="relative md:w-1/2 flex flex-col p-6 md:p-12 border-b md:border-b-0 md:border-e border-zinc-900 overflow-hidden">
        <div className="absolute inset-0 pointer-events-none">
          <div className="absolute top-0 end-1/4 w-96 h-96 bg-fuchsia-500/10 blur-3xl rounded-full" />
          <div className="absolute bottom-0 start-1/3 w-96 h-96 bg-emerald-500/10 blur-3xl rounded-full" />
        </div>
        <div className="relative flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2 font-display font-bold text-zinc-100" data-testid="register-logo">
            <Radar className="w-6 h-6 text-emerald-500" strokeWidth={1.5} />
            <span className="text-xl">CYBER<span className="text-emerald-500">.</span>SCOPE</span>
            <span className="text-[10px] mono text-zinc-500 ms-1">{t('brand.version')}</span>
          </Link>
          <LanguageSwitcher />
        </div>

        <div className="relative flex-1 flex flex-col justify-center max-w-md">
          <h1 className="text-3xl md:text-4xl font-display font-bold leading-tight">
            {t('auth.signup.title')}
          </h1>
          <p className="mt-3 text-zinc-400 text-sm">{t('auth.signup.subtitle')}</p>

          <div className="mt-8 space-y-3">
            {[
              '5 free deep scans per month',
              'All 54 attack modules',
              'Cancel anytime · no credit card',
            ].map((s, i) => (
              <div key={i} className="flex items-start gap-2 text-sm text-zinc-300">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 mt-0.5 shrink-0" />
                <span>{s}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="relative text-[11px] mono text-zinc-600 mt-8">
          <Link to="/" className="hover:text-zinc-400 inline-flex items-center gap-1" data-testid="register-back-home">
            <ArrowLeft className="w-3 h-3" /> {t('nav.home')}
          </Link>
        </div>
      </div>

      {/* Right form panel */}
      <div className="md:w-1/2 flex items-center justify-center p-6 md:p-12">
        <form
          onSubmit={submit}
          data-testid="register-form"
          className="w-full max-w-sm space-y-4"
        >
          <div>
            <div className="text-[10px] mono uppercase tracking-widest text-zinc-500 mb-1">// {t('nav.signup')}</div>
            <h2 className="text-2xl font-display font-bold text-zinc-50">{t('auth.signup.submit')}</h2>
          </div>

          <label className="block">
            <div className="text-xs uppercase tracking-widest text-zinc-500 mono mb-1.5 flex items-center gap-1">
              <Mail className="w-3 h-3" /> {t('auth.signup.email')}
            </div>
            <input
              data-testid="register-email-input"
              type="email" required autoComplete="email"
              value={email} onChange={(e) => setEmail(e.target.value)}
              className="w-full px-3 py-2.5 bg-zinc-900 border border-zinc-800 text-zinc-50 mono focus:outline-none focus:border-emerald-500 transition-colors"
            />
          </label>

          <label className="block">
            <div className="text-xs uppercase tracking-widest text-zinc-500 mono mb-1.5 flex items-center gap-1">
              <User className="w-3 h-3" /> {t('auth.signup.name')}
            </div>
            <input
              data-testid="register-name-input"
              type="text" autoComplete="name"
              value={name} onChange={(e) => setName(e.target.value)}
              className="w-full px-3 py-2.5 bg-zinc-900 border border-zinc-800 text-zinc-50 mono focus:outline-none focus:border-emerald-500 transition-colors"
            />
          </label>

          <label className="block">
            <div className="text-xs uppercase tracking-widest text-zinc-500 mono mb-1.5 flex items-center gap-1">
              <KeyRound className="w-3 h-3" /> {t('auth.signup.password')}
            </div>
            <input
              data-testid="register-password-input"
              type="password" required autoComplete="new-password" minLength={8}
              value={password} onChange={(e) => setPassword(e.target.value)}
              className="w-full px-3 py-2.5 bg-zinc-900 border border-zinc-800 text-zinc-50 mono focus:outline-none focus:border-emerald-500 transition-colors"
            />
          </label>

          <label className="block">
            <div className="text-xs uppercase tracking-widest text-zinc-500 mono mb-1.5">
              {t('auth.signup.password2')}
            </div>
            <input
              data-testid="register-password2-input"
              type="password" required autoComplete="new-password"
              value={password2} onChange={(e) => setPassword2(e.target.value)}
              className="w-full px-3 py-2.5 bg-zinc-900 border border-zinc-800 text-zinc-50 mono focus:outline-none focus:border-emerald-500 transition-colors"
            />
          </label>

          {displayErr && (
            <div
              data-testid="register-error"
              className="bg-red-500/10 border border-red-500/30 text-red-400 px-3 py-2 mono text-xs"
            >
              {displayErr}
            </div>
          )}

          <button
            data-testid="register-submit"
            type="submit"
            disabled={submitting}
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-emerald-500 text-zinc-950 font-semibold hover:bg-emerald-400 disabled:opacity-50 mono text-sm transition-colors"
          >
            <UserPlus className="w-4 h-4" /> {submitting ? t('auth.signup.loading') : t('auth.signup.submit')}
          </button>

          <div className="text-center text-xs text-zinc-500 mono pt-4 border-t border-zinc-800">
            {t('auth.signup.haveAccount')}{' '}
            <Link
              to="/login"
              data-testid="link-login"
              className="text-emerald-500 hover:underline"
            >
              {t('auth.signup.signin')}
            </Link>
          </div>
        </form>
      </div>
    </div>
  );
}
