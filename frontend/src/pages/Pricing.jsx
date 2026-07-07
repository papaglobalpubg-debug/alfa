import React, { useEffect, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useAuth } from '@/lib/auth';
import api from '@/lib/api';
import LanguageSwitcher from '@/components/LanguageSwitcher';
import { Check, X, Sparkles, ArrowRight, Radar, ShieldCheck } from 'lucide-react';

const MATRIX_ROWS = [
  { key: 'modules',    values: [false, true, true, true, true] },
  { key: 'crawler',    values: ['basic', true, true, true, true] },
  { key: 'ai',         values: [false, false, true, true, true] },
  { key: 'monitors',   values: [false, true, true, true, true] },
  { key: 'cve',        values: [false, false, true, true, true] },
  { key: 'team',       values: [false, false, false, true, true] },
  { key: 'api',        values: [false, false, false, true, true] },
  { key: 'whitelabel', values: [false, false, false, true, true] },
  { key: 'download',   values: [false, false, false, true, true] },
  { key: 'lifetime',   values: [false, false, false, false, true] },
];

export default function Pricing() {
  const { t, i18n } = useTranslation();
  const nav = useNavigate();
  const { user } = useAuth();
  const [tiers, setTiers] = useState([]);
  const [status, setStatus] = useState(null);
  const [loadingTier, setLoadingTier] = useState(null);
  const [error, setError] = useState('');
  const [params] = useSearchParams();
  const canceled = params.get('canceled') === '1';
  const isRtl = i18n.language === 'ar';

  useEffect(() => {
    api.billingTiers()
      .then((r) => setTiers(r.data?.tiers || []))
      .catch(() => setError('Failed to load pricing tiers'));
    api.billingStatus()
      .then((r) => setStatus(r.data))
      .catch(() => {});
  }, []);

  const checkout = async (tier) => {
    if (!user) {
      nav(`/register?next=/pricing&tier=${tier}`);
      return;
    }
    if (tier === 'free') {
      nav('/dashboard');
      return;
    }
    setLoadingTier(tier);
    setError('');
    try {
      const { data } = await api.billingCheckout(tier);
      if (data?.url) window.location.href = data.url;
    } catch (e) {
      setError(e.response?.data?.detail || 'Checkout failed');
    } finally {
      setLoadingTier(null);
    }
  };

  const currentTier = status?.tier || 'free';

  return (
    <div data-testid="pricing-page" className="min-h-screen bg-zinc-950 text-zinc-100" dir={isRtl ? 'rtl' : 'ltr'}>
      <header className="sticky top-0 z-40 backdrop-blur bg-zinc-950/80 border-b border-zinc-800">
        <div className="max-w-6xl mx-auto px-4 h-14 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2 font-display font-bold" data-testid="pricing-logo">
            <Radar className="w-5 h-5 text-emerald-500" strokeWidth={1.5} />
            <span>CYBER<span className="text-emerald-500">.</span>SCOPE</span>
          </Link>
          <nav className="flex items-center gap-3 text-sm text-zinc-400">
            <Link to="/" className="hover:text-zinc-100">{t('nav.home')}</Link>
            <LanguageSwitcher />
            {user ? (
              <Link to="/dashboard" className="text-emerald-400 hover:text-emerald-300">{t('nav.dashboard')} →</Link>
            ) : (
              <Link to="/login" className="hover:text-zinc-100">{t('nav.signin')}</Link>
            )}
          </nav>
        </div>
      </header>

      <section className="max-w-6xl mx-auto px-4 pt-16 pb-8 text-center">
        <div className="inline-flex items-center gap-2 text-[10px] mono uppercase tracking-widest text-emerald-400 border border-emerald-500/40 bg-emerald-500/10 px-2 py-1 mb-6">
          <Sparkles className="w-3 h-3" /> {t('pricing.badge')}
        </div>
        <h1 className="text-4xl sm:text-5xl font-display font-bold">{t('pricing.title')}</h1>
        <p className="mt-4 text-zinc-400 max-w-lg mx-auto text-sm">{t('pricing.body')}</p>
        {canceled && (
          <div className="mt-4 inline-block text-amber-300 text-xs mono border border-amber-500/40 bg-amber-500/10 px-3 py-1">
            {t('pricing.canceled')}
          </div>
        )}
        {error && (
          <div className="mt-4 inline-block text-red-300 text-xs mono border border-red-500/40 bg-red-500/10 px-3 py-1" data-testid="pricing-error">
            {error}
          </div>
        )}
      </section>

      <section className="max-w-6xl mx-auto px-4 pb-20">
        <div className="grid md:grid-cols-2 lg:grid-cols-5 gap-3">
          {tiers.map((tier) => {
            const isCurrent = user && currentTier === tier.id;
            return (
              <div
                key={tier.id}
                data-testid={`pricing-tier-${tier.id}`}
                className={`relative bg-zinc-900/70 border p-5 flex flex-col ${
                  tier.popular
                    ? 'border-emerald-500 shadow-[0_0_40px_-15px_rgba(16,185,129,0.6)]'
                    : tier.id === 'lifetime'
                    ? 'border-amber-500/60'
                    : 'border-zinc-800'
                }`}
              >
                {tier.popular && (
                  <div className="absolute -top-3 start-4 text-[9px] mono uppercase tracking-widest bg-emerald-500 text-zinc-950 px-2 py-0.5">
                    {t('landing.pricing.mostPopular')}
                  </div>
                )}
                {tier.id === 'lifetime' && (
                  <div className="absolute -top-3 start-4 text-[9px] mono uppercase tracking-widest bg-amber-500 text-zinc-950 px-2 py-0.5">
                    {t('landing.pricing.bestValue')}
                  </div>
                )}
                <div className="text-[10px] mono uppercase tracking-widest text-zinc-500">{tier.id}</div>
                <div className="font-display font-bold text-lg mt-1">{tier.name}</div>
                <div className="mt-3">
                  <span className="text-3xl font-bold">${(tier.price_cents / 100).toFixed(0)}</span>
                  {tier.interval && <span className="text-zinc-500 text-sm"> {t('landing.pricing.perMonth')}</span>}
                  {!tier.interval && tier.price_cents > 0 && <span className="text-zinc-500 text-sm"> {t('landing.pricing.oneTime')}</span>}
                </div>
                <p className="text-xs text-zinc-400 mt-2 min-h-[36px]">{tier.blurb}</p>
                <div className="mt-3 grid grid-cols-2 gap-1.5 text-[11px] mono">
                  <div className="border border-zinc-800 bg-zinc-950/50 p-1.5">
                    <div className="text-zinc-500 uppercase tracking-wider text-[9px]">{t('landing.pricing.scansPerMonth')}</div>
                    <div className="text-zinc-100 text-sm">{tier.quota_scans_per_month.toLocaleString()}</div>
                  </div>
                  <div className="border border-zinc-800 bg-zinc-950/50 p-1.5">
                    <div className="text-zinc-500 uppercase tracking-wider text-[9px]">{t('landing.pricing.targets')}</div>
                    <div className="text-zinc-100 text-sm">{tier.quota_targets}</div>
                  </div>
                </div>
                <ul className="mt-3 space-y-1.5 flex-1">
                  {(tier.features || []).map((f) => (
                    <li key={f} className="flex items-start gap-1.5 text-[11px] text-zinc-300 leading-4">
                      <Check className="w-3 h-3 text-emerald-400 mt-0.5 shrink-0" />
                      <span>{f}</span>
                    </li>
                  ))}
                </ul>
                <button
                  onClick={() => checkout(tier.id)}
                  disabled={loadingTier === tier.id || isCurrent}
                  data-testid={`checkout-${tier.id}`}
                  className={`mt-4 py-2 font-mono text-xs font-semibold transition-colors disabled:opacity-60 disabled:cursor-not-allowed ${
                    isCurrent
                      ? 'border border-emerald-500/50 text-emerald-300'
                      : tier.popular
                      ? 'bg-emerald-500 hover:bg-emerald-400 text-zinc-950'
                      : tier.id === 'lifetime'
                      ? 'bg-amber-500 hover:bg-amber-400 text-zinc-950'
                      : 'border border-zinc-700 hover:border-zinc-500 text-zinc-100'
                  }`}
                >
                  {isCurrent ? t('landing.pricing.current') :
                    loadingTier === tier.id ? t('landing.pricing.redirecting') :
                    tier.id === 'free' ? t('landing.pricing.startFree') :
                    tier.id === 'lifetime' ? `${t('landing.pricing.buy')} ${tier.name}` :
                    `${t('landing.pricing.get')} ${tier.name}`}
                </button>
              </div>
            );
          })}
        </div>

        {/* Feature matrix */}
        <div className="mt-16 border border-zinc-800 bg-zinc-900/40 overflow-hidden">
          <div className="px-5 py-3 border-b border-zinc-800 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span className="font-mono text-xs uppercase tracking-widest text-zinc-400">{t('pricing.matrix.title')}</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800 text-start text-[11px] mono uppercase tracking-widest text-zinc-500">
                  <th className="p-3 text-start">{t('pricing.matrix.capability')}</th>
                  <th className="p-3 text-center">Free</th>
                  <th className="p-3 text-center">Pro</th>
                  <th className="p-3 text-center">Pro+</th>
                  <th className="p-3 text-center">Enterprise</th>
                  <th className="p-3 text-center">Lifetime</th>
                </tr>
              </thead>
              <tbody>
                {MATRIX_ROWS.map((row) => (
                  <tr key={row.key} className="border-b border-zinc-900 last:border-b-0">
                    <td className="p-3 text-zinc-200">{t(`pricing.matrix.rows.${row.key}`)}</td>
                    {row.values.map((cell, i) => (
                      <td key={i} className="p-3 text-center">
                        {cell === true ? (
                          <Check className="w-4 h-4 text-emerald-400 inline" />
                        ) : cell === false ? (
                          <X className="w-4 h-4 text-zinc-600 inline" />
                        ) : (
                          <span className="text-xs text-zinc-400 mono">{cell}</span>
                        )}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="mt-12 text-center">
          <Link
            to={user ? '/dashboard' : '/register'}
            data-testid="pricing-continue"
            className="inline-flex items-center gap-2 border border-zinc-700 hover:border-zinc-500 text-zinc-100 font-mono px-5 py-2.5"
          >
            {user ? t('nav.dashboard') : t('pricing.continue')} <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
      </section>
    </div>
  );
}
