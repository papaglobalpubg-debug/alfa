import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import api from '@/lib/api';
import HelpTip from '@/components/HelpTip';
import { CreditCard, Sparkles, CheckCircle2, ExternalLink, XCircle, Download, Lock } from 'lucide-react';

const TIER_ACCENT = {
  free: 'text-zinc-400 border-zinc-700',
  pro: 'text-emerald-400 border-emerald-500/40',
  pro_plus: 'text-cyan-400 border-cyan-500/40',
  enterprise: 'text-sky-400 border-sky-500/40',
  lifetime: 'text-amber-400 border-amber-500/40',
};

export default function Billing() {
  const { t } = useTranslation();
  const [status, setStatus] = useState(null);
  const [tiers, setTiers] = useState([]);
  const [downloadAllowed, setDownloadAllowed] = useState({ allowed: false });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [params] = useSearchParams();
  const success = params.get('success') === '1';
  const successTier = params.get('tier');

  const refresh = () => {
    api.billingStatus().then((r) => setStatus(r.data)).catch(() => {});
    api.request('/billing/download-allowed').then((r) => setDownloadAllowed(r.data)).catch(() => {});
  };
  useEffect(() => {
    refresh();
    api.billingTiers().then((r) => setTiers(r.data?.tiers || [])).catch(() => {});
  }, []);

  const openPortal = async () => {
    setBusy(true); setError('');
    try {
      const { data } = await api.billingPortal();
      if (data?.url) window.location.href = data.url;
    } catch (e) {
      setError(e.response?.data?.detail || 'Failed to open portal');
    } finally { setBusy(false); }
  };

  const downgrade = async () => {
    if (!window.confirm('Cancel at the end of current period?')) return;
    setBusy(true); setError('');
    try {
      await api.billingDowngrade();
      refresh();
    } catch (e) {
      setError(e.response?.data?.detail || 'Failed to cancel');
    } finally { setBusy(false); }
  };

  const downloadTarball = () => {
    const url = `${process.env.REACT_APP_BACKEND_URL}/api/downloads/cyberscope.tar.gz`;
    window.location.href = url;
  };

  const tier = status?.tier || 'free';
  const tierMeta = tiers.find((tt) => tt.id === tier);
  const accent = TIER_ACCENT[tier] || TIER_ACCENT.free;

  return (
    <div data-testid="billing-page" className="max-w-4xl mx-auto space-y-6 animate-fade-in-up">
      <header className={`border ${accent} bg-zinc-900/40 p-6`}>
        <div className="flex items-center gap-2 mb-2">
          <CreditCard className="w-5 h-5" />
          <span className="text-[10px] mono uppercase tracking-widest border border-current bg-current/10 px-2 py-0.5">
            {t('sidebar.items.billing')} · v7.9
          </span>
          <HelpTip
            title={t('help.billing.title')}
            body={t('help.billing.body')}
            testId="billing-help"
          />
        </div>
        <h1 className="text-2xl md:text-3xl font-display font-bold text-zinc-50">{t('billing.title')}</h1>
        <p className="text-zinc-400 text-sm mt-2">{t('billing.subtitle')}</p>
      </header>

      {success && (
        <div className="border border-emerald-500/40 bg-emerald-500/10 text-emerald-300 px-4 py-3 flex items-center gap-2 text-sm">
          <CheckCircle2 className="w-4 h-4" />
          {t('billing.paymentSuccess')} <b className="mono">{successTier}</b>. {t('billing.enjoy')}
        </div>
      )}
      {error && (
        <div className="border border-red-500/40 bg-red-500/10 text-red-300 px-4 py-3 flex items-center gap-2 text-sm" data-testid="billing-error">
          <XCircle className="w-4 h-4" /> {error}
        </div>
      )}

      <div className="grid md:grid-cols-3 gap-4">
        <div className="md:col-span-2 border border-zinc-800 bg-zinc-900/40 p-5">
          <div className="text-[10px] mono uppercase tracking-widest text-zinc-500 mb-1">{t('billing.currentTier')}</div>
          <div className={`text-2xl font-display font-bold ${accent.split(' ')[0]}`}>
            {tierMeta?.name || tier}
          </div>
          <div className="text-xs text-zinc-400 mt-1">{tierMeta?.blurb}</div>

          {tierMeta && (
            <div className="grid grid-cols-2 gap-2 mt-4">
              <div className="border border-zinc-800 bg-zinc-950/50 p-3">
                <div className="text-[10px] mono uppercase tracking-wider text-zinc-500">{t('billing.scansPerMonth')}</div>
                <div className="text-lg text-zinc-100">{tierMeta.quota_scans_per_month.toLocaleString()}</div>
              </div>
              <div className="border border-zinc-800 bg-zinc-950/50 p-3">
                <div className="text-[10px] mono uppercase tracking-wider text-zinc-500">{t('billing.targetQuota')}</div>
                <div className="text-lg text-zinc-100">{tierMeta.quota_targets}</div>
              </div>
            </div>
          )}

          <div className="mt-4 flex flex-wrap gap-2">
            <a
              href="/pricing"
              data-testid="billing-change-plan"
              className="border border-zinc-700 hover:border-zinc-500 px-3 py-1.5 text-xs mono flex items-center gap-1"
            >
              <Sparkles className="w-3.5 h-3.5" /> {t('billing.changePlan')}
            </a>
            {status?.stripe_customer_id && (
              <button
                disabled={busy}
                onClick={openPortal}
                data-testid="billing-open-portal"
                className="border border-emerald-500/50 hover:bg-emerald-500 hover:text-zinc-950 text-emerald-300 px-3 py-1.5 text-xs mono flex items-center gap-1 transition-colors disabled:opacity-60"
              >
                <ExternalLink className="w-3.5 h-3.5" /> {t('billing.managePortal')}
              </button>
            )}
            {status?.stripe_status === 'active' && !status?.cancel_at_period_end && tier !== 'lifetime' && (
              <button
                disabled={busy}
                onClick={downgrade}
                data-testid="billing-cancel"
                className="border border-red-500/40 hover:bg-red-500/20 text-red-300 px-3 py-1.5 text-xs mono flex items-center gap-1 disabled:opacity-60"
              >
                <XCircle className="w-3.5 h-3.5" /> {t('billing.cancelAtPeriodEnd')}
              </button>
            )}
            {downloadAllowed.allowed ? (
              <button
                onClick={downloadTarball}
                data-testid="billing-download"
                className="border border-amber-500/50 hover:bg-amber-500 hover:text-zinc-950 text-amber-300 px-3 py-1.5 text-xs mono flex items-center gap-1"
              >
                <Download className="w-3.5 h-3.5" /> {t('landing.deploy.download')}
              </button>
            ) : (
              <span className="border border-zinc-800 text-zinc-500 px-3 py-1.5 text-xs mono flex items-center gap-1" data-testid="billing-download-locked">
                <Lock className="w-3.5 h-3.5" /> {t('landing.deploy.downloadLocked')}
              </span>
            )}
          </div>
        </div>

        <div className="border border-zinc-800 bg-zinc-900/40 p-5 space-y-2">
          <div className="text-[10px] mono uppercase tracking-widest text-zinc-500">{t('billing.status')}</div>
          <Row k={t('billing.stripeStatus')} v={status?.stripe_status || '—'} />
          <Row k={t('billing.customerId')} v={status?.stripe_customer_id ? `${status.stripe_customer_id.slice(0, 10)}…` : '—'} />
          <Row k={t('billing.cancelsAtPeriodEnd')} v={status?.cancel_at_period_end ? 'Yes' : 'No'} />
          <Row k={t('billing.currentPeriodEnds')} v={
            status?.current_period_end
              ? new Date(status.current_period_end * 1000).toLocaleDateString()
              : '—'
          } />
        </div>
      </div>
    </div>
  );
}

function Row({ k, v }) {
  return (
    <div className="flex items-center justify-between text-xs">
      <span className="text-zinc-500 mono">{k}</span>
      <span className="text-zinc-200 mono">{v}</span>
    </div>
  );
}
