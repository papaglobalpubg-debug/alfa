import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useAuth } from '@/lib/auth';
import api from '@/lib/api';
import LanguageSwitcher from '@/components/LanguageSwitcher';
import {
  Radar, Shield, Zap, Brain, Globe, Users,
  CheckCircle2, ArrowRight, Sparkles, Bug, KeyRound, Layers,
  Github, Rocket, Lock, Cpu, Terminal, Lock as LockIcon,
} from 'lucide-react';

const arsenal = [
  'HTTP Smuggling v2', 'Deep SSRF', 'JWT Cracker', 'GraphQL Scanner',
  'Race Condition x200', 'Cache Deception v2', 'Prototype Pollution v2', 'MFA Bypass',
  'WebSocket CSWSH', 'Nuclei Import', 'Bug-Bounty Report', 'Compliance Mapper',
];

const codeSample = `# Install (Enterprise / Lifetime tier unlocks download)
# Sign in, upgrade, then hit /api/downloads/cyberscope.tar.gz
docker-compose up -d

# Or use the CLI (local scan)
python cyberscope_cli.py scan example.com --deep --ai --autopilot`;

export default function Landing() {
  const { t, i18n } = useTranslation();
  const nav = useNavigate();
  const { user } = useAuth();
  const [tiers, setTiers] = useState([]);
  const [proof, setProof] = useState(null);
  const isRtl = i18n.language === 'ar';

  useEffect(() => {
    api.billingTiers()
      .then((r) => setTiers(r.data?.tiers || []))
      .catch(() => {});
    api.socialProof()
      .then((r) => setProof(r.data))
      .catch(() => {});
  }, []);

  const gotoApp = () => nav(user ? '/dashboard' : '/register');

  const features = [
    { icon: Bug,   accent: 'text-red-400 border-red-500/30',       key: 'killer' },
    { icon: Brain, accent: 'text-fuchsia-400 border-fuchsia-500/30', key: 'ai' },
    { icon: Radar, accent: 'text-emerald-400 border-emerald-500/30', key: 'crawler' },
    { icon: Globe, accent: 'text-sky-400 border-sky-500/30',       key: 'intel' },
    { icon: Users, accent: 'text-amber-400 border-amber-500/30',   key: 'team' },
    { icon: Zap,   accent: 'text-cyan-400 border-cyan-500/30',     key: 'continuous' },
  ];

  const stats = [
    { label: t('landing.stats.modules'), value: '54' },
    { label: t('landing.stats.payloads'), value: '219K+' },
    { label: t('landing.stats.cves'), value: t('landing.stats.cves').indexOf('daily') >= 0 ? 'daily' : 'live' },
    { label: t('landing.stats.aiModels'), value: 'Claude · GPT · Gemini' },
  ];

  return (
    <div data-testid="landing-page" className="min-h-screen bg-zinc-950 text-zinc-100" dir={isRtl ? 'rtl' : 'ltr'}>
      {/* Nav */}
      <header className="sticky top-0 z-40 backdrop-blur bg-zinc-950/80 border-b border-zinc-800">
        <div className="max-w-6xl mx-auto px-4 h-14 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2 font-display font-bold" data-testid="landing-logo">
            <Radar className="w-5 h-5 text-emerald-500" strokeWidth={1.5} />
            <span>CYBER<span className="text-emerald-500">.</span>SCOPE</span>
            <span className="text-[10px] mono text-zinc-500 ms-1">{t('brand.version')}</span>
          </Link>
          <nav className="flex items-center gap-3 md:gap-4 text-sm text-zinc-400">
            <a href="#features" className="hover:text-zinc-100 hidden sm:inline">{t('nav.features')}</a>
            <a href="#arsenal" className="hover:text-zinc-100 hidden sm:inline">{t('nav.arsenal')}</a>
            <Link to="/pricing" className="hover:text-zinc-100" data-testid="nav-pricing">{t('nav.pricing')}</Link>
            <a href="#deploy" className="hover:text-zinc-100 hidden md:inline">{t('nav.selfhost')}</a>
            <LanguageSwitcher />
            {user ? (
              <Link to="/dashboard" className="text-emerald-400 hover:text-emerald-300" data-testid="nav-dashboard">
                {t('nav.dashboard')} →
              </Link>
            ) : (
              <>
                <Link to="/login" className="text-zinc-300 hover:text-zinc-100" data-testid="nav-login">
                  {t('nav.signin')}
                </Link>
                <Link
                  to="/register"
                  className="bg-emerald-500 text-zinc-950 px-3 py-1.5 font-mono text-xs font-semibold hover:bg-emerald-400"
                  data-testid="nav-cta-register"
                >
                  {t('nav.startFree')} →
                </Link>
              </>
            )}
          </nav>
        </div>
      </header>

      {/* Social-proof banner — hidden when no signups yet */}
      {proof && (proof.paying_customers + proof.new_last_7d + proof.total_scans) > 0 && (
        <div
          data-testid="social-proof-banner"
          className="bg-emerald-500/10 border-b border-emerald-500/20 text-emerald-300 text-xs mono py-1.5 px-4"
        >
          <div className="max-w-6xl mx-auto flex flex-wrap items-center justify-center gap-x-4 gap-y-1">
            <span className="inline-flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              {proof.paying_customers > 0 && (
                <span data-testid="proof-paying"><b>{proof.paying_customers}</b> paying customers</span>
              )}
            </span>
            {proof.new_last_7d > 0 && (
              <span data-testid="proof-new-week">🔥 <b>{proof.new_last_7d}</b> new analysts joined this week</span>
            )}
            {proof.total_scans > 0 && (
              <span data-testid="proof-scans"><b>{proof.total_scans.toLocaleString()}</b> scans completed</span>
            )}
          </div>
        </div>
      )}

      {/* Hero */}
      <section className="relative overflow-hidden border-b border-zinc-900">
        <div className="absolute inset-0 pointer-events-none">
          <div className="absolute top-0 start-1/4 w-96 h-96 bg-emerald-500/10 blur-3xl rounded-full" />
          <div className="absolute bottom-0 end-1/4 w-96 h-96 bg-red-500/10 blur-3xl rounded-full" />
        </div>
        <div className="relative max-w-6xl mx-auto px-4 pt-20 pb-24">
          <div className="grid md:grid-cols-2 gap-12 items-center">
            <div className="animate-fade-in-up">
              <div className="inline-flex items-center gap-2 text-[10px] mono uppercase tracking-widest text-emerald-400 border border-emerald-500/40 bg-emerald-500/10 px-2 py-1 mb-6">
                <Sparkles className="w-3 h-3" /> {t('landing.badge')}
              </div>
              <h1 className="text-4xl sm:text-5xl lg:text-6xl font-display font-bold leading-tight">
                {t('landing.heroLine1')} <br />
                {t('landing.heroLine2')} <br />
                {t('landing.heroLine3')} <span className="text-emerald-400">{t('landing.heroAccent')}</span>
              </h1>
              <p className="mt-6 text-zinc-400 text-base max-w-lg">{t('landing.heroBody')}</p>
              <div className="mt-8 flex flex-wrap items-center gap-3">
                <button
                  onClick={gotoApp}
                  data-testid="hero-cta-primary"
                  className="group bg-emerald-500 hover:bg-emerald-400 text-zinc-950 font-mono font-semibold px-5 py-3 flex items-center gap-2 transition-colors"
                >
                  {user ? t('landing.ctaOpenDashboard') : t('landing.ctaScan')}
                  <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                </button>
                <Link
                  to="/pricing"
                  data-testid="hero-cta-pricing"
                  className="border border-zinc-700 hover:border-zinc-500 text-zinc-100 font-mono px-5 py-3 flex items-center gap-2"
                >
                  {t('landing.ctaPricing')}
                </Link>
              </div>
              <div className="mt-8 grid grid-cols-2 gap-4 max-w-md">
                {stats.map((s) => (
                  <div key={s.label} className="border-s-2 border-emerald-500/40 ps-3">
                    <div className="text-2xl font-bold text-zinc-50">{s.value}</div>
                    <div className="text-[11px] mono uppercase tracking-wider text-zinc-500">{s.label}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Terminal card */}
            <div className="relative" dir="ltr">
              <div className="absolute -inset-1 bg-gradient-to-br from-emerald-500/20 via-transparent to-red-500/20 blur-xl" />
              <div className="relative bg-zinc-900 border border-zinc-800 shadow-2xl">
                <div className="flex items-center gap-1.5 px-4 h-8 border-b border-zinc-800 bg-zinc-950">
                  <span className="w-2.5 h-2.5 rounded-full bg-red-500/70" />
                  <span className="w-2.5 h-2.5 rounded-full bg-amber-500/70" />
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/70" />
                  <span className="ms-3 text-[11px] mono text-zinc-500">cyberscope@ops:~$</span>
                </div>
                <pre className="p-5 text-[13px] leading-6 mono text-zinc-300 whitespace-pre overflow-x-auto">
{codeSample}
                </pre>
                <div className="px-5 pb-5 -mt-1 text-[11px] mono text-emerald-400 flex items-center gap-1">
                  <span className="w-2 h-2 bg-emerald-400 animate-pulse" /> scanning… 12 findings · 3 critical
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features */}
      <section id="features" className="max-w-6xl mx-auto px-4 py-20">
        <div className="mb-12">
          <div className="text-[10px] mono uppercase tracking-widest text-zinc-500 mb-2">// {t('landing.features.kicker')}</div>
          <h2 className="text-3xl font-display font-bold">{t('landing.features.title')}</h2>
        </div>
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
          {features.map((f) => (
            <div key={f.key} className={`bg-zinc-900/70 border ${f.accent} p-5 hover:bg-zinc-900 transition-colors`}>
              <f.icon className={`w-6 h-6 mb-3 ${f.accent.split(' ')[0]}`} strokeWidth={1.5} />
              <div className="font-display font-semibold text-lg mb-1">{t(`landing.features.${f.key}.title`)}</div>
              <p className="text-sm text-zinc-400 leading-6">{t(`landing.features.${f.key}.body`)}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Arsenal grid */}
      <section id="arsenal" className="border-y border-zinc-900 bg-zinc-950">
        <div className="max-w-6xl mx-auto px-4 py-20">
          <div className="flex items-end justify-between mb-8 flex-wrap gap-4">
            <div>
              <div className="text-[10px] mono uppercase tracking-widest text-red-400 mb-2">// {t('landing.arsenal.kicker')}</div>
              <h2 className="text-3xl font-display font-bold">{t('landing.arsenal.title')}</h2>
            </div>
            <Link
              to={user ? '/vuln/weaponry' : '/register'}
              className="text-sm mono text-emerald-400 hover:text-emerald-300 flex items-center gap-1"
              data-testid="arsenal-cta"
            >
              {t('landing.arsenal.cta')} <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
            {arsenal.map((m, i) => (
              <div
                key={m}
                className="border border-zinc-800 hover:border-red-500/40 bg-zinc-900/50 hover:bg-red-950/20 px-3 py-3 text-sm flex items-center gap-2 transition-colors"
              >
                <span className="text-[10px] mono text-zinc-600">{String(i + 1).padStart(2, '0')}</span>
                <Bug className="w-3.5 h-3.5 text-red-400/70" />
                <span className="text-zinc-200">{m}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Pricing teaser */}
      <section className="max-w-6xl mx-auto px-4 py-20">
        <div className="mb-10">
          <div className="text-[10px] mono uppercase tracking-widest text-zinc-500 mb-2">// {t('landing.pricing.kicker')}</div>
          <h2 className="text-3xl font-display font-bold">{t('landing.pricing.title')}</h2>
        </div>
        <div className="grid md:grid-cols-2 lg:grid-cols-5 gap-3">
          {tiers.map((tier) => (
            <div
              key={tier.id}
              data-testid={`landing-tier-${tier.id}`}
              className={`relative bg-zinc-900/70 border p-5 flex flex-col ${
                tier.popular ? 'border-emerald-500 shadow-[0_0_40px_-15px_rgba(16,185,129,0.5)]' : 'border-zinc-800'
              }`}
            >
              {tier.popular && (
                <div className="absolute -top-3 start-4 text-[9px] mono uppercase tracking-widest bg-emerald-500 text-zinc-950 px-2 py-0.5">
                  {t('landing.pricing.mostPopular')}
                </div>
              )}
              <div className="text-[10px] mono uppercase tracking-widest text-zinc-500 mb-1">{tier.id}</div>
              <div className="font-display font-bold text-lg">{tier.name}</div>
              <div className="mt-3">
                <span className="text-3xl font-bold">${(tier.price_cents / 100).toFixed(0)}</span>
                {tier.interval && <span className="text-zinc-500 text-sm"> {t('landing.pricing.perMonth')}</span>}
                {!tier.interval && tier.price_cents > 0 && <span className="text-zinc-500 text-sm"> {t('landing.pricing.oneTime')}</span>}
              </div>
              <p className="text-xs text-zinc-400 mt-2 min-h-[36px]">{tier.blurb}</p>
              <ul className="mt-4 space-y-1.5 flex-1">
                {(tier.features || []).slice(0, 3).map((f) => (
                  <li key={f} className="flex items-start gap-1.5 text-[11px] text-zinc-300 leading-4">
                    <CheckCircle2 className="w-3 h-3 text-emerald-400 mt-0.5 shrink-0" />
                    <span>{f}</span>
                  </li>
                ))}
              </ul>
              <Link
                to="/pricing"
                className={`mt-4 text-center py-2 font-mono text-xs font-semibold ${
                  tier.popular
                    ? 'bg-emerald-500 hover:bg-emerald-400 text-zinc-950'
                    : 'border border-zinc-700 hover:border-zinc-500 text-zinc-100'
                }`}
              >
                {tier.id === 'free' ? t('landing.pricing.startFree') : `${t('landing.pricing.get')} ${tier.name}`}
              </Link>
            </div>
          ))}
        </div>
      </section>

      {/* Deploy — locked behind Enterprise/Lifetime */}
      <section id="deploy" className="border-t border-zinc-900 bg-zinc-950">
        <div className="max-w-6xl mx-auto px-4 py-20 grid md:grid-cols-2 gap-10 items-center">
          <div>
            <div className="text-[10px] mono uppercase tracking-widest text-zinc-500 mb-2">// {t('landing.deploy.kicker')}</div>
            <h2 className="text-3xl font-display font-bold">{t('landing.deploy.title')}</h2>
            <p className="mt-4 text-zinc-400 text-sm max-w-lg">{t('landing.deploy.body')}</p>
            <div className="mt-6 flex flex-wrap gap-3">
              <Link
                to="/pricing"
                data-testid="deploy-cta-download"
                className="border border-amber-500/50 hover:bg-amber-500 hover:text-zinc-950 text-amber-300 font-mono px-4 py-2.5 flex items-center gap-2 transition-colors"
              >
                <LockIcon className="w-4 h-4" /> {t('landing.deploy.downloadLocked')}
              </Link>
              <a
                href="https://github.com"
                className="border border-zinc-700 hover:border-zinc-500 text-zinc-100 font-mono px-4 py-2.5 flex items-center gap-2"
              >
                <Github className="w-4 h-4" /> {t('landing.deploy.github')}
              </a>
            </div>
            <div className="mt-6 grid grid-cols-3 gap-3 text-xs">
              <div className="flex items-center gap-1.5 text-zinc-400"><Cpu className="w-3.5 h-3.5" /> Docker-first</div>
              <div className="flex items-center gap-1.5 text-zinc-400"><Lock className="w-3.5 h-3.5" /> SSRF-guarded</div>
              <div className="flex items-center gap-1.5 text-zinc-400"><Layers className="w-3.5 h-3.5" /> Non-root</div>
            </div>
          </div>

          <div className="bg-zinc-900 border border-zinc-800" dir="ltr">
            <div className="flex items-center gap-1.5 px-4 h-8 border-b border-zinc-800">
              <Terminal className="w-3.5 h-3.5 text-emerald-500" />
              <span className="text-[11px] mono text-zinc-400">docker-compose.yml</span>
            </div>
            <pre className="p-5 text-[12px] leading-6 mono text-zinc-300 whitespace-pre overflow-x-auto">
{`services:
  backend:
    image: cyberscope/backend:7.9
    environment:
      - MONGO_URL=mongodb://mongo:27017
      - JWT_SECRET=$\{JWT_SECRET}
    ports: ["8001:8001"]
  frontend:
    image: cyberscope/frontend:7.9
    ports: ["3000:3000"]
  mongo:
    image: mongo:7
    volumes: [ "./data:/data/db" ]`}
            </pre>
          </div>
        </div>
      </section>

      {/* Final CTA */}
      <section className="max-w-4xl mx-auto px-4 py-20 text-center">
        <div className="text-[10px] mono uppercase tracking-widest text-emerald-400 mb-3">// {t('landing.final.kicker')}</div>
        <h2 className="text-3xl md:text-4xl font-display font-bold">{t('landing.final.title')}</h2>
        <p className="mt-4 text-zinc-400 text-sm max-w-xl mx-auto">{t('landing.final.body')}</p>
        <button
          onClick={gotoApp}
          data-testid="final-cta"
          className="mt-8 bg-emerald-500 hover:bg-emerald-400 text-zinc-950 font-mono font-semibold px-6 py-3 inline-flex items-center gap-2"
        >
          {user ? t('landing.ctaOpenDashboard') : t('landing.final.cta')} <ArrowRight className="w-4 h-4" />
        </button>
      </section>

      <footer className="border-t border-zinc-900">
        <div className="max-w-6xl mx-auto px-4 py-8 flex flex-wrap items-center justify-between gap-4 text-xs text-zinc-500 mono">
          <div className="flex items-center gap-2">
            <Shield className="w-3.5 h-3.5" />
            © 2026 CyberScope · {t('brand.tagline')}
          </div>
          <div className="flex items-center gap-4">
            <a href="#" className="hover:text-zinc-300">{t('landing.footer.terms')}</a>
            <a href="#" className="hover:text-zinc-300">{t('landing.footer.privacy')}</a>
            <Link to="/pricing" className="hover:text-zinc-300">{t('nav.pricing')}</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
