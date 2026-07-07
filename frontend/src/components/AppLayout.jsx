import React, { useState, useEffect } from 'react';
import { NavLink, useLocation, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  LayoutDashboard, Radar, History, Radio, Settings as SettingsIcon,
  Boxes, BookOpen, Layers, Menu, X, LogOut, User, LogIn, UserPlus,
  Bomb, ShieldAlert, Download, Bell, Zap, Globe, Package, Clock, GitCompare,
  ChevronDown, ChevronRight, Bot, KeyRound, Waypoints, Swords, ScrollText,
  CreditCard, Users, Sparkles,
} from 'lucide-react';
import { NAV } from '@/constants/testIds';
import { useAuth } from '@/lib/auth';
import BackendHealthBanner from '@/components/BackendHealthBanner';
import LanguageSwitcher from '@/components/LanguageSwitcher';

// Sidebar groups — organised by workflow, not by legacy sub-project.
// Every item now has a `translationKey` so labels flip with the language.
const NAV_GROUPS = [
  {
    id: 'main',
    labelKey: 'sidebar.groups.main',
    accent: 'emerald',
    items: [
      { to: '/dashboard', key: 'dashboard', icon: LayoutDashboard, testid: NAV.dashboard, exact: true },
      { to: '/vuln/new',  key: 'newScan',   icon: Bomb, testid: 'nav-vuln-new' },
      { to: '/vuln/autopilot', key: 'autopilot', icon: Bot, testid: 'nav-autopilot' },
    ],
  },
  {
    id: 'scanner',
    labelKey: 'sidebar.groups.scanner',
    accent: 'red',
    items: [
      { to: '/vuln/history',   key: 'history',  icon: ShieldAlert, testid: 'nav-vuln-history' },
      { to: '/vuln/monitors',  key: 'monitors', icon: Radar, testid: 'nav-vuln-monitors' },
      { to: '/vuln/compare',   key: 'compare',  icon: GitCompare, testid: 'nav-compare' },
      { to: '/vuln/schedules', key: 'schedules', icon: Clock, testid: 'nav-schedules' },
    ],
  },
  {
    id: 'attacks',
    labelKey: 'sidebar.groups.attacks',
    accent: 'amber',
    items: [
      { to: '/vuln/weaponry', key: 'weaponry', icon: Swords, testid: 'nav-weaponry' },
      { to: '/vuln/jwt',      key: 'jwt',      icon: KeyRound, testid: 'nav-jwt' },
      { to: '/vuln/graphql',  key: 'graphql',  icon: Waypoints, testid: 'nav-graphql' },
      { to: '/vuln/race',     key: 'race',     icon: Radio, testid: 'nav-race' },
    ],
  },
  {
    id: 'intel',
    labelKey: 'sidebar.groups.intel',
    accent: 'sky',
    items: [
      { to: '/vuln/threat-intel', key: 'threatIntel', icon: ScrollText, testid: 'nav-intel' },
      { to: '/vuln/subdomains',   key: 'subdomains',  icon: Globe, testid: 'nav-subdomains' },
      { to: '/vuln/nuclei',       key: 'nuclei',      icon: Package, testid: 'nav-nuclei' },
      { to: '/vuln/payloads',     key: 'payloads',    icon: Zap, testid: 'nav-payloads' },
      { to: '/vuln/playground',   key: 'playground',  icon: Bomb, testid: 'nav-playground' },
      { to: '/vuln/notifications', key: 'notifications', icon: Bell, testid: 'nav-notifications' },
    ],
  },
  {
    id: 'recon',
    labelKey: 'sidebar.groups.recon',
    accent: 'emerald',
    items: [
      { to: '/scan/new',   key: 'takeover',           icon: Radar, testid: NAV.newScan },
      { to: '/scan/bulk',  key: 'bulk',               icon: Layers, testid: 'nav-bulk-scan' },
      { to: '/history',    key: 'takeoverHistory',    icon: History, testid: NAV.history },
      { to: '/monitors',   key: 'takeoverMonitors',   icon: Radio, testid: NAV.monitors },
      { to: '/playbooks',  key: 'playbooks',          icon: BookOpen, testid: 'nav-playbooks' },
      { to: '/services',   key: 'services',           icon: Boxes, testid: NAV.services },
    ],
  },
  {
    id: 'team',
    labelKey: 'sidebar.groups.team',
    accent: 'fuchsia',
    items: [
      { to: '/workspaces', key: 'workspaces', icon: Users, testid: 'nav-workspaces' },
      { to: '/keys',   key: 'apiKeys',    icon: KeyRound, testid: 'nav-api-keys' },
      { to: '/billing',    key: 'billing',    icon: CreditCard, testid: 'nav-billing' },
    ],
  },
  {
    id: 'system',
    labelKey: 'sidebar.groups.system',
    accent: 'zinc',
    items: [
      { to: '/deploy',   key: 'deploy',   icon: Download, testid: 'nav-deploy' },
      { to: '/settings', key: 'settings', icon: SettingsIcon, testid: NAV.settings },
    ],
  },
];

const ACCENT_TEXT = {
  red: 'text-red-500', emerald: 'text-emerald-500',
  amber: 'text-amber-500', zinc: 'text-zinc-500',
  sky: 'text-sky-400', fuchsia: 'text-fuchsia-400',
};

function persistCollapsed(state) {
  try { localStorage.setItem('cs.nav.collapsed', JSON.stringify(state)); }
  catch (e) { /* ignore quota / disabled storage */ }
}
function loadCollapsed() {
  try { return JSON.parse(localStorage.getItem('cs.nav.collapsed') || '{}'); } catch (e) { return {}; }
}

export default function AppLayout({ children }) {
  const { t, i18n } = useTranslation();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(loadCollapsed);
  const location = useLocation();
  const nav = useNavigate();
  const { user, logout } = useAuth();
  const isRtl = i18n.language === 'ar';

  useEffect(() => { setMobileOpen(false); }, [location.pathname]);

  const toggleGroup = (id) => {
    setCollapsed((prev) => {
      const next = { ...prev, [id]: !prev[id] };
      persistCollapsed(next);
      return next;
    });
  };

  const handleLogout = async () => {
    await logout();
    nav('/login');
  };

  return (
    <div className="min-h-screen flex bg-zinc-950" dir={isRtl ? 'rtl' : 'ltr'}>
      {/* Version banner */}
      <div className="fixed top-0 start-0 end-0 z-[60] bg-gradient-to-r from-emerald-500 via-emerald-400 to-emerald-500 text-zinc-950 text-center py-1 text-[10px] mono uppercase tracking-widest font-bold pointer-events-none">
        CYBERSCOPE · {t('brand.version')} · 54 attack modules · Deep crawler · AI Autopilot · Threat Intel
      </div>
      <BackendHealthBanner />

      {/* Mobile top bar */}
      <div className="lg:hidden fixed top-[22px] start-0 end-0 z-30 bg-zinc-950 border-b border-zinc-800 flex items-center justify-between p-3">
        <div className="flex items-center gap-2">
          <Radar className="w-5 h-5 text-emerald-500" strokeWidth={1.5} />
          <div className="font-display font-bold text-zinc-50 text-sm tracking-tight">
            CYBER<span className="text-emerald-500">.</span>SCOPE
          </div>
        </div>
        <div className="flex items-center gap-2">
          <LanguageSwitcher compact alignRight={!isRtl} />
          <button
            data-testid="mobile-menu-toggle"
            onClick={() => setMobileOpen(!mobileOpen)}
            className="p-2 text-zinc-400 hover:text-emerald-500"
          >
            {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
      </div>

      {mobileOpen && (
        <div
          onClick={() => setMobileOpen(false)}
          className="lg:hidden fixed inset-0 bg-black/60 z-40"
        />
      )}

      {/* Sidebar */}
      <aside
        className={`fixed z-50 h-screen w-64 border-e border-zinc-800 bg-zinc-950 flex flex-col transition-transform lg:translate-x-0 pt-[22px] ${
          mobileOpen
            ? 'translate-x-0'
            : (isRtl ? 'translate-x-full lg:translate-x-0' : '-translate-x-full lg:translate-x-0')
        } ${isRtl ? 'end-0' : 'start-0'}`}
      >
        <div className="p-4 border-b border-zinc-800 hidden lg:flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0">
            <Radar className="w-5 h-5 text-emerald-500 shrink-0" strokeWidth={1.5} />
            <div className="min-w-0">
              <div className="font-display font-bold text-zinc-50 text-sm tracking-tight">
                CYBER<span className="text-emerald-500">.</span>SCOPE
              </div>
              <div className="text-[10px] text-emerald-500 mono uppercase tracking-widest">
                {t('brand.version')}
              </div>
            </div>
          </div>
          <LanguageSwitcher compact alignRight={!isRtl} />
        </div>
        <div className="lg:hidden h-14"></div>

        <nav className="flex-1 p-2 space-y-3 overflow-y-auto">
          {NAV_GROUPS.map((group) => {
            const isCollapsed = !!collapsed[group.id];
            const accentClass = ACCENT_TEXT[group.accent] || 'text-zinc-500';
            return (
              <div key={group.id} className="space-y-0.5">
                {group.labelKey && (
                  <button
                    data-testid={`nav-group-${group.id}`}
                    onClick={() => toggleGroup(group.id)}
                    className="w-full flex items-center justify-between px-3 py-1.5 text-[10px] mono uppercase tracking-[0.15em] text-zinc-500 hover:text-zinc-300 transition-colors"
                  >
                    <span className={accentClass}>{t(group.labelKey)}</span>
                    {isCollapsed
                      ? (isRtl ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />)
                      : <ChevronDown className="w-3 h-3" />}
                  </button>
                )}
                {!isCollapsed && group.items.map(({ to, key, icon: Icon, testid, exact }) => (
                  <NavLink
                    key={to}
                    to={to}
                    end={exact}
                    data-testid={testid}
                    className={({ isActive }) =>
                      `flex items-center gap-3 px-3 py-2 text-sm transition-colors duration-150 ${
                        isActive
                          ? `bg-zinc-900 text-emerald-500 ${isRtl ? 'border-e-2' : 'border-s-2'} border-emerald-500`
                          : `text-zinc-400 hover:text-zinc-100 hover:bg-zinc-900/50 ${isRtl ? 'border-e-2' : 'border-s-2'} border-transparent`
                      }`
                    }
                  >
                    <Icon className="w-4 h-4" strokeWidth={1.5} />
                    <span className="tracking-tight">{t(`sidebar.items.${key}`)}</span>
                  </NavLink>
                ))}
              </div>
            );
          })}
        </nav>

        <div className="p-3 border-t border-zinc-800">
          {user && user.email ? (
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-xs text-zinc-300 mono">
                <User className="w-3 h-3 text-emerald-500" />
                <div className="truncate flex-1" data-testid="user-email">
                  {user.email}
                </div>
              </div>
              <div className="text-[9px] text-zinc-600 mono uppercase">
                Role: <span className={user.role === 'admin' ? 'text-red-400' : 'text-emerald-500'}>{user.role}</span>
              </div>
              <button
                data-testid="logout-btn"
                onClick={handleLogout}
                className="w-full flex items-center gap-2 px-2 py-1 border border-zinc-800 text-zinc-400 hover:text-red-400 hover:border-red-500/40 mono text-xs transition-colors"
              >
                <LogOut className="w-3 h-3" /> Logout
              </button>
            </div>
          ) : user === false ? (
            <div className="space-y-2">
              <div className="text-[10px] text-zinc-600 mono uppercase tracking-widest">
                Guest mode
              </div>
              <div className="flex gap-1">
                <NavLink to="/login" data-testid="link-login-sidebar"
                  className="flex-1 flex items-center gap-1 px-2 py-1 border border-emerald-500/40 text-emerald-500 hover:bg-emerald-500/10 mono text-xs justify-center">
                  <LogIn className="w-3 h-3" /> {t('nav.signin')}
                </NavLink>
                <NavLink to="/register" data-testid="link-register-sidebar"
                  className="flex-1 flex items-center gap-1 px-2 py-1 border border-zinc-800 text-zinc-400 hover:text-zinc-50 mono text-xs justify-center">
                  <UserPlus className="w-3 h-3" /> {t('nav.signup')}
                </NavLink>
              </div>
            </div>
          ) : (
            <div className="text-[10px] text-zinc-600 mono">Loading...</div>
          )}
          <div className="text-[9px] text-zinc-700 mono mt-3 pt-3 border-t border-zinc-800">
            Use with authorization only.
          </div>
        </div>
      </aside>

      <main className={`flex-1 ${isRtl ? 'lg:mr-64' : 'lg:ml-64'} p-4 lg:p-6 max-w-full overflow-x-hidden pt-[60px] lg:pt-10`}>
        {children}
      </main>
    </div>
  );
}
