import React from 'react';
import '@/App.css';
import '@/i18n';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AuthProvider } from '@/lib/auth';
import AppLayout from '@/components/AppLayout';
import Dashboard from '@/pages/Dashboard';
import NewScan from '@/pages/NewScan';
import BulkScan from '@/pages/BulkScan';
import ScanDetail from '@/pages/ScanDetail';
import AttackSurfaceGraph from '@/pages/AttackSurfaceGraph';
import History from '@/pages/History';
import Settings from '@/pages/Settings';
import Monitors from '@/pages/Monitors';
import Services from '@/pages/Services';
import Playbooks from '@/pages/Playbooks';
import Login from '@/pages/Login';
import Register from '@/pages/Register';
import VulnScanNew from '@/pages/VulnScanNew';
import PayloadPlayground from '@/pages/PayloadPlayground';
import VulnScanDetail from '@/pages/VulnScanDetail';
import VulnScanHistory from '@/pages/VulnScanHistory';
import Deploy from '@/pages/Deploy';
import Notifications from '@/pages/Notifications';
import CustomPayloads from '@/pages/CustomPayloads';
import Subdomains from '@/pages/Subdomains';
import NucleiTemplates from '@/pages/NucleiTemplates';
import Schedules from '@/pages/Schedules';
import CompareScans from '@/pages/CompareScans';
// v7.7.2 · Total Annihilation
import JWTCracker from '@/pages/JWTCracker';
import GraphQLScanner from '@/pages/GraphQLScanner';
import AutoPilot from '@/pages/AutoPilot';
import RaceCondition from '@/pages/RaceCondition';
import VulnMonitors from '@/pages/VulnMonitors';
// v7.8 · Weaponized Wave
import Weaponry from '@/pages/Weaponry';
import ThreatIntel from '@/pages/ThreatIntel';
// v7.9 · Commercial Wave
import Landing from '@/pages/Landing';
import Pricing from '@/pages/Pricing';
import Billing from '@/pages/Billing';
import Workspaces from '@/pages/Workspaces';
// v7.9.2 · Public API + SDK
import ApiKeys from '@/pages/ApiKeys';

function AppShell({ children }) {
  return <AppLayout>{children}</AppLayout>;
}

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          {/* Public marketing pages */}
          <Route path="/" element={<Landing />} />
          <Route path="/pricing" element={<Pricing />} />
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />

          {/* Authenticated app */}
          <Route path="/dashboard" element={<AppShell><Dashboard /></AppShell>} />
          <Route path="/scan/new" element={<AppShell><NewScan /></AppShell>} />
          <Route path="/vuln/playground" element={<AppShell><PayloadPlayground /></AppShell>} />
          <Route path="/scan/bulk" element={<AppShell><BulkScan /></AppShell>} />
          <Route path="/scan/:id" element={<AppShell><ScanDetail /></AppShell>} />
          <Route path="/scan/:id/graph" element={<AppShell><AttackSurfaceGraph /></AppShell>} />
          <Route path="/history" element={<AppShell><History /></AppShell>} />
          <Route path="/monitors" element={<AppShell><Monitors /></AppShell>} />
          <Route path="/playbooks" element={<AppShell><Playbooks /></AppShell>} />
          <Route path="/services" element={<AppShell><Services /></AppShell>} />
          <Route path="/settings" element={<AppShell><Settings /></AppShell>} />
          <Route path="/vuln/new" element={<AppShell><VulnScanNew /></AppShell>} />
          <Route path="/vuln/history" element={<AppShell><VulnScanHistory /></AppShell>} />
          <Route path="/vuln/scan/:id" element={<AppShell><VulnScanDetail /></AppShell>} />
          <Route path="/vuln/notifications" element={<AppShell><Notifications /></AppShell>} />
          <Route path="/vuln/payloads" element={<AppShell><CustomPayloads /></AppShell>} />
          <Route path="/vuln/subdomains" element={<AppShell><Subdomains /></AppShell>} />
          <Route path="/vuln/nuclei" element={<AppShell><NucleiTemplates /></AppShell>} />
          <Route path="/vuln/schedules" element={<AppShell><Schedules /></AppShell>} />
          <Route path="/vuln/compare" element={<AppShell><CompareScans /></AppShell>} />
          {/* v7.7.2 · Total Annihilation */}
          <Route path="/vuln/autopilot" element={<AppShell><AutoPilot /></AppShell>} />
          <Route path="/vuln/jwt" element={<AppShell><JWTCracker /></AppShell>} />
          <Route path="/vuln/graphql" element={<AppShell><GraphQLScanner /></AppShell>} />
          <Route path="/vuln/race" element={<AppShell><RaceCondition /></AppShell>} />
          <Route path="/vuln/monitors" element={<AppShell><VulnMonitors /></AppShell>} />
          {/* v7.8 · Weaponized Wave */}
          <Route path="/vuln/weaponry" element={<AppShell><Weaponry /></AppShell>} />
          <Route path="/vuln/threat-intel" element={<AppShell><ThreatIntel /></AppShell>} />
          {/* v7.9 · Commercial Wave */}
          <Route path="/billing" element={<AppShell><Billing /></AppShell>} />
          <Route path="/workspaces" element={<AppShell><Workspaces /></AppShell>} />
          <Route path="/keys" element={<AppShell><ApiKeys /></AppShell>} />
          <Route path="/deploy" element={<AppShell><Deploy /></AppShell>} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;
