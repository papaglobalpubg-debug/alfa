import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Bomb, Zap, Target, Layers, Settings2, ChevronDown } from 'lucide-react';
import api from '@/lib/api';

const ALL_MODULES = [
  { key: 'fingerprint', label: 'Fingerprint (Tech/WAF)', default: true },
  { key: 'recon', label: 'Recon (Wayback/OTX/JS mining)', default: true },
  { key: 'crawler', label: 'Deep Crawler (BFS + sitemap + robots)', default: true },
  { key: 'xss', label: 'XSS (Reflected/Stored)', default: true },
  { key: 'sqli', label: 'SQL Injection', default: true },
  { key: 'nosqli', label: 'NoSQL Injection', default: true },
  { key: 'cmd', label: 'Command Injection', default: true },
  { key: 'ssti', label: 'Server-Side Template Injection', default: true },
  { key: 'lfi', label: 'LFI / Path Traversal', default: true },
  { key: 'xxe', label: 'XML External Entity', default: true },
  { key: 'ssrf', label: 'Server-Side Request Forgery', default: true },
  { key: 'open_redirect', label: 'Open Redirect', default: true },
  { key: 'cors', label: 'CORS Misconfiguration', default: true },
  { key: 'crlf', label: 'CRLF Injection', default: true },
  { key: 'host_header', label: 'Host Header Injection', default: true },
  { key: 'web_cache_deception', label: 'Web Cache Deception', default: true },
  { key: 'client_proto', label: 'Client-side Prototype Pollution', default: true },
  { key: 'csp', label: 'CSP Audit', default: true },
  { key: 'directory_listing', label: 'Directory Listing', default: true },
  { key: 'http_methods', label: 'Dangerous HTTP Methods (PUT/TRACE)', default: true },
  { key: 'sri', label: 'Subresource Integrity Audit', default: true },
  { key: 'smuggling', label: 'HTTP Request Smuggling', default: false },
  { key: 'cache_poisoning', label: 'Cache Poisoning', default: true },
  { key: 'prototype_pollution', label: 'Prototype Pollution (Server)', default: true },
  { key: 'graphql', label: 'GraphQL Attacks', default: true },
  { key: 'deserialization', label: 'Deserialization', default: true },
  { key: 'cloud_buckets', label: 'Cloud Buckets (S3/GCS/Azure)', default: true },
  { key: 'infra_apis', label: 'K8s / Docker / etcd / Consul', default: true },
  { key: 'cve_templates', label: 'CVE Templates (nuclei-lite)', default: true },
  { key: 'secrets', label: 'Secrets Discovery', default: true },
  { key: 'port_scan', label: 'Port Scanner (deep only)', default: false },
  // v7.5 — Batch 3 modules (API/Auth/Mobile/Web3)
  { key: 'api_security', label: 'API Security (REST + GraphQL hardening)', default: true },
  { key: 'oauth_saml', label: 'OAuth2 / OIDC / SAML Attacks', default: true },
  { key: 'mobile_backend', label: 'Mobile Backend (Firebase / API keys / APK)', default: true },
  { key: 'web3', label: 'Web3 / Smart Contract (dApp frontend leaks)', default: true },
];

export default function VulnScanNew() {
  const nav = useNavigate();
  const [info, setInfo] = useState(null);
  const [target, setTarget] = useState('');
  const [depth, setDepth] = useState('medium');
  const [concurrency, setConcurrency] = useState(30);
  const [timeout, setTimeoutSec] = useState(12);
  const [oobHost, setOobHost] = useState('');
  const [jwtToken, setJwtToken] = useState('');
  const [customParams, setCustomParams] = useState('');
  const [modules, setModules] = useState(new Set(ALL_MODULES.filter(m => m.default).map(m => m.key)));
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    api.vulnInfo().then(r => setInfo(r.data)).catch(() => {});
  }, []);

  const toggleModule = (k) => {
    const next = new Set(modules);
    if (next.has(k)) next.delete(k); else next.add(k);
    setModules(next);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    if (!target.trim()) { setError('Please enter a target URL or domain'); return; }
    setSubmitting(true);
    try {
      const payload = {
        target: target.trim(),
        depth, concurrency: Number(concurrency), timeout: Number(timeout),
        modules: Array.from(modules),
        oob_host: oobHost.trim() || null,
        jwt_token: jwtToken.trim() || null,
        custom_params: customParams.split(',').map(p => p.trim()).filter(Boolean),
      };
      const r = await api.createVulnScan(payload);
      nav(`/vuln/scan/${r.data.scan_id}`);
    } catch (err) {
      setError(err?.response?.data?.detail || err.message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="max-w-5xl">
      <div className="mb-6 flex items-center gap-3">
        <Bomb className="w-6 h-6 text-red-500" />
        <div>
          <h1 className="text-2xl font-bold text-zinc-50 tracking-tight">CyberScope Vulnerability Scan</h1>
          <p className="text-xs mono text-zinc-500 mt-1">
            v{info?.version || '7.7.1'} — {(info?.payload_counts?.GRAND_TOTAL || info?.payload_counts?.TOTAL || 995).toLocaleString()} payloads · {info?.modules?.length || 38} modules · AI Destroyer + 100% Verifier
          </p>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6" data-testid="vuln-scan-form">
        {/* Target */}
        <div className="border border-zinc-800 bg-zinc-950 p-5">
          <label className="text-xs mono uppercase tracking-widest text-emerald-500 flex items-center gap-2 mb-3">
            <Target className="w-3 h-3" /> Target
          </label>
          <input
            data-testid="vuln-target-input"
            type="text" value={target} onChange={(e) => setTarget(e.target.value)}
            placeholder="https://example.com or example.com"
            className="w-full bg-zinc-900 border border-zinc-800 text-zinc-50 mono p-3 focus:border-emerald-500 focus:outline-none"
          />
          <div className="text-[10px] mono text-zinc-600 mt-2">
            Enter a URL you are authorized to test. All payloads are sent from this scanner.
          </div>
        </div>

        {/* Depth */}
        <div className="border border-zinc-800 bg-zinc-950 p-5">
          <label className="text-xs mono uppercase tracking-widest text-emerald-500 flex items-center gap-2 mb-3">
            <Zap className="w-3 h-3" /> Scan Depth
          </label>
          <div className="grid grid-cols-3 gap-2">
            {['shallow', 'medium', 'deep'].map((d) => (
              <button
                type="button"
                key={d}
                onClick={() => setDepth(d)}
                data-testid={`depth-${d}-btn`}
                className={`p-3 border transition-colors mono text-xs uppercase tracking-widest ${
                  depth === d
                    ? 'border-emerald-500 bg-emerald-500/10 text-emerald-500'
                    : 'border-zinc-800 text-zinc-500 hover:border-zinc-700 hover:text-zinc-300'
                }`}
              >
                {d}
              </button>
            ))}
          </div>
          <div className="mt-2 text-[10px] mono text-zinc-600">
            {depth === 'shallow' && 'Fast: fingerprint + core injection tests only'}
            {depth === 'medium' && 'Balanced: fingerprint + recon + all vuln modules'}
            {depth === 'deep' && 'Maximum: adds smuggling, port scanning, and CommonCrawl'}
          </div>
        </div>

        {/* Modules */}
        <div className="border border-zinc-800 bg-zinc-950 p-5">
          <label className="text-xs mono uppercase tracking-widest text-emerald-500 flex items-center gap-2 mb-3">
            <Layers className="w-3 h-3" /> Modules ({modules.size} enabled)
          </label>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-96 overflow-y-auto">
            {ALL_MODULES.map((m) => (
              <label key={m.key}
                className="flex items-center gap-2 p-2 border border-zinc-900 hover:border-zinc-800 cursor-pointer">
                <input
                  type="checkbox"
                  data-testid={`module-${m.key}-cb`}
                  checked={modules.has(m.key)}
                  onChange={() => toggleModule(m.key)}
                  className="accent-emerald-500"
                />
                <span className="text-xs mono text-zinc-300">{m.label}</span>
              </label>
            ))}
          </div>
        </div>

        {/* Advanced */}
        <div className="border border-zinc-800 bg-zinc-950">
          <button type="button" onClick={() => setShowAdvanced(!showAdvanced)}
            className="w-full p-4 flex items-center justify-between text-left">
            <span className="text-xs mono uppercase tracking-widest text-emerald-500 flex items-center gap-2">
              <Settings2 className="w-3 h-3" /> Advanced Options
            </span>
            <ChevronDown className={`w-4 h-4 text-zinc-500 transition-transform ${showAdvanced ? 'rotate-180' : ''}`} />
          </button>
          {showAdvanced && (
            <div className="p-5 pt-0 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-[10px] mono text-zinc-500 block mb-1">Concurrency (10-100)</label>
                  <input type="number" min="1" max="200" value={concurrency}
                    onChange={(e) => setConcurrency(e.target.value)}
                    className="w-full bg-zinc-900 border border-zinc-800 text-zinc-50 mono p-2 text-xs"/>
                </div>
                <div>
                  <label className="text-[10px] mono text-zinc-500 block mb-1">Request Timeout (sec)</label>
                  <input type="number" min="1" max="60" value={timeout}
                    onChange={(e) => setTimeoutSec(e.target.value)}
                    className="w-full bg-zinc-900 border border-zinc-800 text-zinc-50 mono p-2 text-xs"/>
                </div>
              </div>
              <div>
                <label className="text-[10px] mono text-zinc-500 block mb-1">
                  OOB Host (Interactsh domain — for blind vulns) [optional]
                </label>
                <input type="text" value={oobHost} onChange={(e) => setOobHost(e.target.value)}
                  placeholder="xxxx.oast.pro"
                  className="w-full bg-zinc-900 border border-zinc-800 text-zinc-50 mono p-2 text-xs"/>
              </div>
              <div>
                <label className="text-[10px] mono text-zinc-500 block mb-1">
                  JWT Token to test (optional)
                </label>
                <input type="text" value={jwtToken} onChange={(e) => setJwtToken(e.target.value)}
                  placeholder="eyJhbGc..."
                  className="w-full bg-zinc-900 border border-zinc-800 text-zinc-50 mono p-2 text-xs"/>
              </div>
              <div>
                <label className="text-[10px] mono text-zinc-500 block mb-1">
                  Custom Parameters (comma-separated) [optional]
                </label>
                <input type="text" value={customParams} onChange={(e) => setCustomParams(e.target.value)}
                  placeholder="q,search,id,user_id"
                  className="w-full bg-zinc-900 border border-zinc-800 text-zinc-50 mono p-2 text-xs"/>
              </div>
            </div>
          )}
        </div>

        {error && (
          <div className="border border-red-500/40 bg-red-500/5 p-3 text-xs mono text-red-400">
            {error}
          </div>
        )}

        <button
          type="submit"
          data-testid="submit-vuln-scan"
          disabled={submitting}
          className="w-full p-4 bg-red-500 hover:bg-red-600 disabled:bg-zinc-800 disabled:text-zinc-600 text-white font-bold mono uppercase tracking-widest transition-colors flex items-center justify-center gap-2"
        >
          <Bomb className="w-4 h-4" />
          {submitting ? 'Launching...' : 'Launch Attack'}
        </button>
      </form>
    </div>
  );
}
