import axios from 'axios';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
export const API = `${BACKEND_URL}/api`;

const client = axios.create({ baseURL: API, timeout: 60000, withCredentials: true });

export const api = {
  root: () => client.get('/'),
  stats: () => client.get('/stats'),
  services: () => client.get('/services'),
  sources: () => client.get('/sources'),
  // Auth
  authMe: () => client.get('/auth/me'),
  authLogin: (email, password) => client.post('/auth/login', { email, password }),
  authRegister: (payload) => client.post('/auth/register', payload),
  authLogout: () => client.post('/auth/logout'),
  // Scans
  listScans: (params) => client.get('/scans', { params }),
  createScan: (payload) => client.post('/scans', payload),
  getScan: (id) => client.get(`/scans/${id}`),
  deleteScan: (id) => client.delete(`/scans/${id}`),
  cancelScan: (id) => client.post(`/scans/${id}/cancel`),
  createBulkScan: (payload) => client.post('/scans/bulk', payload),
  getScanResults: (id, params) => client.get(`/scans/${id}/results`, { params }),
  getScanLogs: (id) => client.get(`/scans/${id}/logs`),
  exportScanUrl: (id, fmt) => `${API}/scans/${id}/export/${fmt}`,
  getBugBountyReport: (scanId, subdomain) => client.get(`/scans/${scanId}/report/bug-bounty/${encodeURIComponent(subdomain)}`),
  // Playbooks
  listPlaybooks: () => client.get('/playbooks'),
  getPlaybook: (key) => client.get(`/playbooks/${encodeURIComponent(key)}`),
  // Recon
  runRecon: (payload) => client.post('/recon', payload),
  // Screenshot
  takeScreenshot: (scanId, subdomain) => client.post(`/scans/${scanId}/screenshots/${encodeURIComponent(subdomain)}`),
  screenshotUrl: (scanId, subdomain) => `${API}/scans/${scanId}/screenshots/${encodeURIComponent(subdomain)}`,
  // Attack surface graph
  getGraph: (scanId) => client.get(`/scans/${scanId}/graph`),
  // Settings
  getSettings: () => client.get('/settings'),
  updateSettings: (payload) => client.put('/settings', payload),
  // Monitors
  listMonitors: () => client.get('/monitors'),
  createMonitor: (payload) => client.post('/monitors', payload),
  updateMonitor: (id, payload) => client.put(`/monitors/${id}`, payload),
  deleteMonitor: (id) => client.delete(`/monitors/${id}`),
  // Vuln Scanner v6 (Weaponized)
  vulnInfo: () => client.get('/vuln/info'),
  createVulnScan: (payload) => client.post('/vuln/scans', payload),
  listVulnScans: (params) => client.get('/vuln/scans', { params }),
  getVulnScan: (id) => client.get(`/vuln/scans/${id}`),
  getVulnScanLogs: (id) => client.get(`/vuln/scans/${id}/logs`),
  getVulnScanFindings: (id, params) => client.get(`/vuln/scans/${id}/findings`, { params }),
  deleteVulnScan: (id) => client.delete(`/vuln/scans/${id}`),
  // v7.4 Stop + bulk operations
  cancelVulnScan: (id) => client.post(`/vuln/scans/${id}/cancel`),
  bulkCancelVulnScans: (ids) => client.post('/vuln/scans/bulk-cancel', { ids }),
  bulkDeleteVulnScans: (ids) => client.post('/vuln/scans/bulk-delete', { ids }),
  // v7.5 — AI FP predictor
  predictFalsePositives: (id, use_llm = false) =>
    client.post(`/vuln/scans/${id}/fp-predict?use_llm=${use_llm ? 'true' : 'false'}`),
  // v7.6 — Security posture indicator
  securityStatus: () => client.get('/security-status'),
  // v7.7 · Batch 6 · Total Annihilation
  batch6Info: () => client.get('/vuln/batch6-info'),
  wordlistsStats: () => client.get('/vuln/wordlists/stats'),
  wordlistsSync: (force = false) => client.post(`/vuln/wordlists/sync${force ? '?force=true' : ''}`),
  mutatePayload: (payload, waf) => client.post('/vuln/mutate', { payload, waf }),
  semanticDiff: (a, b) => client.post('/vuln/semantic-diff', { a, b }),
  crawlV2: (body) => client.post('/vuln/crawl-v2', body),
  aiCraftPayload: (body) => client.post('/vuln/ai-craft', body),
  aiVerifyFinding: (id, idx) => client.post(`/vuln/scans/${id}/ai-verify/${idx}`),
  aiTriage: (id) => client.post(`/vuln/scans/${id}/ai-triage`),
  aiChainsV2: (id, lang = 'ar') => client.post(`/vuln/scans/${id}/ai-chains-v2?lang=${lang}`),
  burpProject: (id) => `${(process.env.REACT_APP_BACKEND_URL || '').replace(/\/$/, '')}/api/vuln/scans/${id}/burp.zip`,
  scansHistoryDiff: (target) => client.get(`/vuln/history-diff?target=${encodeURIComponent(target)}`),
  // v7.2 Batch-1 endpoints
  explainFinding: (scanId, findingIndex, lang = 'ar') =>
    client.post(`/vuln/scans/${scanId}/explain`, { finding_index: findingIndex, lang }),
  suggestChains: (scanId, lang = 'ar') =>
    client.post(`/vuln/scans/${scanId}/suggest-chains?lang=${lang}`),
  // v7.3 Batch-2
  importNucleiText: (yaml_text) => client.post('/vuln/nuclei/import-text', { yaml_text }),
  listNucleiTemplates: () => client.get('/vuln/nuclei/templates'),
  deleteNucleiTemplate: (id) => client.delete(`/vuln/nuclei/templates/${id}`),
  listSchedules: () => client.get('/vuln/schedules'),
  createSchedule: (s) => client.post('/vuln/schedules', s),
  toggleSchedule: (id) => client.post(`/vuln/schedules/${id}/toggle`),
  deleteSchedule: (id) => client.delete(`/vuln/schedules/${id}`),
  reportMdUrl: (scanId, includeUnverified = false) =>
    `${client.defaults.baseURL}/vuln/scans/${scanId}/report.md?include_unverified=${includeUnverified}`,
  reportHtmlUrl: (scanId, includeUnverified = false) =>
    `${client.defaults.baseURL}/vuln/scans/${scanId}/report.html?include_unverified=${includeUnverified}`,
  findingScreenshotUrl: (scanId, hash) =>
    `${client.defaults.baseURL}/vuln/scans/${scanId}/screenshot/${hash}`,
  discoverSubdomains: (domain) => client.get(`/subdomains/${domain}`),
  getNotifyConfig: () => client.get('/vuln/notify-config'),
  setNotifyConfig: (cfg) => client.post('/vuln/notify-config', cfg),
  testNotify: (cfg) => client.post('/vuln/notify-test', cfg),
  listCustomPayloads: () => client.get('/vuln/payloads/custom'),
  addCustomPayload: (p) => client.post('/vuln/payloads/custom', p),
  deleteCustomPayload: (id) => client.delete(`/vuln/payloads/custom/${id}`),
  diffScans: (a, b) => client.get(`/vuln/scans/${a}/diff/${b}`),
  // v7.7.2 · Total Annihilation
  dashboardStats: () => client.get('/vuln/dashboard-stats'),
  jwtInspect: (token) => client.post('/vuln/jwt/inspect', { token }),
  jwtCrack: (token, max_secrets = 100000, tamper = null) =>
    client.post('/vuln/jwt/crack', { token, max_secrets, tamper }),
  graphqlProbe: (url) => client.post('/vuln/graphql/probe', { url }),
  racePost: (url, json_body, n = 50) =>
    client.post('/vuln/race', { url, method: 'POST', json_body, n }),
  raceGet: (url, n = 50) =>
    client.post('/vuln/race', { url, method: 'GET', n }),
  autopilot: (target, depth = 'medium') =>
    client.post('/vuln/autopilot', { target, depth }),
  exploitChain: (scanId) =>
    client.post(`/vuln/scans/${scanId}/exploit-chain`),
  listVulnMonitors: () => client.get('/vuln/monitors-v2'),
  createVulnMonitor: (m) => client.post('/vuln/monitors-v2', m),
  toggleVulnMonitor: (id) => client.post(`/vuln/monitors-v2/${id}/toggle`),
  deleteVulnMonitor: (id) => client.delete(`/vuln/monitors-v2/${id}`),
  // v7.8 · Weaponized Wave
  smugglingV2:      (urls) => client.post('/vuln/smuggling-v2', { urls }),
  cacheV2:          (urls) => client.post('/vuln/cache-v2', { urls }),
  aiPayloadGen:     (opts) => client.post('/vuln/payloads/ai-generate', opts),
  prototypePollution: (urls) => client.post('/vuln/prototype-pollution', { urls }),
  ssrfDeep:         (ssrf_url_template) => client.post('/vuln/ssrf-deep', { ssrf_url_template }),
  mfaBypass:        (opts) => client.post('/vuln/mfa-bypass', opts),
  scanCompliance:   (id) => client.post(`/vuln/scans/${id}/compliance`),
  scanBountyEstimate: (id) => client.post(`/vuln/scans/${id}/bounty-estimate`),
  cveFeedList:      (limit = 50) => client.get(`/vuln/cve-feed?limit=${limit}`),
  cveFeedSync:      () => client.post('/vuln/cve-feed/sync'),
  threatIntel:      () => client.get('/vuln/threat-intel'),
  // v7.9 · Commercial Wave — Billing
  billingTiers:     () => client.get('/billing/tiers'),
  billingStatus:    () => client.get('/billing/status'),
  billingCheckout:  (tier) => client.post('/billing/checkout', { tier }),
  billingPortal:    () => client.post('/billing/portal'),
  billingDowngrade: () => client.post('/billing/downgrade'),
  // v7.9 · Commercial Wave — Workspaces
  listWorkspaces:   () => client.get('/workspaces'),
  createWorkspace:  (payload) => client.post('/workspaces', payload),
  getWorkspace:     (id) => client.get(`/workspaces/${id}`),
  deleteWorkspace:  (id) => client.delete(`/workspaces/${id}`),
  inviteMember:     (id, payload) => client.post(`/workspaces/${id}/invite`, payload),
  acceptInvite:     (token) => client.post(`/workspaces/invites/${token}/accept`),
  updateMemberRole: (wid, uid, role) => client.patch(`/workspaces/${wid}/members/${uid}`, { role }),
  removeMember:     (wid, uid) => client.delete(`/workspaces/${wid}/members/${uid}`),
  assignScan:       (wid, payload) => client.post(`/workspaces/${wid}/assign`, payload),
  listAssignments:  (wid) => client.get(`/workspaces/${wid}/assignments`),
  addComment:       (wid, payload) => client.post(`/workspaces/${wid}/comments`, payload),
  listComments:     (wid, scanId) => client.get(`/workspaces/${wid}/comments/${scanId}`),
  // v7.9.2 · AI triple-vote triage + public API keys + social proof
  triageV2:         (scanId, max = 20) => client.post(`/vuln/scans/${scanId}/triage-v2?max_items=${max}`),
  verifyVote:       (finding) => client.post('/vuln/findings/verify-vote', finding),
  socialProof:      () => client.get('/stats/social-proof'),
  apiKeysList:      () => client.get('/pub/keys'),
  apiKeysCreate:    (payload) => client.post('/pub/keys', payload),
  apiKeysRevoke:    (id) => client.delete(`/pub/keys/${id}`),
  // Generic passthrough — for endpoints not yet in the helper list
  request: (path, opts = {}) => client.request({ url: path.replace(/^\/api/, ''), ...opts }),
  // Health
  health: () => client.get('/health'),
  healthDeep: () => client.get('/health/deep'),
};

export default api;
