// Frontend testIds constants
export const NAV = {
  dashboard: 'nav-dashboard',
  newScan: 'nav-new-scan',
  history: 'nav-history',
  monitors: 'nav-monitors',
  settings: 'nav-settings',
  services: 'nav-services',
};

export const DASHBOARD = {
  container: 'dashboard-container',
  statTotalScans: 'stat-total-scans',
  statActive: 'stat-active-scans',
  statVerified: 'stat-verified',
  statClaimable: 'stat-claimable',
  statSubs: 'stat-subs',
  statServices: 'stat-services',
  recentTable: 'recent-scans-table',
  quickScanBtn: 'quick-scan-btn',
};

export const NEW_SCAN = {
  container: 'new-scan-container',
  domainInput: 'new-scan-domain-input',
  threadsInput: 'new-scan-threads-input',
  timeoutInput: 'new-scan-timeout-input',
  verifyToggle: 'new-scan-verify-toggle',
  notifyToggle: 'new-scan-notify-toggle',
  sourcesGroup: 'new-scan-sources',
  wordlistTextarea: 'new-scan-wordlist',
  submitBtn: 'new-scan-submit-btn',
  cancelBtn: 'new-scan-cancel-btn',
};

export const SCAN_DETAIL = {
  container: 'scan-detail-container',
  header: 'scan-detail-header',
  liveDot: 'scan-detail-live-dot',
  progressBar: 'scan-detail-progress',
  logsPanel: 'scan-detail-logs',
  filterPriority: 'filter-priority',
  filterClass: 'filter-class',
  filterSearch: 'filter-search',
  resultsTable: 'results-table',
  exportJson: 'export-json-btn',
  exportHtml: 'export-html-btn',
  exportCsv: 'export-csv-btn',
  exportTxt: 'export-txt-btn',
  deleteBtn: 'scan-delete-btn',
  rescanBtn: 'scan-rescan-btn',
};

export const HISTORY = {
  container: 'history-container',
  table: 'history-table',
  filterDomain: 'history-filter-domain',
  filterStatus: 'history-filter-status',
};

export const SETTINGS = {
  container: 'settings-container',
  apiKeyInput: (key) => `settings-apikey-${key}`,
  slackInput: 'settings-slack',
  discordInput: 'settings-discord',
  telegramToken: 'settings-telegram-token',
  telegramChat: 'settings-telegram-chat',
  saveBtn: 'settings-save-btn',
};

export const MONITORS = {
  container: 'monitors-container',
  addBtn: 'monitors-add-btn',
  domainInput: 'monitor-domain-input',
  intervalInput: 'monitor-interval-input',
  saveBtn: 'monitor-save-btn',
  table: 'monitors-table',
};

export const SERVICES = {
  container: 'services-container',
  searchInput: 'services-search',
  table: 'services-table',
};
