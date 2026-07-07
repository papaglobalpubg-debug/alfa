/**
 * CyberScope JavaScript SDK (v7.9.2)
 *
 * Requires: Enterprise or Lifetime plan.
 * Works in Node.js (18+) and modern browsers via native `fetch`.
 *
 * Usage:
 *   import { CyberScope } from './cyberscope-sdk.js';
 *   const cs = new CyberScope({ apiKey: 'cs_...', base: 'https://your-instance.com' });
 *   const scan = await cs.scan('https://example.com', { depth: 'deep' });
 *   const done = await cs.wait(scan.scan_id);
 *   const triage = await cs.triage(scan.scan_id);
 */

export class CyberScopeError extends Error {}

export class CyberScope {
  constructor({ apiKey, base = 'https://cyberscope.io', timeoutMs = 60000 } = {}) {
    if (!apiKey || !apiKey.startsWith('cs_')) {
      throw new Error("apiKey must start with 'cs_'");
    }
    this.apiKey = apiKey;
    this.base = base.replace(/\/$/, '');
    this.timeoutMs = timeoutMs;
  }

  async _req(method, path, { body, params } = {}) {
    let url = `${this.base}${path}`;
    if (params) {
      const qs = new URLSearchParams(params).toString();
      if (qs) url += `?${qs}`;
    }
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      const res = await fetch(url, {
        method,
        headers: {
          'X-API-Key': this.apiKey,
          'Content-Type': 'application/json',
          'User-Agent': 'cyberscope-sdk-js/7.9.2',
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: ctrl.signal,
      });
      if (!res.ok) {
        let detail;
        try { detail = (await res.json()).detail; }
        catch { detail = await res.text(); }
        throw new CyberScopeError(`HTTP ${res.status}: ${detail}`);
      }
      return res.json();
    } finally { clearTimeout(t); }
  }

  info() { return this._req('GET', '/api/pub/v1/info'); }

  scan(target, { depth = 'medium', modules } = {}) {
    const body = { target, depth };
    if (modules) body.modules = modules;
    return this._req('POST', '/api/pub/v1/scan', { body });
  }

  getScan(scanId) { return this._req('GET', `/api/pub/v1/scan/${scanId}`); }

  triage(scanId, maxItems = 20) {
    return this._req('GET', `/api/pub/v1/scan/${scanId}/triage`, { params: { max_items: maxItems } });
  }

  async wait(scanId, { pollMs = 5000, maxWaitMs = 900000 } = {}) {
    const deadline = Date.now() + maxWaitMs;
    while (Date.now() < deadline) {
      const s = await this.getScan(scanId);
      if (['done', 'failed', 'canceled'].includes(s.status)) return s;
      await new Promise((r) => setTimeout(r, pollMs));
    }
    throw new CyberScopeError('timeout_waiting_for_scan');
  }
}
