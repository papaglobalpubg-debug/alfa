import React, { useState, useEffect } from 'react';
import { Bell, Send, CheckCircle2, XCircle } from 'lucide-react';
import api from '@/lib/api';

const NotifyRow = ({ label, hint, children }) => (
  <div className="border border-zinc-800 bg-zinc-950 p-4">
    <div className="text-xs mono uppercase tracking-widest text-emerald-500 mb-2">{label}</div>
    {hint && <p className="text-[11px] mono text-zinc-500 mb-2">{hint}</p>}
    {children}
  </div>
);

const NotifyInput = (props) => (
  <input
    {...props}
    className={`w-full bg-zinc-900 border border-zinc-800 px-3 py-2 text-sm mono text-zinc-100
                focus:border-emerald-500 focus:outline-none ${props.className || ''}`}
  />
);

export default function NotificationsPage() {
  const [cfg, setCfg] = useState({
    slack_webhook: '', discord_webhook: '', telegram_bot_token: '',
    telegram_chat_id: '', generic_webhook: '', email_to: '',
    smtp: { host: '', port: 587, user: '', password: '', from_addr: '' },
  });
  // v7.6 · SEC-004 — remember which secret fields already have a stored value
  // on the server so we can show "•••• configured" placeholder + not send an
  // empty string on save (which would wipe the real secret).
  const [status, setStatus] = useState({
    slack_webhook_configured: false, slack_webhook_preview: null,
    discord_webhook_configured: false, discord_webhook_preview: null,
    telegram_bot_token_configured: false, telegram_bot_token_preview: null,
    generic_webhook_configured: false, generic_webhook_preview: null,
  });
  const [saved, setSaved] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);

  useEffect(() => {
    api.getNotifyConfig().then(r => {
      if (r.data) {
        // Never mirror masked previews back into the form as if they were real
        // secret values — keep local inputs empty and store the "configured"
        // flags separately so the UI can hint at existing values.
        const nonSecret = {
          telegram_chat_id: r.data.telegram_chat_id || '',
          email_to: r.data.email_to || '',
          smtp: r.data.smtp || cfg.smtp,
        };
        setCfg(prev => ({ ...prev, ...nonSecret }));
        setStatus({
          slack_webhook_configured: !!r.data.slack_webhook_configured,
          slack_webhook_preview: r.data.slack_webhook_preview || null,
          discord_webhook_configured: !!r.data.discord_webhook_configured,
          discord_webhook_preview: r.data.discord_webhook_preview || null,
          telegram_bot_token_configured: !!r.data.telegram_bot_token_configured,
          telegram_bot_token_preview: r.data.telegram_bot_token_preview || null,
          generic_webhook_configured: !!r.data.generic_webhook_configured,
          generic_webhook_preview: r.data.generic_webhook_preview || null,
        });
      }
    }).catch(() => { /* best-effort */ });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const save = async () => {
    // Only send fields that the user has actually typed into.
    const payload = {};
    for (const k of ['slack_webhook', 'discord_webhook', 'telegram_bot_token',
                     'telegram_chat_id', 'generic_webhook', 'email_to']) {
      if (cfg[k]) payload[k] = cfg[k];
    }
    if (cfg.smtp && (cfg.smtp.host || cfg.smtp.user)) payload.smtp = cfg.smtp;
    await api.setNotifyConfig(payload);
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
    // reload to see new masked previews
    const r = await api.getNotifyConfig();
    if (r.data) {
      setStatus({
        slack_webhook_configured: !!r.data.slack_webhook_configured,
        slack_webhook_preview: r.data.slack_webhook_preview || null,
        discord_webhook_configured: !!r.data.discord_webhook_configured,
        discord_webhook_preview: r.data.discord_webhook_preview || null,
        telegram_bot_token_configured: !!r.data.telegram_bot_token_configured,
        telegram_bot_token_preview: r.data.telegram_bot_token_preview || null,
        generic_webhook_configured: !!r.data.generic_webhook_configured,
        generic_webhook_preview: r.data.generic_webhook_preview || null,
      });
      setCfg(prev => ({
        ...prev,
        slack_webhook: '', discord_webhook: '',
        telegram_bot_token: '', generic_webhook: '',
      }));
    }
  };

  const test = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const r = await api.testNotify(cfg);
      setTestResult(r.data);
    } catch (e) {
      setTestResult({ error: String(e) });
    } finally {
      setTesting(false);
    }
  };

  const upd = (k, v) => setCfg({ ...cfg, [k]: v });
  const updSmtp = (k, v) => setCfg({ ...cfg, smtp: { ...cfg.smtp, [k]: v } });

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-4" data-testid="notifications-page">
      <div className="flex items-center gap-3 mb-2">
        <Bell className="w-6 h-6 text-emerald-500" />
        <div>
          <h1 className="text-2xl font-bold text-zinc-50">Notifications</h1>
          <p className="text-xs mono text-zinc-500">Receive alerts when critical findings are discovered.</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <NotifyRow label="Slack Webhook" hint={status.slack_webhook_configured
              ? `✓ configured (${status.slack_webhook_preview}) — leave blank to keep, or paste a new URL to replace`
              : 'Create at api.slack.com/messaging/webhooks'}>
          <NotifyInput value={cfg.slack_webhook || ''} onChange={e => upd('slack_webhook', e.target.value)}
                 placeholder={status.slack_webhook_configured ? '•••• leave blank to keep current ••••' : 'https://hooks.slack.com/services/...'}
                 data-testid="slack-webhook-input" />
        </NotifyRow>
        <NotifyRow label="Discord Webhook" hint={status.discord_webhook_configured
              ? `✓ configured (${status.discord_webhook_preview}) — leave blank to keep, or paste a new URL to replace`
              : 'Server Settings → Integrations → Webhooks'}>
          <NotifyInput value={cfg.discord_webhook || ''} onChange={e => upd('discord_webhook', e.target.value)}
                 placeholder={status.discord_webhook_configured ? '•••• leave blank to keep current ••••' : 'https://discord.com/api/webhooks/...'}
                 data-testid="discord-webhook-input" />
        </NotifyRow>
        <NotifyRow label="Telegram Bot Token" hint={status.telegram_bot_token_configured
              ? `✓ configured (${status.telegram_bot_token_preview}) — leave blank to keep`
              : 'Get from @BotFather'}>
          <NotifyInput value={cfg.telegram_bot_token || ''} onChange={e => upd('telegram_bot_token', e.target.value)}
                 placeholder={status.telegram_bot_token_configured ? '•••• leave blank to keep current ••••' : '123456:ABC-DEF...'}
                 data-testid="telegram-token-input" />
        </NotifyRow>
        <NotifyRow label="Telegram Chat ID" hint="Get from @userinfobot">
          <NotifyInput value={cfg.telegram_chat_id || ''} onChange={e => upd('telegram_chat_id', e.target.value)}
                 placeholder="-100..." data-testid="telegram-chat-input" />
        </NotifyRow>
        <NotifyRow label="Generic Webhook" hint={status.generic_webhook_configured
              ? `✓ configured (${status.generic_webhook_preview}) — leave blank to keep`
              : 'Any HTTPS URL that accepts POST JSON'}>
          <NotifyInput value={cfg.generic_webhook || ''} onChange={e => upd('generic_webhook', e.target.value)}
                 placeholder={status.generic_webhook_configured ? '•••• leave blank to keep current ••••' : 'https://your-endpoint.com/hook'}
                 data-testid="webhook-input" />
        </NotifyRow>
        <NotifyRow label="Email address">
          <NotifyInput value={cfg.email_to || ''} onChange={e => upd('email_to', e.target.value)}
                 placeholder="you@example.com" data-testid="email-input" />
        </NotifyRow>
      </div>

      <div className="border border-zinc-800 bg-zinc-950 p-4">
        <div className="text-xs mono uppercase tracking-widest text-emerald-500 mb-2">SMTP (for Email)</div>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
          <NotifyInput value={cfg.smtp?.host || ''} onChange={e => updSmtp('host', e.target.value)} placeholder="smtp.gmail.com" />
          <NotifyInput value={cfg.smtp?.port || 587} onChange={e => updSmtp('port', e.target.value)} placeholder="587" />
          <NotifyInput value={cfg.smtp?.user || ''} onChange={e => updSmtp('user', e.target.value)} placeholder="user@gmail.com" />
          <NotifyInput type="password" value={cfg.smtp?.password || ''} onChange={e => updSmtp('password', e.target.value)} placeholder="app password" />
          <NotifyInput value={cfg.smtp?.from_addr || ''} onChange={e => updSmtp('from_addr', e.target.value)} placeholder="from address" />
        </div>
      </div>

      <div className="flex gap-3">
        <button onClick={save} data-testid="save-notify-config"
                className="px-4 py-2 bg-emerald-500 hover:bg-emerald-600 text-black font-bold mono text-xs uppercase tracking-widest">
          {saved ? '✓ Saved' : 'Save Configuration'}
        </button>
        <button onClick={test} disabled={testing} data-testid="test-notify"
                className="px-4 py-2 border border-zinc-700 text-zinc-300 hover:text-emerald-400 hover:border-emerald-500/40 mono text-xs uppercase tracking-widest flex items-center gap-2">
          <Send className="w-3 h-3" /> {testing ? 'Sending...' : 'Send Test'}
        </button>
      </div>

      {testResult && (
        <div className="border border-zinc-800 bg-zinc-950 p-4 mono text-xs" data-testid="test-result">
          <div className="text-emerald-500 uppercase tracking-widest text-[10px] mb-2">Test Result</div>
          {Object.entries(testResult).map(([channel, ok]) => (
            <div key={channel} className="flex items-center gap-2 text-zinc-300">
              {ok === true ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> :
                             <XCircle className="w-4 h-4 text-red-400" />}
              {channel}: {ok === true ? 'delivered' : String(ok)}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
