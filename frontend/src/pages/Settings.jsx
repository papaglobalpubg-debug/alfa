import React, { useEffect, useState } from 'react';
import api from '@/lib/api';
import { SETTINGS } from '@/constants/testIds';
import { Save, Key, Webhook, Send, Check } from 'lucide-react';

const API_KEYS = [
  { key: 'securitytrails', label: 'SecurityTrails', hint: 'securitytrails.com/app' },
  { key: 'shodan', label: 'Shodan', hint: 'account.shodan.io/' },
  { key: 'virustotal', label: 'VirusTotal', hint: 'virustotal.com/gui/my-apikey' },
  { key: 'chaos', label: 'Chaos (ProjectDiscovery)', hint: 'chaos.projectdiscovery.io' },
  { key: 'binaryedge', label: 'BinaryEdge', hint: 'binaryedge.io' },
  { key: 'censys_id', label: 'Censys API ID', hint: 'search.censys.io/account' },
  { key: 'censys_secret', label: 'Censys Secret', hint: 'search.censys.io/account' },
];

export default function Settings() {
  const [settings, setSettings] = useState(null);
  const [keys, setKeys] = useState({});
  const [slack, setSlack] = useState('');
  const [discord, setDiscord] = useState('');
  const [tgToken, setTgToken] = useState('');
  const [tgChat, setTgChat] = useState('');
  const [saved, setSaved] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getSettings().then(({ data }) => {
      setSettings(data);
      setSlack(data.webhooks?.slack || '');
      setDiscord(data.webhooks?.discord || '');
      setTgChat(data.telegram?.chat_id || '');
      setLoading(false);
    });
  }, []);

  const save = async () => {
    const payload = {
      api_keys: keys,
      webhooks: { slack, discord },
      telegram: {
        ...(tgToken ? { token: tgToken } : {}),
        chat_id: tgChat,
      },
    };
    await api.updateSettings(payload);
    setKeys({});
    setTgToken('');
    setSaved(true);
    // reload
    const { data } = await api.getSettings();
    setSettings(data);
    setTimeout(() => setSaved(false), 2000);
  };

  const isKeySet = (k) => settings?.api_keys_set?.includes(k);
  const maskedFor = (k) => settings?.api_keys_masked?.[k];

  if (loading) return <div className="text-zinc-500 mono p-8">Loading settings...</div>;

  return (
    <div data-testid={SETTINGS.container} className="max-w-3xl space-y-6">
      <header>
        <h1 className="text-2xl font-display font-bold text-zinc-50 tracking-tight">
          <span className="text-emerald-500">&gt;</span> Settings
        </h1>
        <p className="text-zinc-500 text-sm mt-1 mono">
          Configure API keys and webhook integrations
        </p>
      </header>

      <section className="bg-zinc-900 border border-zinc-800 p-5">
        <div className="flex items-center gap-2 mb-3">
          <Key className="w-4 h-4 text-emerald-500" strokeWidth={1.5} />
          <h2 className="text-sm uppercase tracking-widest text-zinc-300 mono">
            API Keys (optional, unlock premium sources)
          </h2>
        </div>
        <p className="text-xs text-zinc-500 mono mb-4">
          Enter a new value to update. Existing keys are masked. Leave blank to keep unchanged; enter empty string in field then save with intent to remove.
        </p>
        <div className="space-y-3">
          {API_KEYS.map(({ key, label, hint }) => (
            <label key={key} className="block">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs text-zinc-300 mono">{label}</span>
                {isKeySet(key) && (
                  <span className="text-[10px] text-emerald-500 mono">
                    SET {maskedFor(key)}
                  </span>
                )}
              </div>
              <input
                data-testid={SETTINGS.apiKeyInput(key)}
                type="password"
                value={keys[key] || ''}
                onChange={(e) => setKeys({ ...keys, [key]: e.target.value })}
                placeholder={isKeySet(key) ? '(set) enter new value to update' : hint}
                className="w-full px-3 py-2 bg-black border border-zinc-800 mono text-xs text-zinc-300 focus:outline-none focus:border-emerald-500"
              />
              <div className="text-[10px] text-zinc-600 mono mt-1">Get from: {hint}</div>
            </label>
          ))}
        </div>
      </section>

      <section className="bg-zinc-900 border border-zinc-800 p-5">
        <div className="flex items-center gap-2 mb-3">
          <Webhook className="w-4 h-4 text-emerald-500" strokeWidth={1.5} />
          <h2 className="text-sm uppercase tracking-widest text-zinc-300 mono">
            Webhook Alerts
          </h2>
        </div>
        <div className="space-y-3">
          <label className="block">
            <div className="text-xs text-zinc-300 mono mb-1">Slack Webhook URL</div>
            <input
              data-testid={SETTINGS.slackInput}
              type="text"
              value={slack}
              onChange={(e) => setSlack(e.target.value)}
              placeholder="https://hooks.slack.com/services/..."
              className="w-full px-3 py-2 bg-black border border-zinc-800 mono text-xs text-zinc-300 focus:outline-none focus:border-emerald-500"
            />
          </label>
          <label className="block">
            <div className="text-xs text-zinc-300 mono mb-1">Discord Webhook URL</div>
            <input
              data-testid={SETTINGS.discordInput}
              type="text"
              value={discord}
              onChange={(e) => setDiscord(e.target.value)}
              placeholder="https://discord.com/api/webhooks/..."
              className="w-full px-3 py-2 bg-black border border-zinc-800 mono text-xs text-zinc-300 focus:outline-none focus:border-emerald-500"
            />
          </label>
        </div>
      </section>

      <section className="bg-zinc-900 border border-zinc-800 p-5">
        <div className="flex items-center gap-2 mb-3">
          <Send className="w-4 h-4 text-emerald-500" strokeWidth={1.5} />
          <h2 className="text-sm uppercase tracking-widest text-zinc-300 mono">
            Telegram
          </h2>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <label className="block">
            <div className="text-xs text-zinc-300 mono mb-1">
              Bot Token {settings?.telegram?.token_set && <span className="text-emerald-500">(set)</span>}
            </div>
            <input
              data-testid={SETTINGS.telegramToken}
              type="password"
              value={tgToken}
              onChange={(e) => setTgToken(e.target.value)}
              placeholder="123456:ABC..."
              className="w-full px-3 py-2 bg-black border border-zinc-800 mono text-xs text-zinc-300 focus:outline-none focus:border-emerald-500"
            />
          </label>
          <label className="block">
            <div className="text-xs text-zinc-300 mono mb-1">Chat ID</div>
            <input
              data-testid={SETTINGS.telegramChat}
              type="text"
              value={tgChat}
              onChange={(e) => setTgChat(e.target.value)}
              placeholder="-1001234567890"
              className="w-full px-3 py-2 bg-black border border-zinc-800 mono text-xs text-zinc-300 focus:outline-none focus:border-emerald-500"
            />
          </label>
        </div>
      </section>

      <div className="flex justify-end items-center gap-3">
        {saved && (
          <span className="text-emerald-500 mono text-xs flex items-center gap-1">
            <Check className="w-3 h-3" /> Saved
          </span>
        )}
        <button
          data-testid={SETTINGS.saveBtn}
          onClick={save}
          className="flex items-center gap-2 px-6 py-2 bg-emerald-500 text-zinc-950 font-semibold hover:bg-emerald-400 mono text-sm transition-colors"
        >
          <Save className="w-4 h-4" /> Save Settings
        </button>
      </div>
    </div>
  );
}
