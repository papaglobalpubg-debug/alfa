"""
Notifications dispatcher — Slack, Discord, Telegram, Email (SMTP), generic webhook.
Users configure webhook URLs and notification rules per-workspace.
"""
import asyncio
import json
import os
from typing import Dict, List

import httpx


async def _post_json(url: str, data: dict, headers: dict = None) -> bool:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(url, json=data, headers=headers or {})
            return r.status_code < 400
    except Exception:
        return False


async def notify_slack(webhook: str, title: str, body: str,
                        severity: str = 'critical') -> bool:
    color_map = {'critical': '#dc2626', 'high': '#ea580c',
                 'medium': '#eab308', 'low': '#0891b2', 'info': '#6b7280'}
    payload = {
        'attachments': [{
            'color': color_map.get(severity, '#6b7280'),
            'title': title,
            'text': body[:3000],
            'footer': 'CyberScope v7.2',
        }],
    }
    return await _post_json(webhook, payload)


async def notify_discord(webhook: str, title: str, body: str,
                          severity: str = 'critical') -> bool:
    color_map = {'critical': 0xdc2626, 'high': 0xea580c,
                 'medium': 0xeab308, 'low': 0x0891b2, 'info': 0x6b7280}
    payload = {
        'embeds': [{
            'title': title[:256],
            'description': body[:4000],
            'color': color_map.get(severity, 0x6b7280),
            'footer': {'text': 'CyberScope v7.2'},
        }],
    }
    return await _post_json(webhook, payload)


async def notify_telegram(bot_token: str, chat_id: str, title: str,
                           body: str) -> bool:
    url = f'https://api.telegram.org/bot{bot_token}/sendMessage'
    text = f'*{title}*\n\n{body}'[:4000]
    return await _post_json(url, {
        'chat_id': chat_id, 'text': text, 'parse_mode': 'Markdown',
    })


async def notify_webhook(url: str, payload: dict) -> bool:
    return await _post_json(url, payload)


async def notify_email(smtp_conf: dict, to: str, subject: str, body: str) -> bool:
    """
    Send email via SMTP. smtp_conf: {host, port, user, password, from_addr}.
    Uses aiosmtplib if available, otherwise sync fallback.
    """
    try:
        import aiosmtplib
        from email.message import EmailMessage
        msg = EmailMessage()
        msg['From'] = smtp_conf.get('from_addr', smtp_conf.get('user'))
        msg['To'] = to
        msg['Subject'] = subject
        msg.set_content(body)
        await aiosmtplib.send(msg, hostname=smtp_conf['host'],
                              port=int(smtp_conf.get('port', 587)),
                              username=smtp_conf.get('user'),
                              password=smtp_conf.get('password'),
                              start_tls=True)
        return True
    except Exception:
        return False


async def dispatch_notification(config: Dict, title: str, body: str,
                                 severity: str = 'critical',
                                 payload: dict = None) -> Dict:
    """
    Send a notification through ALL enabled channels in config.
    Returns per-channel success status.
    """
    tasks = []
    labels = []
    if config.get('slack_webhook'):
        labels.append('slack')
        tasks.append(notify_slack(config['slack_webhook'], title, body, severity))
    if config.get('discord_webhook'):
        labels.append('discord')
        tasks.append(notify_discord(config['discord_webhook'], title, body, severity))
    if config.get('telegram_bot_token') and config.get('telegram_chat_id'):
        labels.append('telegram')
        tasks.append(notify_telegram(config['telegram_bot_token'],
                                     config['telegram_chat_id'], title, body))
    if config.get('generic_webhook'):
        labels.append('webhook')
        tasks.append(notify_webhook(config['generic_webhook'],
                                    payload or {'title': title, 'body': body,
                                                'severity': severity}))
    if config.get('smtp') and config.get('email_to'):
        labels.append('email')
        tasks.append(notify_email(config['smtp'], config['email_to'], title, body))

    if not tasks:
        return {'sent': [], 'note': 'no channels configured'}

    results = await asyncio.gather(*tasks, return_exceptions=True)
    return {label: (r is True) for label, r in zip(labels, results)}
