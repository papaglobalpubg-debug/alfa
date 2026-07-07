"""
CyberScope v7.8 · Weekly Threat Intel Feed.

Uses the Emergent LLM key to generate a personalised weekly intel brief
for the caller: what CVEs matter for their stack, notable HackerOne
writeups, recommended techniques to try next.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional


async def _ask_llm(system: str, prompt: str) -> str:
    key = os.environ.get('EMERGENT_LLM_KEY')
    if not key:
        return ''
    try:
        from emergentintegrations.llm.chat import LlmChat, UserMessage
        chat = (LlmChat(api_key=key, session_id='threat-intel', system_message=system)
                .with_model('anthropic', 'claude-sonnet-4-20250514'))
        return await chat.send_message(UserMessage(text=prompt)) or ''
    except Exception:
        return ''


async def generate_brief(recent_targets: List[str],
                         recent_tech_stack: List[str],
                         cves_context: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Given the user's recent scan targets and detected tech stack, produce
    a JSON-structured intel brief.
    """
    system = (
        "You are a senior threat-intelligence analyst.  Produce a concise "
        "weekly brief for a bug-bounty hunter based on their tech stack. "
        "Return JSON ONLY.  Schema: "
        "{"
        "  \"headline\": \"...\","
        "  \"cve_watchlist\": [{\"cve\": \"CVE-XXXX-XXXX\", \"why\": \"...\", \"impact\": \"...\"}],"
        "  \"writeup_ideas\": [{\"title\": \"...\", \"technique\": \"...\", \"expected_bounty\": \"$xxxx\"}],"
        "  \"top_techniques_to_try\": [\"...\", \"...\", \"...\"],"
        "  \"summary_words\": 60"
        "}"
    )
    prompt = (
        f"Bug hunter recent targets: {recent_targets[:10]}\n"
        f"Detected tech stack: {recent_tech_stack[:20]}\n"
        f"Recent high-severity CVEs (context, do not repeat verbatim): "
        f"{json.dumps((cves_context or [])[:5])}\n\n"
        "Produce this week's intel brief.  Return JSON only."
    )
    raw = await _ask_llm(system, prompt)
    # Robust JSON slice
    if raw:
        start, end = raw.find('{'), raw.rfind('}')
        if start != -1 and end > start:
            try:
                return {**json.loads(raw[start:end + 1]), 'raw': raw[:800]}
            except Exception:
                pass
    # Fallback brief
    return {
        'headline': 'AI unavailable — showing fallback brief',
        'cve_watchlist': [
            {'cve': 'CVE-2024-4577', 'why': 'PHP-CGI arg injection', 'impact': 'RCE (Windows)'},
            {'cve': 'CVE-2024-23897', 'why': 'Jenkins CLI arbitrary file read', 'impact': 'Credential leak'},
        ],
        'writeup_ideas': [
            {'title': 'GraphQL introspection → PII leak', 'technique': 'Batched introspection queries',
             'expected_bounty': '$500-$5000'},
            {'title': 'JWT alg=none forgery', 'technique': 'Header manipulation',
             'expected_bounty': '$2000-$10000'},
        ],
        'top_techniques_to_try': [
            'GraphQL query batching to bypass rate limits',
            'JWT weak-secret cracking with 104K wordlist',
            'HTTP request smuggling for cache poisoning',
        ],
        'summary_words': 60,
        'raw': '',
    }
