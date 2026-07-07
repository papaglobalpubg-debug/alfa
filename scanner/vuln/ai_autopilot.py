"""
CyberScope v7.7.2 · AI Autopilot Pentester.

Given a target URL, the autopilot lets the LLM decide the plan:
  1. Fingerprint the target
  2. Ask the AI to output a JSON plan: which modules to run, in what order,
     which params to focus on, and what payloads to prefer.
  3. Execute the plan (via the existing orchestrator) with the
     LLM-chosen module list.
  4. After the scan, ask the AI to build an exploitation chain from the
     findings and rank them by real-world impact (P0 → P3).

Uses the Emergent LLM key via emergentintegrations (same pattern as the
existing ai_destroyer module).
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

# Available modules the AI may choose from — MUST match orchestrator.
AVAILABLE_MODULES = [
    'fingerprint', 'recon', 'crawler', 'xss', 'sqli', 'nosqli', 'cmd',
    'ssti', 'lfi', 'xxe', 'ssrf', 'open_redirect', 'cors', 'crlf',
    'smuggling', 'cache_poisoning', 'prototype_pollution', 'graphql',
    'deserialization', 'cloud_buckets', 'infra_apis', 'cve_templates',
    'secrets', 'port_scan', 'host_header', 'web_cache_deception',
    'client_proto', 'csp', 'directory_listing', 'http_methods', 'sri',
    'api_security', 'oauth_saml', 'mobile_backend', 'web3',
]


async def _ask_llm(system: str, prompt: str, key: Optional[str] = None) -> str:
    """Small wrapper around emergentintegrations LlmChat.  Returns text."""
    key = key or os.environ.get('EMERGENT_LLM_KEY')
    if not key:
        return ''
    try:
        from emergentintegrations.llm.chat import LlmChat, UserMessage
        chat = (LlmChat(api_key=key, session_id='autopilot', system_message=system)
                .with_model('anthropic', 'claude-sonnet-4-20250514'))
        resp = await chat.send_message(UserMessage(text=prompt))
        return resp or ''
    except Exception as e:
        return f'ERROR:{e}'


def _extract_json(text: str) -> Dict[str, Any]:
    """Robustly extract the first JSON object from an LLM reply."""
    if not text:
        return {}
    # Try fenced JSON first
    for tag in ('```json', '```'):
        if tag in text:
            frag = text.split(tag, 1)[1]
            if '```' in frag:
                frag = frag.split('```', 1)[0]
            try:
                return json.loads(frag)
            except Exception:
                pass
    # Try raw first-brace-to-last-brace slice
    start, end = text.find('{'), text.rfind('}')
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except Exception:
            pass
    return {}


async def plan_attack(fingerprint: Dict[str, Any],
                       target: str,
                       recon_summary: str = '',
                       llm_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Ask the LLM to build an attack plan for the target based on fingerprint.
    Returns {modules: [...], notes: '...', priority: '...'}.
    """
    system = (
        "You are an elite offensive security AI. Given a fingerprint of a web "
        "target, output a JSON plan choosing which vulnerability modules to run. "
        "You MUST respond with valid JSON ONLY, no prose. Schema: "
        "{\"modules\": [\"module1\", \"module2\", ...], "
        "\"priority_params\": [\"id\", \"file\", ...], "
        "\"reason\": \"short justification\"}"
    )
    prompt = (
        f"TARGET: {target}\n"
        f"FINGERPRINT: {json.dumps(fingerprint)[:1500]}\n"
        f"RECON: {recon_summary[:1500]}\n\n"
        f"Available modules: {AVAILABLE_MODULES}\n"
        f"Pick 8-15 modules that give maximum coverage for THIS target. "
        f"Prioritise fingerprint-relevant modules. Return JSON only."
    )
    txt = await _ask_llm(system, prompt, key=llm_key)
    plan = _extract_json(txt) if txt else {}
    # Sanity — filter unknown modules
    modules = [m for m in (plan.get('modules') or []) if m in AVAILABLE_MODULES]
    if not modules:
        # Fallback plan
        modules = ['fingerprint', 'recon', 'crawler', 'xss', 'sqli', 'ssrf',
                   'open_redirect', 'cors', 'csp', 'directory_listing']
        plan_reason = 'LLM unavailable — fell back to broad-coverage default.'
    else:
        plan_reason = plan.get('reason') or 'LLM-chosen plan.'
    return {
        'modules': modules,
        'priority_params': plan.get('priority_params') or [],
        'reason': plan_reason,
        'raw': txt[:800],
    }


async def build_exploit_chain(findings: List[Dict[str, Any]],
                               target: str,
                               llm_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Given a findings list, ask the LLM to weave them into a chained exploit
    story (e.g. XSS → CSRF → IDOR → account takeover) and rank each finding
    P0/P1/P2/P3.
    """
    if not findings:
        return {'chain': [], 'ranked': []}
    system = (
        "You are an elite bug-bounty triager. Given a list of security "
        "findings, produce (a) chained exploit story ideas and (b) a P0-P3 "
        "ranking. RESPOND WITH JSON ONLY. Schema: "
        "{\"chains\": [{\"title\": \"...\", \"steps\": [\"...\"], "
        "\"impact\": \"...\"}], "
        "\"ranked\": [{\"finding_index\": 0, \"priority\": \"P0\", "
        "\"reason\": \"...\", \"estimated_bounty\": \"$xxxx\"}]}"
    )
    # Slim down findings for token budget
    slim = [
        {'i': i, 'type': f.get('type'), 'subtype': f.get('subtype'),
         'severity': f.get('severity'), 'url': (f.get('url') or '')[:80],
         'evidence': (f.get('evidence') or '')[:150]}
        for i, f in enumerate(findings[:30])
    ]
    prompt = (
        f"TARGET: {target}\n"
        f"FINDINGS ({len(slim)} shown of {len(findings)}):\n"
        f"{json.dumps(slim)}\n\n"
        "Build 1-3 exploit chains and rank the findings.  Return JSON only."
    )
    txt = await _ask_llm(system, prompt, key=llm_key)
    data = _extract_json(txt) if txt else {}
    return {
        'chains': data.get('chains') or [],
        'ranked': data.get('ranked') or [],
        'raw': txt[:1200],
    }
