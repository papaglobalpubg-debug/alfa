"""
AI-powered vulnerability explainer using Emergent LLM Key.
Uses Claude Sonnet 4.6 for high-quality Arabic + English explanations.
"""
import os
import json
from typing import Dict, Optional

from emergentintegrations.llm.chat import LlmChat, UserMessage


SYSTEM_PROMPT_AR = """أنت خبير أمن سيبراني عربي محترف تشرح ثغرات الويب لمُختبِري الاختراق.
لكل ثغرة تشرح باللغة العربية:
1. **ما هي الثغرة؟** (شرح مبسّط)
2. **أين مكان الثغرة بالضبط؟** (URL / parameter / header / cookie)
3. **لماذا هي خطيرة؟** (السيناريو الأسوأ)
4. **كيف يستغلها المهاجم؟** (خطوات عملية + payload جاهز)
5. **كيف نصلحها؟** (الحل التقني الصحيح + مثال كود)
6. **مرجع خارجي** (OWASP / CVE / CWE)

كن دقيقاً ومباشراً. لا تخترع معلومات. إذا الأدلة ضعيفة قل "بحاجة تحقق يدوي".
اجعل إجابتك منظّمة بـ Markdown مع عناوين (##) وقوائم."""

SYSTEM_PROMPT_EN = """You are a professional cybersecurity expert explaining web vulnerabilities to pentesters.
For each finding explain in English:
1. **What is it?**
2. **Exact location** (URL / parameter / header / cookie)
3. **Why is it dangerous?** (worst-case scenario)
4. **How does an attacker exploit it?** (concrete PoC steps + ready payload)
5. **How to fix?** (technical fix + code example)
6. **References** (OWASP / CVE / CWE)

Be accurate and direct. Never invent facts. If evidence is weak, say "requires manual verification".
Output well-structured Markdown with ## headings and lists."""


async def explain_finding(finding: Dict, lang: str = 'ar', session_id: Optional[str] = None) -> Dict:
    """
    Get an AI-generated explanation for a single vulnerability finding.
    Returns: {'explanation': markdown_text, 'lang': ..., 'model': ...}
    """
    api_key = os.environ.get('EMERGENT_LLM_KEY')
    if not api_key:
        return {'error': 'EMERGENT_LLM_KEY not configured', 'explanation': ''}

    sys_prompt = SYSTEM_PROMPT_AR if lang == 'ar' else SYSTEM_PROMPT_EN

    # Compact the finding for the prompt (remove noise)
    compact = {k: v for k, v in finding.items() if k in {
        'type', 'subtype', 'severity', 'cvss', 'url', 'param', 'payload',
        'evidence', 'name', 'cve', 'method', 'confidence', 'verified',
        'delay', 'secret_type', 'value_snippet', 'csp_value', 'redirect_to',
    } and v is not None}
    # Truncate evidence for LLM context
    if 'evidence' in compact and len(str(compact['evidence'])) > 800:
        compact['evidence'] = str(compact['evidence'])[:800] + '...'

    user_prompt = ('اشرح هذه الثغرة بالتفصيل:\n\n' if lang == 'ar' else 'Explain this finding in detail:\n\n') + \
                  json.dumps(compact, ensure_ascii=False, indent=2)

    chat = LlmChat(
        api_key=api_key,
        session_id=session_id or f'vuln-{finding.get("type", "x")}-{finding.get("url", "")[:30]}',
        system_message=sys_prompt,
    ).with_model('anthropic', 'claude-sonnet-4-6')

    try:
        response = await chat.send_message(UserMessage(text=user_prompt))
        # send_message returns a string (not the stream — used for one-shot report gen)
        return {
            'explanation': str(response),
            'lang': lang,
            'model': 'claude-sonnet-4-6',
            'finding_type': finding.get('type'),
        }
    except Exception as e:
        err = str(e)
        # Friendly error for common cases
        if 'budget' in err.lower():
            err = ('LLM budget exhausted. Please top up your Emergent Universal Key '
                   'from Profile → Universal Key → Add Balance, or set your own '
                   'ANTHROPIC_API_KEY in backend/.env.')
        return {'error': err, 'explanation': ''}


async def suggest_attack_chain(findings: list, lang: str = 'ar') -> Dict:
    """
    LLM-based attack chain suggester. Analyzes ALL findings and suggests
    novel exploitation chains that the template-based builder may have missed.
    """
    api_key = os.environ.get('EMERGENT_LLM_KEY')
    if not api_key or not findings:
        return {'chains': [], 'error': None if api_key else 'no_llm_key'}

    verified = [f for f in findings if f.get('verified')]
    if len(verified) < 2:
        return {'chains': [], 'reason': 'need_at_least_2_verified'}

    compact_list = []
    for f in verified[:30]:
        compact_list.append({
            'type': f.get('type'), 'subtype': f.get('subtype'),
            'severity': f.get('severity'), 'url': f.get('url'),
            'param': f.get('param'),
        })

    sys = ("أنت خبير ثغرات ويب. حلّل قائمة الثغرات المؤكّدة واقترح سلاسل استغلال ذكية "
           "(كل سلسلة عبارة عن دمج ٢-٤ ثغرات لتحقيق أثر أكبر). "
           "أعد JSON فقط بالشكل: {\"chains\":[{\"name\":\"...\", \"severity\":\"critical\", "
           "\"steps\":[\"...\"], \"why_it_works\":\"...\"}]}") if lang == 'ar' else \
          ("You are a web exploit expert. Analyze the verified findings and suggest smart "
           "exploitation chains (each chain combines 2-4 findings). "
           "Return ONLY JSON: {\"chains\":[{\"name\":\"...\", \"severity\":\"critical\", "
           "\"steps\":[\"...\"], \"why_it_works\":\"...\"}]}")

    chat = LlmChat(api_key=api_key, session_id='chain-suggest',
                   system_message=sys).with_model('anthropic', 'claude-sonnet-4-6')
    try:
        resp = await chat.send_message(UserMessage(
            text=json.dumps({'findings': compact_list}, ensure_ascii=False)))
        text = str(resp).strip()
        # Extract JSON block
        if '```json' in text:
            text = text.split('```json', 1)[1].split('```', 1)[0]
        elif '```' in text:
            text = text.split('```', 1)[1].split('```', 1)[0]
        try:
            data = json.loads(text)
            return {'chains': data.get('chains', []), 'model': 'claude-sonnet-4-6'}
        except json.JSONDecodeError:
            return {'chains': [], 'raw': text[:500], 'error': 'json_parse'}
    except Exception as e:
        return {'chains': [], 'error': str(e)}


def fp_predictor_score(finding: Dict) -> float:
    """
    Heuristic false-positive predictor (0.0 = definitely real, 1.0 = definitely FP).
    Based on rules learned from tesla-style FPs.
    """
    score = 0.0
    ev = (finding.get('evidence') or '').lower()
    conf = finding.get('confidence', 50)
    verified = finding.get('verified')

    # 1. WAF/CDN markers
    waf_hints = ['access denied', "you don't have permission", 'reference #',
                 'blocked by', 'cloudfront', 'cloudflare', 'akamai',
                 '<title>attention required', 'error 1020']
    if any(h in ev for h in waf_hints):
        score += 0.6

    # 2. Not verified
    if verified is False:
        score += 0.25

    # 3. Low confidence
    if conf < 60:
        score += 0.2

    # 4. Same-domain redirect
    if finding.get('type') == 'open_redirect':
        redirect_to = (finding.get('redirect_to') or '').lower()
        url = (finding.get('url') or '').lower()
        try:
            from urllib.parse import urlparse
            h1 = urlparse(url).hostname or ''
            h2 = urlparse(redirect_to).hostname or ''
            if h1 and h2 and (h1 == h2 or h1.replace('www.', '') == h2.replace('www.', '')):
                score += 0.5
        except Exception:
            pass

    # 5. Reflected XSS in JSON response
    if finding.get('type') == 'xss':
        ct = (finding.get('content_type') or '').lower()
        if 'json' in ct or (finding.get('evidence') or '').startswith('{'):
            score += 0.5

    return min(score, 1.0)
