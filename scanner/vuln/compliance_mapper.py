"""
CyberScope v7.8 · Compliance Mapper.

Given a findings list, maps each finding to the relevant control(s) of
several major frameworks: OWASP Top 10 (2021+2024), CWE, PCI-DSS v4,
GDPR articles, SOC 2, HIPAA.

Also produces a per-framework "Compliance Score" (0-100).
"""
from __future__ import annotations

from typing import Any, Dict, List


MAP = {
    # type/subtype → framework → control
    'xss': {
        'owasp': 'A03:2021 Injection',
        'cwe': 'CWE-79',
        'pci': '6.5.7 Cross-site scripting',
        'gdpr': 'Art. 32 - Security of processing',
        'soc2': 'CC6.1 - Logical access',
        'hipaa': '§164.308(a)(1) - Security management',
    },
    'sqli': {
        'owasp': 'A03:2021 Injection',
        'cwe': 'CWE-89',
        'pci': '6.5.1 Injection flaws',
        'gdpr': 'Art. 32 - Security of processing',
        'soc2': 'CC6.6 - Data protection',
        'hipaa': '§164.312(c)(1) - Integrity',
    },
    'ssrf': {
        'owasp': 'A10:2021 SSRF',
        'cwe': 'CWE-918',
        'pci': '6.5.10 Broken access',
        'gdpr': 'Art. 32',
        'soc2': 'CC6.6',
        'hipaa': '§164.312(a)(1) - Access control',
    },
    'open_redirect': {
        'owasp': 'A01:2021 Broken Access Control',
        'cwe': 'CWE-601',
        'pci': '6.5.10',
        'gdpr': 'Art. 32',
        'soc2': 'CC6.1',
        'hipaa': '§164.308(a)(3)',
    },
    'cors': {
        'owasp': 'A05:2021 Security Misconfig',
        'cwe': 'CWE-346',
        'pci': '2.2 Configuration standards',
        'gdpr': 'Art. 32',
        'soc2': 'CC6.7',
        'hipaa': '§164.312(e)(1)',
    },
    'csp': {
        'owasp': 'A05:2021 Security Misconfig',
        'cwe': 'CWE-1021',
        'pci': '2.2',
        'gdpr': 'Art. 32',
        'soc2': 'CC7.1',
        'hipaa': '§164.312(e)(2)(ii)',
    },
    'directory_listing': {
        'owasp': 'A05:2021 Security Misconfig',
        'cwe': 'CWE-548',
        'pci': '6.5.8 Improper access',
        'gdpr': 'Art. 32',
        'soc2': 'CC6.1',
        'hipaa': '§164.308(a)(4)',
    },
    'jwt_cracker': {
        'owasp': 'A02:2021 Cryptographic Failures',
        'cwe': 'CWE-347',
        'pci': '3.6 Cryptographic keys',
        'gdpr': 'Art. 32',
        'soc2': 'CC6.1',
        'hipaa': '§164.312(a)(2)(iv)',
    },
    'graphql': {
        'owasp': 'A05:2021 Security Misconfig',
        'cwe': 'CWE-200',
        'pci': '6.5.8',
        'gdpr': 'Art. 32',
        'soc2': 'CC6.6',
        'hipaa': '§164.312(a)(1)',
    },
    'race_condition': {
        'owasp': 'A04:2021 Insecure Design',
        'cwe': 'CWE-362',
        'pci': '6.5.10',
        'gdpr': 'Art. 32',
        'soc2': 'CC7.2',
        'hipaa': '§164.312(c)(2)',
    },
    'mfa_bypass': {
        'owasp': 'A07:2021 Identification & Authentication Failures',
        'cwe': 'CWE-287',
        'pci': '8.4 MFA requirement',
        'gdpr': 'Art. 32',
        'soc2': 'CC6.1',
        'hipaa': '§164.308(a)(5)',
    },
    'websocket': {
        'owasp': 'A05:2021 Security Misconfig',
        'cwe': 'CWE-346',
        'pci': '6.5.10',
        'gdpr': 'Art. 32',
        'soc2': 'CC6.6',
        'hipaa': '§164.312(e)(1)',
    },
    'http_smuggling': {
        'owasp': 'A05:2021 Security Misconfig',
        'cwe': 'CWE-444',
        'pci': '2.2',
        'gdpr': 'Art. 32',
        'soc2': 'CC7.2',
        'hipaa': '§164.312(e)(1)',
    },
    'web_cache_poisoning': {
        'owasp': 'A05:2021 Security Misconfig',
        'cwe': 'CWE-524',
        'pci': '6.5.10',
        'gdpr': 'Art. 32',
        'soc2': 'CC6.6',
        'hipaa': '§164.312(a)(1)',
    },
    'prototype_pollution': {
        'owasp': 'A03:2021 Injection',
        'cwe': 'CWE-1321',
        'pci': '6.5.1',
        'gdpr': 'Art. 32',
        'soc2': 'CC6.1',
        'hipaa': '§164.312(c)(2)',
    },
    'ssrf_deep': {
        'owasp': 'A10:2021 SSRF',
        'cwe': 'CWE-918',
        'pci': '6.5.10',
        'gdpr': 'Art. 32',
        'soc2': 'CC6.6',
        'hipaa': '§164.312(a)(1)',
    },
}


SEVERITY_WEIGHT = {'critical': 25, 'high': 10, 'medium': 3, 'low': 1, 'info': 0}


def map_findings(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Return per-finding mapping + per-framework scores + rollup counts."""
    mapped: List[Dict[str, Any]] = []
    by_framework: Dict[str, Dict[str, int]] = {
        'owasp': {}, 'cwe': {}, 'pci': {}, 'gdpr': {}, 'soc2': {}, 'hipaa': {},
    }
    penalty = 0
    for f in findings:
        typ = (f.get('type') or '').lower()
        mapping = MAP.get(typ) or {}
        mapped.append({**f, 'compliance': mapping})
        penalty += SEVERITY_WEIGHT.get(f.get('severity', 'info'), 0)
        for fw, ctrl in mapping.items():
            by_framework[fw][ctrl] = by_framework[fw].get(ctrl, 0) + 1

    score = max(0, min(100, 100 - penalty))
    return {
        'score': score,
        'penalty': penalty,
        'by_framework': by_framework,
        'total_findings': len(findings),
        'mapped_findings': len([m for m in mapped if m.get('compliance')]),
    }
