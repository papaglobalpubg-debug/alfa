"""
Nuclei YAML template importer.
Parses Nuclei-format YAML templates and converts them to CyberScope's
internal CVE template format.
Supports the most common matcher types: status, word, regex, header.
"""
import os
import re
from pathlib import Path
from typing import Dict, List, Optional

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


def parse_nuclei_template(template_yaml: str) -> Optional[Dict]:
    """Parse a single Nuclei template YAML and return CyberScope CVE dict."""
    if not HAS_YAML:
        return None
    # Preprocess: auto-quote {{...}} placeholders so PyYAML doesn't choke
    # on flow-style mapping conflicts.
    cleaned = re.sub(
        r'(?m)^(\s*-\s+)(\{\{[^\n]*)$',
        lambda m: f"{m.group(1)}'{m.group(2).strip()}'",
        template_yaml,
    )
    # Also handle inline: `path: {{BaseURL}}/x` (rare) — wrap in quotes
    cleaned = re.sub(
        r'(?m)(:\s+)(\{\{[^\n\']*)$',
        lambda m: f"{m.group(1)}'{m.group(2).strip()}'",
        cleaned,
    )
    try:
        data = yaml.safe_load(cleaned)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None

    info = data.get('info', {}) or {}
    if not info:
        return None

    sev_map = {'critical': 'critical', 'high': 'high', 'medium': 'medium',
               'low': 'low', 'info': 'info', 'unknown': 'info'}
    cvss_map = {'critical': 9.5, 'high': 8.0, 'medium': 6.0, 'low': 3.5, 'info': 0}
    sev = sev_map.get(str(info.get('severity', 'info')).lower(), 'info')

    # Extract CVE from tags / classification
    cve = None
    tags = info.get('tags', '')
    if isinstance(tags, str):
        m = re.search(r'CVE-\d{4}-\d+', tags, re.IGNORECASE)
        if m:
            cve = m.group(0).upper()
    classification = info.get('classification', {})
    if isinstance(classification, dict):
        cids = classification.get('cve-id') or classification.get('cve_id') or ''
        if isinstance(cids, str) and cids.startswith('CVE'):
            cve = cids.upper()

    # HTTP requests
    requests = data.get('http') or data.get('requests') or []
    if not requests:
        return None
    req = requests[0] if isinstance(requests, list) else {}

    method = 'GET'
    paths = []
    if isinstance(req, dict):
        raw_paths = req.get('path', [])
        if isinstance(raw_paths, str):
            raw_paths = [raw_paths]
        for p in raw_paths:
            p = str(p).replace('{{BaseURL}}', '').replace('{{Hostname}}', '')
            if not p.startswith('/'):
                p = '/' + p
            paths.append(p)
        method = (req.get('method') or 'GET').upper()

    if not paths:
        return None

    # Matchers
    match_status = []
    match_body = []
    match_headers = []
    header_match = {}

    matchers = req.get('matchers', []) if isinstance(req, dict) else []
    for m in matchers or []:
        if not isinstance(m, dict):
            continue
        t = m.get('type', '')
        # Nuclei stores values under 'status', 'words', 'regex' — NOT under the type name
        val_key_map = {'status': 'status', 'word': 'words', 'regex': 'regex',
                       'binary': 'binary', 'dsl': 'dsl'}
        vkey = val_key_map.get(t, t)
        parts = m.get(vkey, m.get(t, []))
        if not isinstance(parts, list):
            parts = [parts] if parts else []
        if t == 'status':
            for s in parts:
                try:
                    match_status.append(int(s))
                except (ValueError, TypeError):
                    pass
        elif t in ('word', 'words'):
            for w in parts:
                match_body.append(str(w))
        elif t == 'regex':
            for rgx in parts:
                try:
                    re.compile(rgx)
                    match_body.append(rgx)
                except re.error:
                    pass

    if not (match_body or match_status):
        return None

    tid = data.get('id') or info.get('name', 'nuclei-imported')
    return {
        'id': f'nuclei-{tid}',
        'cve': cve,
        'name': info.get('name', tid),
        'severity': sev,
        'cvss': float(info.get('cvss', {}).get('score', cvss_map[sev]))
                if isinstance(info.get('cvss'), dict) else cvss_map[sev],
        'method': method,
        'paths': paths[:5],
        'match_status': match_status or [200],
        'match_body': match_body[:5],
        'match_headers': match_headers,
        'header_match': header_match,
        'source': 'nuclei',
        'imported_from': tid,
    }


def import_from_directory(directory: str) -> Dict:
    """Walk a directory of .yaml files and return list of parsed templates."""
    if not HAS_YAML:
        return {'error': 'pyyaml not installed', 'imported': 0, 'templates': []}
    root = Path(directory)
    if not root.exists():
        return {'error': f'directory not found: {directory}', 'imported': 0, 'templates': []}
    templates = []
    errors = 0
    for path in root.rglob('*.yaml'):
        try:
            content = path.read_text(encoding='utf-8')
            parsed = parse_nuclei_template(content)
            if parsed:
                templates.append(parsed)
        except Exception:
            errors += 1
    for path in root.rglob('*.yml'):
        try:
            content = path.read_text(encoding='utf-8')
            parsed = parse_nuclei_template(content)
            if parsed:
                templates.append(parsed)
        except Exception:
            errors += 1
    return {
        'imported': len(templates),
        'errors': errors,
        'templates': templates,
    }


def import_from_yaml_text(text: str) -> Dict:
    """Import a single template from a YAML text string."""
    if not HAS_YAML:
        return {'error': 'pyyaml not installed', 'imported': 0}
    parsed = parse_nuclei_template(text)
    if parsed:
        return {'imported': 1, 'template': parsed}
    return {'imported': 0, 'error': 'parse_failed'}
