#!/usr/bin/env python3
"""
cyberscope — command-line interface for the CyberScope vulnerability scanner.

Usage examples:
  cyberscope scan example.com --depth medium --json report.json
  cyberscope scan https://staging.foo.com --modules xss,sqli,api_security
  cyberscope scan target.com --depth deep --output pretty
  cyberscope list-modules
  cyberscope version

It runs the exact same orchestrator that the web app uses, so results match 1:1.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


# Add project root to path so we can import `scanner` regardless of where the
# user launches the CLI from (tarball layout: root/scanner, root/cli.py).
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parent))

try:
    from scanner.vuln import VulnScanner, VulnScanConfig, PAYLOADS
except ImportError:
    print('[!] Cannot import scanner. Run this from the CyberScope tarball root.', file=sys.stderr)
    raise


ANSI = {
    'reset': '\033[0m', 'bold': '\033[1m',
    'red': '\033[91m', 'green': '\033[92m', 'yellow': '\033[93m',
    'blue': '\033[94m', 'magenta': '\033[95m', 'cyan': '\033[96m',
    'gray': '\033[90m',
}


def c(txt: str, color: str) -> str:
    if not sys.stdout.isatty():
        return txt
    return f'{ANSI.get(color, "")}{txt}{ANSI["reset"]}'


def payload_total() -> int:
    """Sum of all payload lists exposed by scanner.vuln.PAYLOADS."""
    total = 0
    for attr in dir(PAYLOADS):
        if attr.startswith('_'):
            continue
        val = getattr(PAYLOADS, attr, None)
        if isinstance(val, (list, tuple, set)):
            total += len(val)
    return total


def banner():
    print(c('  ╔══════════════════════════════════════════════════════════╗', 'red'))
    print(c('  ║  ', 'red') + c('CyberScope v7.5', 'bold') + c(' · Weaponized Web Auditor           ║', 'red'))
    print(c('  ║  ', 'red') + c(f'{payload_total():>4} payloads · 35 modules · CLI mode         ', 'gray') + c('║', 'red'))
    print(c('  ╚══════════════════════════════════════════════════════════╝', 'red'))
    print()


def sev_color(sev: str) -> str:
    return {
        'critical': 'red', 'high': 'red',
        'medium': 'yellow', 'low': 'blue',
        'info': 'gray',
    }.get(sev, 'gray')


def print_pretty(result: dict) -> None:
    """Human-friendly TTY output."""
    findings = result.get('findings', [])
    summary = result.get('summary', {})
    print(c(f'\n[+] Scan target: {result.get("target")}', 'green'))
    print(c(f'[+] Duration:    {result.get("duration_seconds", 0):.1f}s', 'green'))
    print(c(f'[+] Total:       {summary.get("total", 0)} findings', 'green'))
    for sev in ('critical', 'high', 'medium', 'low', 'info'):
        n = summary.get(sev, 0)
        if n:
            label = sev.upper().rjust(8)
            print(f'  {c("•", sev_color(sev))} {c(label, sev_color(sev))}: {n}')

    if not findings:
        print(c('\n  No vulnerabilities detected on that surface.', 'gray'))
        return

    print(c('\n' + '-' * 60, 'gray'))
    for i, f in enumerate(findings[:100], 1):
        sev = f.get('severity', 'info')
        print(f'\n{c(f"[{i}]", "bold")} {c(sev.upper(), sev_color(sev))} · '
              f'{c(f.get("type", "?"), "cyan")}'
              f'{" · " + f["subtype"] if f.get("subtype") else ""}')
        print(f'    {c("url:", "gray")}     {f.get("url", "")}')
        if f.get('parameter'):
            print(f'    {c("param:", "gray")}   {f["parameter"]}')
        if f.get('evidence'):
            ev = str(f["evidence"])[:180].replace('\n', ' ')
            print(f'    {c("evidence:", "gray")}{ev}')
        if f.get('description'):
            print(f'    {c("desc:", "gray")}    {f["description"][:200]}')
    if len(findings) > 100:
        print(c(f'\n  … {len(findings) - 100} more findings truncated. Use --json to see all.', 'gray'))


async def cmd_scan(args) -> int:
    banner()
    modules = None
    if args.modules:
        modules = set(args.modules.split(','))
    cfg = VulnScanConfig(
        target=args.target,
        depth=args.depth,
        concurrency=args.concurrency,
        timeout=args.timeout,
        enabled_modules=modules or set(),
        log_cb=(lambda m: print(c(m, 'gray'))) if args.verbose else None,
    )
    # If user passed --modules, respect exactly that set; else use defaults.
    if modules:
        cfg.enabled_modules = modules
    else:
        # cfg default already correct
        pass
    print(c(f'[*] Target:       {args.target}', 'cyan'))
    print(c(f'[*] Depth:        {args.depth}', 'cyan'))
    print(c(f'[*] Modules:      {len(cfg.enabled_modules)} enabled', 'cyan'))
    print(c(f'[*] Concurrency:  {args.concurrency}', 'cyan'))
    print()

    scanner = VulnScanner(cfg)
    try:
        result = await scanner.run()
    except KeyboardInterrupt:
        print(c('\n[!] Cancelled by user (Ctrl-C).', 'yellow'))
        scanner.request_cancel()
        return 130

    result['scanned_at'] = datetime.now(timezone.utc).isoformat()

    # Output
    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=2, default=str))
        print(c(f'\n[+] Wrote JSON report → {args.json}', 'green'))
        if args.output == 'pretty':
            print_pretty(result)
    elif args.output == 'pretty':
        print_pretty(result)
    else:
        print(json.dumps(result, indent=2, default=str))
    return 0


def cmd_list_modules(args) -> int:
    banner()
    all_mods = [
        ('fingerprint', 'Tech/WAF fingerprint'),
        ('recon', 'Wayback + OTX + JS mining'),
        ('crawler', 'Deep BFS crawl + sitemap + robots'),
        ('xss', 'Reflected + stored XSS'),
        ('sqli', 'Error / blind / time-based SQLi'),
        ('nosqli', 'NoSQL injection'),
        ('cmd', 'Command injection'),
        ('ssti', 'SSTI (Jinja2/Twig/Freemarker/Velocity)'),
        ('lfi', 'LFI / path traversal'),
        ('xxe', 'XML external entity'),
        ('ssrf', 'Server-side request forgery + cloud meta'),
        ('open_redirect', 'Open redirect (canonicalized)'),
        ('cors', 'CORS misconfig'),
        ('crlf', 'CRLF header injection'),
        ('smuggling', 'HTTP request smuggling'),
        ('cache_poisoning', 'Cache poisoning'),
        ('prototype_pollution', 'Prototype pollution'),
        ('graphql', 'GraphQL introspection + batching'),
        ('deserialization', 'PHP/Java/.NET deserialization'),
        ('cloud_buckets', 'S3/GCS/Azure bucket enum'),
        ('infra_apis', 'K8s / Docker / etcd / Consul APIs'),
        ('cve_templates', 'Bundled CVE templates'),
        ('secrets', 'Secrets discovery'),
        ('port_scan', 'Port scanner (deep only)'),
        ('host_header', 'Host-header injection'),
        ('web_cache_deception', 'Web cache deception'),
        ('client_proto', 'Client-side prototype pollution'),
        ('csp', 'CSP audit'),
        ('directory_listing', 'Directory listing'),
        ('http_methods', 'Dangerous verbs (PUT/DELETE/TRACE)'),
        ('sri', 'Subresource Integrity audit'),
        ('api_security', 'REST + GraphQL API hardening'),
        ('oauth_saml', 'OAuth2/OIDC/SAML attack surface'),
        ('mobile_backend', 'Firebase / mobile backend leaks'),
        ('web3', 'Web3 / dApp frontend leaks'),
    ]
    print(c(f'  {len(all_mods)} modules available:\n', 'bold'))
    for k, desc in all_mods:
        key = k.ljust(22)
        print(f'  {c(key, "cyan")} {desc}')
    return 0


def cmd_version(args) -> int:
    print(f'cyberscope 7.5.0 ({payload_total()} payloads)')
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog='cyberscope',
        description='CyberScope — weaponized web vulnerability scanner (CLI)',
    )
    sub = parser.add_subparsers(dest='cmd', required=True)

    p_scan = sub.add_parser('scan', help='Run a vulnerability scan against a target')
    p_scan.add_argument('target', help='URL or domain, e.g. https://example.com')
    p_scan.add_argument('--depth', choices=['shallow', 'medium', 'deep'], default='medium')
    p_scan.add_argument('--concurrency', type=int, default=30)
    p_scan.add_argument('--timeout', type=int, default=12)
    p_scan.add_argument('--modules', help='Comma-separated module list (default: all)')
    p_scan.add_argument('--json', help='Write full JSON result to this file')
    p_scan.add_argument('--output', choices=['pretty', 'json'], default='pretty')
    p_scan.add_argument('-v', '--verbose', action='store_true')
    p_scan.set_defaults(func=lambda args: asyncio.run(cmd_scan(args)))

    p_list = sub.add_parser('list-modules', help='List available scan modules')
    p_list.set_defaults(func=cmd_list_modules)

    p_ver = sub.add_parser('version', help='Print version')
    p_ver.set_defaults(func=cmd_version)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == '__main__':
    main()
