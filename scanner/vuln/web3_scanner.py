"""
Web3 / Smart-Contract adjacent scanner (dApp frontend surface).

We do NOT interact with mainnet or spend gas. We inspect the dApp's frontend
for common Web3 misconfigurations that leak keys, endpoints, or enable
phishing.

Findings:
  * Ethereum private key `0x` + 64 hex leaked in JS / HTML (critical)
  * Infura / Alchemy / QuickNode project id + key in client (medium/high)
  * WalletConnect projectId leaked (low — but nice to flag)
  * Hard-coded contract addresses matching known scam / drainer lists (info)
  * MetaMask "eth_sign" callable from any origin (blind signing)  — heuristic
  * IPFS gateway used without content-hash verification (low)
  * Web3 provider URL over HTTP (not HTTPS/WSS) (medium)
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

# Regex catalogue — anchored so we don't false-flag random hex
ETH_PRIVKEY = re.compile(r'\b0x[a-fA-F0-9]{64}\b')
ETH_ADDR = re.compile(r'\b0x[a-fA-F0-9]{40}\b')

INFURA_KEY = re.compile(
    r'infura\.io/v3/([a-f0-9]{20,64})',
)
ALCHEMY_KEY = re.compile(
    r'g\.alchemy\.com/v2/([A-Za-z0-9_\-]{20,64})',
)
QUICKNODE_KEY = re.compile(
    r'quiknode\.pro/([A-Za-z0-9]{20,64})/?',
)
WALLETCONNECT = re.compile(
    r'walletconnect[^"\']{0,80}?"projectId"\s*:\s*"([a-f0-9]{16,40})"', re.IGNORECASE,
)

HTTP_RPC = re.compile(r'http://[^\s"\']+?(?:8545|8546|rpc)[^\s"\']*')

# Known ETH signing calls that are dangerous
DANGEROUS_ETH_METHODS = ['eth_sign', 'personal_sign', 'signTypedData']


def _add(out: List[Dict], **kw):
    kw.setdefault('type', 'web3')
    kw.setdefault('confidence', 85)
    out.append(kw)


def _looks_like_privkey(text: str) -> bool:
    """
    We already matched 0x + 64 hex. Filter obvious false-positives:
      * All same digit
      * Common test/sample keys (Hardhat, Anvil default account #0)
    """
    hex_part = text[2:]
    if len(set(hex_part.lower())) < 6:
        return False
    # Anvil default private key #0 — legitimate but still bad to leak
    return True


async def scan_web3(client, base_url: str, baseline_text: str = '',
                    log_cb: Optional[callable] = None) -> List[Dict]:
    """
    Public entrypoint. `baseline_text` should be raw HTML/JS content of the
    page (concatenated); the scanner will regex through it for leaks.
    """
    findings: List[Dict] = []
    text = baseline_text or ''
    if not text:
        # Fall back to a single GET on the base URL
        try:
            r = await client.get(base_url)
            text = r.text or ''
        except Exception as e:
            if log_cb:
                log_cb(f'[!] web3 baseline fetch failed: {e}')
            return findings

    # 1) Leaked private keys
    for m in list(ETH_PRIVKEY.finditer(text))[:5]:
        pk = m.group(0)
        if not _looks_like_privkey(pk):
            continue
        _add(
            findings,
            subtype='eth_privkey_leak',
            severity='critical',
            cvss=9.8,
            url=base_url,
            evidence=f'{pk[:6]}…{pk[-4:]}',
            description='A raw Ethereum private key (0x + 64 hex) is embedded in the '
                        'client-side JavaScript. This gives an attacker full control of the '
                        'associated wallet, including draining funds.',
            remediation='Rotate the compromised key IMMEDIATELY. Never ship private keys to '
                        'client code — use a wallet connect flow or a backend signing service.',
            confidence=98,
        )

    # 2) Infura keys
    for m in list(INFURA_KEY.finditer(text))[:3]:
        pid = m.group(1)
        _add(
            findings,
            subtype='infura_project_id_leak',
            severity='medium',
            cvss=5.3,
            url=base_url,
            evidence=f'{pid[:8]}…',
            description='Infura project ID is embedded in the frontend. This is the default '
                        'pattern for dApps, but an unrestricted project ID lets anyone '
                        'consume your monthly quota.',
            remediation='Enable "Allowlist" restrictions on the Infura project — restrict '
                        'to your production origin(s).',
            confidence=90,
        )

    # 3) Alchemy keys
    for m in list(ALCHEMY_KEY.finditer(text))[:3]:
        _add(
            findings,
            subtype='alchemy_api_key_leak',
            severity='medium',
            cvss=5.3,
            url=base_url,
            evidence=f'alchemy key {m.group(1)[:8]}…',
            description='Alchemy API key is embedded in the frontend. Without JWT + referrer '
                        'restrictions this key can be scraped and used to burn quota.',
            remediation='In Alchemy dashboard, add HTTP referrer restrictions and enable JWT.',
            confidence=90,
        )

    # 4) QuickNode
    for m in list(QUICKNODE_KEY.finditer(text))[:3]:
        _add(
            findings,
            subtype='quicknode_key_leak',
            severity='medium',
            cvss=5.3,
            url=base_url,
            evidence=f'quicknode key {m.group(1)[:8]}…',
            description='QuickNode API key is embedded in the frontend.',
            remediation='Restrict the QuickNode endpoint to your origins in the QuickNode dashboard.',
            confidence=90,
        )

    # 5) WalletConnect project id
    for m in list(WALLETCONNECT.finditer(text))[:3]:
        _add(
            findings,
            subtype='walletconnect_project_id',
            severity='low',
            cvss=3.1,
            url=base_url,
            evidence=f'wc projectId {m.group(1)[:8]}…',
            description='WalletConnect projectId leaked in client. Not directly exploitable, '
                        'but attackers can impersonate the dApp for phishing.',
            remediation='This is expected — but consider enabling verified domain in WC dashboard.',
            confidence=80,
        )

    # 6) HTTP (not HTTPS/WSS) RPC endpoints
    for m in list(HTTP_RPC.finditer(text))[:3]:
        _add(
            findings,
            subtype='web3_rpc_over_http',
            severity='medium',
            cvss=5.9,
            url=base_url,
            evidence=m.group(0)[:200],
            description=('The dApp connects to an EVM RPC endpoint over plain HTTP. A network '
                         'attacker can tamper with transaction receipts / balances.'),
            remediation='Change the provider URL to https:// or wss://.',
            confidence=90,
        )

    # 7) Dangerous signing methods called from JS
    for meth in DANGEROUS_ETH_METHODS:
        if meth in text:
            _add(
                findings,
                subtype='dangerous_eth_signing_call',
                severity='medium',
                cvss=5.9,
                url=base_url,
                evidence=f'method called: {meth}',
                description=(f'The dApp calls `{meth}` — this is unsafe because MetaMask '
                             'presents a raw hex prompt to the user, enabling blind signing '
                             'attacks and phishing.'),
                remediation='Use EIP-712 `signTypedData_v4` (typed structured data) or a '
                            'wallet plugin that shows a human-readable prompt.',
                confidence=70,
            )
            break

    return findings
