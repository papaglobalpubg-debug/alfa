"""
Weaponized Web Vulnerability Scanner v6
Intelligent, context-aware, adaptive scanning engine.
"""
from .orchestrator import VulnScanner, VulnScanConfig
from .payloads import PAYLOADS

__all__ = ['VulnScanner', 'VulnScanConfig', 'PAYLOADS']
__version__ = '6.0.0'
