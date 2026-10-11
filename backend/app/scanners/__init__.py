from app.scanners.api_security import ApiSecurityScanner
from app.scanners.base import BaseScanner, ScanContext, SeverityTally
from app.scanners.headers import HeaderScanner
from app.scanners.ports import PortScanner
from app.scanners.sensitive_files import SensitiveFileScanner
from app.scanners.subdomains import SubdomainScanner
from app.scanners.tls import TlsScanner

SCANNER_REGISTRY: list[type[BaseScanner]] = [
    HeaderScanner,
    TlsScanner,
    ApiSecurityScanner,
    SensitiveFileScanner,
    PortScanner,
    SubdomainScanner,
]

__all__ = [
    "SCANNER_REGISTRY",
    "BaseScanner",
    "ScanContext",
    "SeverityTally",
]
