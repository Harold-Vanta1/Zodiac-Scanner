"""Subdomain enumeration scanner."""

from typing import List
import dns.resolver
import dns.exception
from zodiac.scanners.scanner_base import ScannerBase
from zodiac.core.request_handler import RequestHandler
from zodiac.core.report_manager import Finding


class SubdomainScanner(ScannerBase):
    """Scanner for subdomain enumeration."""
    
    def __init__(self, request_handler: RequestHandler):
        super().__init__(request_handler)
        # Common subdomain prefixes
        self.subdomains = [
            "www", "mail", "ftp", "admin", "test", "dev", "staging",
            "blog", "shop", "api", "secure", "vpn", "mobile", "m",
            "old", "new", "backup", "demo", "beta", "alpha",
        ]
    
    def scan(self, target: str, paths: List[str]) -> List[Finding]:
        """Enumerate subdomains for a domain."""
        findings = []
        
        # Extract domain from target
        domain = self._extract_domain(target)
        if not domain:
            return findings
        
        found_subdomains = []
        
        # Try DNS resolution for each subdomain
        for subdomain in self.subdomains:
            full_domain = f"{subdomain}.{domain}"
            
            try:
                dns.resolver.resolve(full_domain, 'A')
                found_subdomains.append(full_domain)
                
                findings.append(Finding(
                    id=self.generate_finding_id(),
                    type="SUBDOMAIN",
                    target=target,
                    path=full_domain,
                    severity="LOW",
                    confidence="HIGH",
                    evidence=f"Subdomain {full_domain} exists and resolves",
                    metadata={"subdomain": full_domain}
                ))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
                continue
        
        # If subdomains found, add summary finding
        if found_subdomains:
            findings.append(Finding(
                id=self.generate_finding_id(),
                type="SUBDOMAIN",
                target=target,
                path="summary",
                severity="INFO",
                confidence="HIGH",
                evidence=f"Found {len(found_subdomains)} subdomains: {', '.join(found_subdomains)}",
                metadata={"count": len(found_subdomains), "subdomains": found_subdomains}
            ))
        
        return findings
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        from urllib.parse import urlparse
        
        try:
            parsed = urlparse(url if '://' in url else f"http://{url}")
            domain = parsed.netloc or parsed.path.split('/')[0]
            # Remove port if present
            domain = domain.split(':')[0]
            return domain
        except Exception:
            return ""

