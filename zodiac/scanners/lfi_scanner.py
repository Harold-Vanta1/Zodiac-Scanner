"""Local File Inclusion (LFI) vulnerability scanner."""

from typing import List
from zodiac.scanners.scanner_base import ScannerBase
from zodiac.core.request_handler import RequestHandler
from zodiac.core.report_manager import Finding


class LFIScanner(ScannerBase):
    """Scanner for Local File Inclusion vulnerabilities."""
    
    def __init__(self, request_handler: RequestHandler):
        super().__init__(request_handler)
        # Common test payloads for LFI detection
        self.test_payloads = [
            "/etc/passwd",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "../../../../etc/passwd",
            "....//....//....//etc/passwd",
        ]
    
    def scan(self, target: str, paths: List[str]) -> List[Finding]:
        """Scan for LFI vulnerabilities."""
        findings = []
        
        for path in paths:
            # Check if path has file parameter
            if '=' in path:
                param = path.split('=')[0]
                url = f"{target.rstrip('/')}/{path}"
                
                # Test LFI payloads
                for payload in self.test_payloads[:2]:  # Limit payloads
                    test_url = url.replace(param.split('/')[-1], payload)
                    response = self.request_handler.get(test_url)
                    
                    if response and response.status_code == 200:
                        # Check for common file contents
                        content = response.text.lower()
                        file_indicators = [
                            "root:x:0:0:",
                            "[boot loader]",
                            "# /etc/hosts",
                            "local-host",
                        ]
                        
                        if any(indicator in content for indicator in file_indicators):
                            findings.append(Finding(
                                id=self.generate_finding_id(),
                                type="LFI",
                                target=target,
                                path=path,
                                parameter=param,
                                severity="HIGH",
                                confidence="HIGH",
                                evidence=f"File inclusion detected with system file indicators",
                                metadata={"payload_used": "sanitized"}
                            ))
                            break
        
        return findings

