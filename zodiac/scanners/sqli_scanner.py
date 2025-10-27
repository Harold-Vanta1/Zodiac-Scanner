"""SQL injection vulnerability scanner."""

from typing import List
from zodiac.scanners.scanner_base import ScannerBase
from zodiac.core.request_handler import RequestHandler
from zodiac.core.report_manager import Finding


class SQLiScanner(ScannerBase):
    """Scanner for SQL injection vulnerabilities."""
    
    def __init__(self, request_handler: RequestHandler):
        super().__init__(request_handler)
        # Basic test payloads for error-based detection
        self.test_payloads = [
            "'",
            "1' OR '1'='1",
            "1' OR 1=1--",
            "1' OR '1'='1'--",
            "' UNION SELECT NULL--",
        ]
    
    def scan(self, target: str, paths: List[str]) -> List[Finding]:
        """Scan for SQL injection vulnerabilities."""
        findings = []
        
        for path in paths:
            url = f"{target.rstrip('/')}/{path.lstrip('/')}"
            
            # Try each test payload
            for payload in self.test_payloads[:3]:  # Limit to first 3 for safety
                response = self.request_handler.get(f"{url}?id={payload}")
                
                if response and response.status_code == 200:
                    # Check for common SQL error messages
                    content_lower = response.text.lower()
                    sql_errors = [
                        "sql syntax",
                        "mysql",
                        "warning: mysql",
                        "postgresql",
                        "ora-",
                        "microsoft ole db",
                        "sqlite",
                        "sql server",
                        "mysql_fetch",
                    ]
                    
                    if any(error in content_lower for error in sql_errors):
                        findings.append(Finding(
                            id=self.generate_finding_id(),
                            type="SQLi",
                            target=target,
                            path=path,
                            parameter="id",
                            severity="CRITICAL",
                            confidence="HIGH",
                            evidence="SQL error message detected in response",
                            metadata={"payload_used": "sanitized"}
                        ))
                        break
        
        return findings

