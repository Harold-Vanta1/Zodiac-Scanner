"""XSS vulnerability scanner."""

from typing import List
from bs4 import BeautifulSoup
from zodiac.scanners.scanner_base import ScannerBase
from zodiac.core.request_handler import RequestHandler
from zodiac.core.report_manager import Finding


class XSSScanner(ScannerBase):
    """Scanner for Cross-Site Scripting (XSS) vulnerabilities."""
    
    def __init__(self, request_handler: RequestHandler):
        super().__init__(request_handler)
        # Using non-malicious test payloads for public repo
        self.test_payloads = [
            "ZODIAC_XSS_TEST",
            "test<script>alert(1)</script>",
            "test\"'><img src=x onerror=alert(1)>",
        ]
    
    def scan(self, target: str, paths: List[str]) -> List[Finding]:
        """Scan for XSS vulnerabilities in forms and parameters."""
        findings = []
        
        for path in paths:
            url = f"{target.rstrip('/')}/{path.lstrip('/')}"
            
            # Check if page has forms or input fields
            response = self.request_handler.get(url)
            if not response or response.status_code != 200:
                continue
            
            try:
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form')
                inputs = soup.find_all('input', {'type': ['text', 'search', 'email', 'password']})
                
                # Test each form with test payload
                for form in forms:
                    action = form.get('action', '')
                    form_url = url if not action or action.startswith('/') else action
                    
                    # Check GET forms
                    if form.get('method', 'get').lower() == 'get':
                        for payload in self.test_payloads:
                            params = {}
                            for inp in form.find_all('input'):
                                inp_name = inp.get('name')
                                if inp_name:
                                    params[inp_name] = payload
                            
                            test_response = self.request_handler.get(form_url, params=params)
                            if test_response and self._check_xss_present(test_response.text, payload):
                                findings.append(Finding(
                                    id=self.generate_finding_id(),
                                    type="XSS",
                                    target=target,
                                    path=path,
                                    parameter=str(list(params.keys())[0]) if params else None,
                                    severity="HIGH",
                                    confidence="MEDIUM",
                                    evidence=f"Potential reflected XSS in form parameters",
                                    metadata={"payload_used": "sanitized"}
                                ))
                                break
                    
                    # Check POST forms
                    else:
                        for payload in self.test_payloads[:1]:  # Use only first payload for POST
                            data = {}
                            for inp in form.find_all('input'):
                                inp_name = inp.get('name')
                                if inp_name:
                                    data[inp_name] = payload
                            
                            test_response = self.request_handler.post(form_url, data=data)
                            if test_response and self._check_xss_present(test_response.text, payload):
                                findings.append(Finding(
                                    id=self.generate_finding_id(),
                                    type="XSS",
                                    target=target,
                                    path=path,
                                    severity="HIGH",
                                    confidence="MEDIUM",
                                    evidence=f"Potential XSS vulnerability detected in POST data",
                                    metadata={"payload_used": "sanitized"}
                                ))
                                break
                
            except Exception as e:
                continue
        
        return findings
    
    def _check_xss_present(self, content: str, payload: str) -> bool:
        """Check if payload is reflected in response."""
        # Basic check - payload appears unencoded
        safe_payload = payload.replace('<script>', '').replace('</script>', '')
        return safe_payload in content or "ZODIAC_XSS_TEST" in content

