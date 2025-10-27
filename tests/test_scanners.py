"""Tests for vulnerability scanners."""

import pytest
from unittest.mock import Mock, patch
from zodiac.core.request_handler import RequestHandler
from zodiac.scanners.xss_scanner import XSSScanner
from zodiac.scanners.sqli_scanner import SQLiScanner
from zodiac.scanners.lfi_scanner import LFIScanner
from zodiac.scanners.subdomain_scanner import SubdomainScanner


class TestXSSScanner:
    """Test suite for XSSScanner."""
    
    def test_init(self):
        """Test XSSScanner initialization."""
        handler = RequestHandler()
        scanner = XSSScanner(handler)
        
        assert scanner.request_handler is not None
        assert len(scanner.test_payloads) > 0
    
    @patch('zodiac.core.request_handler.requests.Session')
    def test_scan_no_vulnerability(self, mock_session_class):
        """Test scanning with no vulnerability."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>Safe content</body></html>"
        
        mock_session = Mock()
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session
        
        handler = RequestHandler(rate_limit_rps=10.0)
        handler.session = mock_session
        
        scanner = XSSScanner(handler)
        findings = scanner.scan("https://example.com", ["index.html"])
        
        assert isinstance(findings, list)


class TestSQLiScanner:
    """Test suite for SQLiScanner."""
    
    def test_init(self):
        """Test SQLiScanner initialization."""
        handler = RequestHandler()
        scanner = SQLiScanner(handler)
        
        assert scanner.request_handler is not None
        assert len(scanner.test_payloads) > 0
    
    @patch('zodiac.core.request_handler.requests.Session')
    def test_scan_with_error(self, mock_session_class):
        """Test scanning with SQL error."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Error: You have an error in your SQL syntax"
        
        mock_session = Mock()
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session
        
        handler = RequestHandler(rate_limit_rps=10.0)
        handler.session = mock_session
        
        scanner = SQLiScanner(handler)
        findings = scanner.scan("https://example.com", ["index.php"])
        
        assert isinstance(findings, list)


class TestLFIScanner:
    """Test suite for LFIScanner."""
    
    def test_init(self):
        """Test LFIScanner initialization."""
        handler = RequestHandler()
        scanner = LFIScanner(handler)
        
        assert scanner.request_handler is not None
    
    @patch('zodiac.core.request_handler.requests.Session')
    def test_scan(self, mock_session_class):
        """Test LFI scanning."""
        mock_response = Mock()
        mock_response.status_code = 404
        
        mock_session = Mock()
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session
        
        handler = RequestHandler(rate_limit_rps=10.0)
        handler.session = mock_session
        
        scanner = LFIScanner(handler)
        findings = scanner.scan("https://example.com", ["test.php"])
        
        assert isinstance(findings, list)


class TestSubdomainScanner:
    """Test suite for SubdomainScanner."""
    
    def test_init(self):
        """Test SubdomainScanner initialization."""
        handler = RequestHandler()
        scanner = SubdomainScanner(handler)
        
        assert scanner.request_handler is not None
        assert len(scanner.subdomains) > 0
    
    def test_extract_domain(self):
        """Test domain extraction."""
        handler = RequestHandler()
        scanner = SubdomainScanner(handler)
        
        assert scanner._extract_domain("https://example.com/path") == "example.com"
        assert scanner._extract_domain("example.com") == "example.com"
    
    @patch('dns.resolver.resolve')
    def test_scan_subdomain_exists(self, mock_dns_resolve):
        """Test scanning with existing subdomain."""
        handler = RequestHandler()
        scanner = SubdomainScanner(handler)
        
        findings = scanner.scan("https://example.com", ["www"])
        
        assert isinstance(findings, list)

