"""Tests for RequestHandler."""

import pytest
import requests
from unittest.mock import Mock, patch
from zodiac.core.request_handler import RequestHandler


class TestRequestHandler:
    """Test suite for RequestHandler."""
    
    def test_init(self):
        """Test RequestHandler initialization."""
        handler = RequestHandler(
            timeout=10,
            verify=True,
            max_retries=3,
            rate_limit_rps=1.0,
        )
        
        assert handler.timeout == 10
        assert handler.verify is True
        assert handler.max_retries == 3
        assert handler.rate_limit_rps == 1.0
    
    def test_extract_domain(self):
        """Test domain extraction from URL."""
        handler = RequestHandler()
        
        assert handler._extract_domain("https://example.com/path") == "example.com"
        assert handler._extract_domain("http://test.com:8080") == "test.com"
        assert handler._extract_domain("example.com") == "example.com"
    
    @patch('zodiac.core.request_handler.requests.Session')
    def test_get_success(self, mock_session_class):
        """Test successful GET request."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session
        
        handler = RequestHandler(rate_limit_rps=10.0)  # High rate limit for tests
        handler.session = mock_session
        
        response = handler.get("https://example.com")
        
        assert response is not None
        assert response.status_code == 200
        mock_session.get.assert_called_once()
    
    @patch('zodiac.core.request_handler.requests.Session')
    def test_get_failure(self, mock_session_class):
        """Test failed GET request."""
        mock_session = Mock()
        mock_session.get.side_effect = requests.exceptions.RequestException()
        mock_session_class.return_value = mock_session
        
        handler = RequestHandler(rate_limit_rps=10.0)
        handler.session = mock_session
        
        response = handler.get("https://example.com")
        
        assert response is None
    
    @patch('zodiac.core.request_handler.requests.Session')
    def test_post_success(self, mock_session_class):
        """Test successful POST request."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response
        mock_session_class.return_value = mock_session
        
        handler = RequestHandler(rate_limit_rps=10.0)
        handler.session = mock_session
        
        response = handler.post("https://example.com", data={"key": "value"})
        
        assert response is not None
        assert response.status_code == 200
        mock_session.post.assert_called_once()
    
    def test_circuit_breaker(self):
        """Test circuit breaker functionality."""
        handler = RequestHandler(rate_limit_rps=10.0)
        
        # Record 5 failures to open circuit
        for _ in range(5):
            handler._record_failure("https://example.com")
        
        # Circuit should be open
        assert handler._is_circuit_open("https://example.com") is True
        
        # Circuit should reset after success
        handler._record_success("https://example.com")
        assert handler._is_circuit_open("https://example.com") is False
    
    def test_close(self):
        """Test session closing."""
        handler = RequestHandler()
        handler.close()  # Should not raise exception

