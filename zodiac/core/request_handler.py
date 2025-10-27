"""Professional HTTP request handler with rate limiting, retries, and safety controls."""

import time
import random
from typing import Optional, Dict
from collections import defaultdict
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class RequestHandler:
    """
    Robust HTTP request handler with safety features:
    - Rate limiting (token bucket algorithm)
    - Exponential backoff with jitter
    - Connection pooling
    - Circuit breaker for error handling
    """

    def __init__(
        self,
        timeout: int = 10,
        verify: bool = True,
        max_retries: int = 3,
        rate_limit_rps: float = 1.0,
        proxy: Optional[str] = None,
        user_agent: str = None,
    ):
        self.timeout = timeout
        self.verify = verify
        self.max_retries = max_retries
        self.rate_limit_rps = rate_limit_rps
        self.proxy = proxy
        self.user_agent = user_agent or (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        
        # Token bucket for rate limiting
        self.token_buckets = defaultdict(lambda: {"tokens": rate_limit_rps, "last_update": time.time()})
        
        # Circuit breaker state
        self.circuit_breakers = defaultdict(lambda: {"failures": 0, "last_failure": None, "opened_at": None})
        
        # Create session with retry strategy
        self.session = requests.Session()
        
        # Configure retries with exponential backoff
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set default headers
        self.session.headers.update({"User-Agent": self.user_agent})
        
        if proxy:
            self.session.proxies = {
                "http": proxy,
                "https": proxy,
            }

    def _wait_for_token(self, url: str):
        """Token bucket rate limiting implementation."""
        domain = self._extract_domain(url)
        bucket = self.token_buckets[domain]
        current_time = time.time()
        
        # Refill tokens based on elapsed time
        elapsed = current_time - bucket["last_update"]
        bucket["tokens"] = min(
            self.rate_limit_rps,
            bucket["tokens"] + elapsed * self.rate_limit_rps
        )
        bucket["last_update"] = current_time
        
        # Wait if we don't have enough tokens
        if bucket["tokens"] < 1.0:
            wait_time = (1.0 - bucket["tokens"]) / self.rate_limit_rps
            time.sleep(wait_time)
            bucket["tokens"] = 0
        else:
            bucket["tokens"] -= 1.0

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL for rate limiting."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc
        except Exception:
            return "default"

    def _is_circuit_open(self, url: str) -> bool:
        """Check if circuit breaker is open for this target."""
        domain = self._extract_domain(url)
        circuit = self.circuit_breakers[domain]
        
        if circuit["opened_at"] is None:
            return False
        
        # Auto-reset after 60 seconds
        if time.time() - circuit["opened_at"] > 60:
            circuit["opened_at"] = None
            circuit["failures"] = 0
            return False
        
        return True

    def _record_failure(self, url: str):
        """Record a failure for circuit breaker."""
        domain = self._extract_domain(url)
        circuit = self.circuit_breakers[domain]
        
        circuit["failures"] += 1
        circuit["last_failure"] = time.time()
        
        # Open circuit after 5 consecutive failures
        if circuit["failures"] >= 5:
            circuit["opened_at"] = time.time()

    def _record_success(self, url: str):
        """Reset circuit breaker on success."""
        domain = self._extract_domain(url)
        circuit = self.circuit_breakers[domain]
        circuit["failures"] = 0

    def get(self, url: str, params: Dict = None, headers: Dict = None) -> Optional[requests.Response]:
        """
        Perform a GET request with rate limiting and error handling.
        
        Args:
            url: Target URL
            params: Query parameters
            headers: Additional headers
            
        Returns:
            Response object or None if request failed
        """
        try:
            # Check circuit breaker
            if self._is_circuit_open(url):
                return None
            
            # Rate limiting
            self._wait_for_token(url)
            
            # Prepare headers
            request_headers = self.session.headers.copy()
            if headers:
                request_headers.update(headers)
            
            # Perform request
            response = self.session.get(
                url,
                params=params,
                headers=request_headers,
                timeout=self.timeout,
                verify=self.verify,
                allow_redirects=True,
            )
            
            self._record_success(url)
            return response
            
        except requests.exceptions.RequestException as e:
            self._record_failure(url)
            return None

    def post(self, url: str, data: Dict = None, json: Dict = None, headers: Dict = None) -> Optional[requests.Response]:
        """
        Perform a POST request with rate limiting and error handling.
        
        Args:
            url: Target URL
            data: Form data
            json: JSON data
            headers: Additional headers
            
        Returns:
            Response object or None if request failed
        """
        try:
            # Check circuit breaker
            if self._is_circuit_open(url):
                return None
            
            # Rate limiting
            self._wait_for_token(url)
            
            # Prepare headers
            request_headers = self.session.headers.copy()
            if headers:
                request_headers.update(headers)
            
            # Perform request
            response = self.session.post(
                url,
                data=data,
                json=json,
                headers=request_headers,
                timeout=self.timeout,
                verify=self.verify,
                allow_redirects=True,
            )
            
            self._record_success(url)
            return response
            
        except requests.exceptions.RequestException as e:
            self._record_failure(url)
            return None

    def close(self):
        """Close the session."""
        self.session.close()

