"""Base scanner interface for all vulnerability scanners."""

from abc import ABC, abstractmethod
from typing import List
from zodiac.core.request_handler import RequestHandler
from zodiac.core.report_manager import Finding
from uuid import uuid4


class ScannerBase(ABC):
    """Base class for all vulnerability scanners."""
    
    def __init__(self, request_handler: RequestHandler):
        self.request_handler = request_handler
        self.findings: List[Finding] = []
    
    @abstractmethod
    def scan(self, target: str, paths: List[str]) -> List[Finding]:
        """
        Perform the scan.
        
        Args:
            target: Target URL or domain
            paths: List of paths to scan
            
        Returns:
            List of findings
        """
        pass
    
    def generate_finding_id(self) -> str:
        """Generate a unique finding ID."""
        return str(uuid4())

