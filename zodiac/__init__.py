"""Zodiac Vulnerability Scanner - A professional web security testing tool."""

__version__ = "1.0.0"
__author__ = "Zodiac Scanner Team"

from zodiac.core.request_handler import RequestHandler
from zodiac.core.report_manager import ReportManager, Finding
from zodiac.scanners.scanner_base import ScannerBase

__all__ = [
    "RequestHandler",
    "ReportManager",
    "Finding",
    "ScannerBase",
]

