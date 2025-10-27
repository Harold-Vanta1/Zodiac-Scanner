"""Tests for ReportManager."""

import pytest
import json
import os
from zodiac.core.report_manager import ReportManager, Finding
from datetime import datetime


class TestReportManager:
    """Test suite for ReportManager."""
    
    def test_init(self):
        """Test ReportManager initialization."""
        manager = ReportManager()
        
        assert len(manager.findings) == 0
        assert manager.metadata is not None
    
    def test_add_finding(self):
        """Test adding findings."""
        manager = ReportManager()
        
        finding = Finding(
            id="test-123",
            type="XSS",
            target="https://example.com",
            path="/test",
            severity="HIGH",
            confidence="MEDIUM",
        )
        
        manager.add_finding(finding)
        
        assert len(manager.findings) == 1
        assert manager.findings[0].type == "XSS"
    
    def test_get_stats(self):
        """Test statistics generation."""
        manager = ReportManager()
        
        # Add multiple findings
        manager.add_finding(Finding(
            id="1", type="XSS", target="https://example.com", path="/",
            severity="HIGH", confidence="HIGH"
        ))
        manager.add_finding(Finding(
            id="2", type="SQLi", target="https://example.com", path="/",
            severity="CRITICAL", confidence="HIGH"
        ))
        
        stats = manager.get_stats()
        
        assert stats["total_findings"] == 2
        assert "XSS" in stats["type_breakdown"]
        assert stats["severity_breakdown"]["HIGH"] == 1
        assert stats["severity_breakdown"]["CRITICAL"] == 1
    
    def test_save_json(self, tmp_path):
        """Test JSON report generation."""
        manager = ReportManager()
        manager.set_meta({"target": "https://example.com"})
        
        finding = Finding(
            id="test-123",
            type="XSS",
            target="https://example.com",
            path="/test",
            severity="HIGH",
        )
        manager.add_finding(finding)
        
        json_path = tmp_path / "report.json"
        manager.save_json(str(json_path))
        
        assert json_path.exists()
        
        with open(json_path, "r") as f:
            data = json.load(f)
        
        assert "metadata" in data
        assert "findings" in data
        assert len(data["findings"]) == 1
    
    def test_save_html(self, tmp_path):
        """Test HTML report generation."""
        manager = ReportManager()
        manager.set_meta({"target": "https://example.com"})
        
        finding = Finding(
            id="test-123",
            type="XSS",
            target="https://example.com",
            path="/test",
            severity="HIGH",
        )
        manager.add_finding(finding)
        
        html_path = tmp_path / "report.html"
        manager.save_html(str(html_path))
        
        assert html_path.exists()
        
        with open(html_path, "r") as f:
            content = f.read()
        
        assert "<html" in content
        assert "Zodiac" in content
    
    def test_set_meta(self):
        """Test metadata setting."""
        manager = ReportManager()
        
        manager.set_meta({"custom_key": "custom_value"})
        
        assert manager.metadata["custom_key"] == "custom_value"


class TestFinding:
    """Test suite for Finding model."""
    
    def test_finding_creation(self):
        """Test Finding creation."""
        finding = Finding(
            id="test-123",
            type="XSS",
            target="https://example.com",
            path="/test",
        )
        
        assert finding.id == "test-123"
        assert finding.type == "XSS"
        assert finding.timestamp is not None
        assert finding.metadata is not None
    
    def test_finding_defaults(self):
        """Test Finding default values."""
        finding = Finding(
            id="test-123",
            type="XSS",
            target="https://example.com",
            path="/test",
        )
        
        assert finding.severity == "MEDIUM"
        assert finding.confidence == "MEDIUM"

