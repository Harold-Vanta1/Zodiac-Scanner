#!/usr/bin/env python3
"""
Basic usage example for Zodiac Scanner.

This example demonstrates how to use Zodiac programmatically.
"""

from zodiac import RequestHandler, ReportManager, Finding
from zodiac.scanners import XSSScanner, SQLiScanner, SubdomainScanner


def main():
    """Example of using Zodiac scanners programmatically."""
    
    print("♊ Zodiac Scanner - Programmatic Example\n")
    
    # Initialize components
    handler = RequestHandler(rate_limit_rps=1.0, timeout=10)
    report_manager = ReportManager()
    
    # Set metadata
    target = "https://example.com"
    report_manager.set_meta({
        "target": target,
        "classification": "Internal Use Only",
    })
    
    # Run scanners
    print(f"Scanning {target}...\n")
    
    # XSS Scan
    xss_scanner = XSSScanner(handler)
    xss_findings = xss_scanner.scan(target, ["index.html", "search.php"])
    print(f"✓ XSS Scanner found {len(xss_findings)} findings")
    
    # SQLi Scan
    sqli_scanner = SQLiScanner(handler)
    sqli_findings = sqli_scanner.scan(target, ["index.php", "login.php"])
    print(f"✓ SQLi Scanner found {len(sqli_findings)} findings")
    
    # Add findings to report
    for finding in xss_findings + sqli_findings:
        report_manager.add_finding(finding)
    
    # Save reports
    print("\nGenerating reports...")
    report_manager.save_json("example_report.json")
    report_manager.save_html("example_report.html")
    
    print("✓ Report saved to example_report.json")
    print("✓ Report saved to example_report.html")
    
    # Print statistics
    stats = report_manager.get_stats()
    print(f"\nTotal findings: {stats['total_findings']}")
    print("\nScan complete!")
    
    handler.close()


if __name__ == "__main__":
    main()

