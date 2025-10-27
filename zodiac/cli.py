"""Command-line interface for Zodiac Vulnerability Scanner."""

import argparse
import sys
from typing import List
from colorama import init, Fore, Style
from tqdm import tqdm

from zodiac.core.request_handler import RequestHandler
from zodiac.core.report_manager import ReportManager, Finding
from zodiac.scanners.xss_scanner import XSSScanner
from zodiac.scanners.sqli_scanner import SQLiScanner
from zodiac.scanners.lfi_scanner import LFIScanner
from zodiac.scanners.subdomain_scanner import SubdomainScanner

# Initialize colorama
init(autoreset=True)


class ZodiacCLI:
    """Main CLI orchestrator for Zodiac Scanner."""
    
    def __init__(self):
        self.scanners = []
        self.report_manager = ReportManager()
    
    def print_banner(self):
        """Print the Zodiac banner."""
        banner = f"""{Fore.CYAN}
╔════════════════════════════════════════════════════╗
║                                                    ║
║         {Fore.YELLOW}♊  Z O D I A C  S C A N N E R  ♊{Fore.CYAN}        ║
║                                                    ║
║         {Style.DIM}Professional Web Security Testing{Style.RESET_ALL}{Fore.CYAN}    ║
║                                                    ║
╚════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
        print(banner)
    
    def print_info(self, message: str):
        """Print info message."""
        print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {message}")
    
    def print_success(self, message: str):
        """Print success message."""
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {message}")
    
    def print_error(self, message: str):
        """Print error message."""
        print(f"{Fore.RED}[-]{Style.RESET_ALL} {message}")
    
    def print_warning(self, message: str):
        """Print warning message."""
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {message}")
    
    def run_scan(
        self,
        target: str,
        scan_types: List[str],
        rate_limit: float,
        max_requests: int,
        dry_run: bool,
        output_dir: str,
    ):
        """Execute the vulnerability scan."""
        
        # Initialize request handler
        handler = RequestHandler(
            timeout=10,
            verify=True,
            max_retries=3,
            rate_limit_rps=rate_limit,
        )
        
        # Initialize scanners based on scan types
        if "xss" in scan_types or "all" in scan_types:
            self.scanners.append(("XSS", XSSScanner(handler)))
        
        if "sqli" in scan_types or "all" in scan_types:
            self.scanners.append(("SQLi", SQLiScanner(handler)))
        
        if "lfi" in scan_types or "all" in scan_types:
            self.scanners.append(("LFI", LFIScanner(handler)))
        
        if "subdomain" in scan_types or "all" in scan_types:
            self.scanners.append(("Subdomain", SubdomainScanner(handler)))
        
        if not self.scanners:
            self.print_error("No scanners selected!")
            return
        
        # Set metadata
        self.report_manager.set_meta({
            "target": target,
            "scan_type": ", ".join(scan_types),
            "classified": "Internal Use Only",
        })
        
        # Prepare scan paths
        default_paths = [
            "",  # Root
            "index.php",
            "index.html",
            "login.php",
            "admin.php",
            "test.php",
            "search.php",
            "api/users",
        ]
        
        all_findings = []
        
        # Run scans
        self.print_info(f"Starting scan on {target}")
        self.print_info(f"Rate limit: {rate_limit} requests/second")
        
        if dry_run:
            self.print_warning("DRY RUN MODE: No actual requests will be made")
        
        with tqdm(total=len(self.scanners), desc="Scanning", bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}') as pbar:
            for name, scanner in self.scanners:
                pbar.set_description(f"Running {name} scan")
                
                if dry_run:
                    self.print_info(f"[DRY RUN] Would run {name} scanner")
                    pbar.update(1)
                    continue
                
                try:
                    findings = scanner.scan(target, default_paths)
                    all_findings.extend(findings)
                    self.print_success(f"{name}: Found {len(findings)} findings")
                except Exception as e:
                    self.print_error(f"{name}: Error - {str(e)}")
                
                pbar.update(1)
        
        # Add findings to report
        for finding in all_findings:
            self.report_manager.add_finding(finding)
        
        # Save reports
        json_path = f"{output_dir}/report.json"
        html_path = f"{output_dir}/report.html"
        
        self.print_info(f"Saving JSON report to {json_path}")
        self.report_manager.save_json(json_path)
        
        self.print_info(f"Saving HTML report to {html_path}")
        self.report_manager.save_html(html_path, sanitize=True)
        
        # Print summary
        stats = self.report_manager.get_stats()
        self.print_success(f"\nScan completed! Total findings: {stats['total_findings']}")
        
        if stats['severity_breakdown']:
            print(f"\n{Fore.YELLOW}Severity Breakdown:{Style.RESET_ALL}")
            for severity, count in stats['severity_breakdown'].items():
                print(f"  {severity}: {count}")
        
        handler.close()


def main():
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(
        description="Zodiac Vulnerability Scanner - Professional Web Security Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run XSS scan on a target
  zodiac scan --target https://example.com --types xss
  
  # Run all scans with rate limiting
  zodiac scan --target https://example.com --types all --rate-limit 0.5
  
  # Dry run mode (no actual requests)
  zodiac scan --target https://example.com --dry-run
  
  # Custom output directory
  zodiac scan --target https://example.com --output ./results/

Warning: Only scan targets you own or have explicit permission to test.
        """
    )
    
    parser.add_argument(
        "--target",
        required=True,
        help="Target URL or domain to scan",
    )
    
    parser.add_argument(
        "--types",
        nargs="+",
        default=["all"],
        choices=["all", "xss", "sqli", "lfi", "subdomain"],
        help="Types of scans to run",
    )
    
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=1.0,
        help="Rate limit in requests per second (default: 1.0)",
    )
    
    parser.add_argument(
        "--max-requests",
        type=int,
        default=100,
        help="Maximum number of requests per scan (default: 100)",
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Dry run mode - don't make actual requests",
    )
    
    parser.add_argument(
        "--output",
        default="scan_results",
        help="Output directory for reports (default: scan_results)",
    )
    
    parser.add_argument(
        "--confirm-scope",
        type=str,
        help="Confirmation token for scan authorization",
    )
    
    args = parser.parse_args()
    
    # Print banner
    cli = ZodiacCLI()
    cli.print_banner()
    
    # Safety warnings
    cli.print_warning("IMPORTANT: Only scan targets you own or have explicit permission to test!")
    cli.print_warning("Unauthorized scanning is illegal and unethical.")
    
    if args.confirm_scope:
        cli.print_success(f"Authorization confirmed: {args.confirm_scope[:8]}...")
    else:
        cli.print_warning("Running without explicit authorization confirmation")
    
    # Create output directory
    import os
    os.makedirs(args.output, exist_ok=True)
    
    try:
        cli.run_scan(
            target=args.target,
            scan_types=args.types,
            rate_limit=args.rate_limit,
            max_requests=args.max_requests,
            dry_run=args.dry_run,
            output_dir=args.output,
        )
    except KeyboardInterrupt:
        cli.print_error("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        cli.print_error(f"Fatal error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()

