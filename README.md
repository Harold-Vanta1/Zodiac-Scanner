# ♊ Zodiac Vulnerability Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

> A professional, modular web vulnerability scanner with rate limiting, beautiful reporting, and safety controls.

## 🎯 Overview

Zodiac is a production-ready vulnerability scanner designed for security professionals and developers who need to test their own web applications. It features:

- **Modular Scanner Architecture** - Easy to extend with custom scanners
- **Rate Limiting & Safety Controls** - Prevents accidental DoS attacks
- **Beautiful HTML Reports** - Professional, searchable vulnerability reports
- **Multiple Scanner Types** - XSS, SQLi, LFI, and Subdomain enumeration
- **Circuit Breaker Pattern** - Automatic failure handling for unstable targets
- **Dry-Run Mode** - Test your setup without making actual requests

## ⚠️ Legal & Ethical Notice

**IMPORTANT**: This tool is for authorized security testing only. Only scan:
- Websites and applications you own
- Systems you have explicit written permission to test
- Your own local/staging environments

Unauthorized scanning is illegal and unethical. The authors assume no liability for misuse of this software.

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/zodiac-scanner.git
cd zodiac-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

### Basic Usage

```bash
# Run a quick XSS scan
zodiac scan --target https://example.com --types xss

# Run all scanners
zodiac scan --target https://example.com --types all

# Use rate limiting to be gentle on the server
zodiac scan --target https://example.com --types all --rate-limit 0.5

# Dry run mode (no actual requests)
zodiac scan --target https://example.com --dry-run

# Custom output directory
zodiac scan --target https://example.com --output ./my_reports/
```

## 📊 Features

### Available Scanners

- **XSS Scanner** - Detects Cross-Site Scripting vulnerabilities in forms and parameters
- **SQLi Scanner** - Identifies SQL injection vulnerabilities using error-based detection
- **LFI Scanner** - Finds Local File Inclusion vulnerabilities
- **Subdomain Scanner** - Enumerates subdomains via DNS resolution

### Safety Features

- ✅ Rate limiting with token bucket algorithm
- ✅ Circuit breaker for failing targets
- ✅ Exponential backoff with jitter
- ✅ Connection timeouts
- ✅ Request retry logic
- ✅ Dry-run mode

### Reporting

The scanner generates two types of reports:

**JSON Report** (`report.json`) - Machine-readable format for automation
```json
{
  "metadata": { ... },
  "statistics": {
    "total_findings": 5,
    "severity_breakdown": { ... }
  },
  "findings": [ ... ]
}
```

**HTML Report** (`report.html`) - Beautiful, searchable web report with:
- Interactive statistics
- Color-coded severity levels
- Detailed vulnerability information
- Professional styling

## 📖 Detailed Usage

### Command-Line Options

```bash
zodiac scan --help
```

```
Options:
  --target URL          Target URL or domain to scan (required)
  --types [LIST]        Types of scans to run (default: all)
                        Options: all, xss, sqli, lfi, subdomain
  --rate-limit FLOAT    Rate limit in requests/second (default: 1.0)
  --max-requests INT    Maximum requests per scan (default: 100)
  --dry-run             Dry run mode - no actual requests
  --output DIR          Output directory (default: scan_results)
  --confirm-scope TOKEN Authorization token for scan
```

### Examples

#### Scan a Single Application

```bash
zodiac scan \
  --target https://myapp.com \
  --types xss sqli \
  --rate-limit 0.5 \
  --output ./reports/
```

#### Authorized Penetration Test

```bash
zodiac scan \
  --target https://client.com \
  --types all \
  --confirm-scope "auth-token-12345" \
  --rate-limit 0.3
```

#### Development Testing

```bash
# Test against local instance
zodiac scan \
  --target http://localhost:8000 \
  --types xss \
  --dry-run  # Test without making requests first
```

## 🏗️ Architecture

```
zodiac-scanner/
├── zodiac/
│   ├── __init__.py
│   ├── cli.py                  # CLI interface
│   ├── core/
│   │   ├── request_handler.py  # HTTP handler with rate limiting
│   │   └── report_manager.py   # Report generation
│   └── scanners/
│       ├── scanner_base.py     # Base scanner interface
│       ├── xss_scanner.py      # XSS detection
│       ├── sqli_scanner.py     # SQL injection detection
│       ├── lfi_scanner.py      # LFI detection
│       └── subdomain_scanner.py # Subdomain enumeration
├── tests/                      # Unit tests
├── README.md                   # This file
├── requirements.txt            # Dependencies
└── setup.py                    # Package setup
```

## 🧪 Testing

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run all tests
pytest

# Run with coverage
pytest --cov=zodiac --cov-report=html

# Run specific test file
pytest tests/test_request_handler.py
```

## 🔧 Extending Zodiac

### Creating a Custom Scanner

```python
from zodiac.scanners.scanner_base import ScannerBase
from zodiac.core.request_handler import RequestHandler
from zodiac.core.report_manager import Finding

class CustomScanner(ScannerBase):
    def scan(self, target: str, paths: List[str]) -> List[Finding]:
        findings = []
        
        # Your scan logic here
        for path in paths:
            # Test for vulnerability
            response = self.request_handler.get(f"{target}/{path}")
            
            if self._is_vulnerable(response):
                findings.append(Finding(
                    id=self.generate_finding_id(),
                    type="CUSTOM",
                    target=target,
                    path=path,
                    severity="HIGH",
                    confidence="MEDIUM",
                    evidence="Custom vulnerability detected"
                ))
        
        return findings
```

### Adding to CLI

Update `zodiac/cli.py` to include your scanner:

```python
if "custom" in scan_types or "all" in scan_types:
    self.scanners.append(("Custom", CustomScanner(handler)))
```

## 📝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

Built with care for the security community. Remember to always test responsibly!

## 📞 Support

- 🐛 **Issues**: [GitHub Issues](https://github.com/yourusername/zodiac-scanner/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/yourusername/zodiac-scanner/discussions)

---

**Stay secure, scan responsibly!** ♊

