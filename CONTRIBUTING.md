# Contributing to Zodiac Scanner

Thank you for your interest in contributing to Zodiac! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please be respectful and professional in all interactions. Remember that this tool is used for authorized security testing only.

## How to Contribute

### Reporting Bugs

If you find a bug, please open an issue with:
- Clear description of the bug
- Steps to reproduce
- Expected vs actual behavior
- System information (OS, Python version)

### Suggesting Features

We welcome feature suggestions! Please open an issue to discuss before implementing.

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`pytest`)
6. Run linting (`flake8 zodiac tests`)
7. Commit your changes (`git commit -m 'Add amazing feature'`)
8. Push to your branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

## Development Setup

```bash
# Clone and setup
git clone https://github.com/yourusername/zodiac-scanner.git
cd zodiac-scanner
python -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt
pip install -e .

# Run tests
pytest

# Run linting
flake8 zodiac tests
```

## Coding Standards

- Follow PEP 8 style guide
- Add type hints where appropriate
- Write docstrings for all public functions and classes
- Add tests for new scanners or features
- Keep code modular and maintainable

## Security Considerations

- Never include real exploit payloads in public commits
- Always use sanitized test payloads
- Follow the principle of least privilege
- Be mindful of rate limiting and safety controls

Thank you for contributing to Zodiac! 🎉

