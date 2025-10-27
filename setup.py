"""Setup script for Zodiac Vulnerability Scanner."""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as f:
        return f.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="zodiac-scanner",
    version="1.0.0",
    description="A professional web vulnerability scanner with modular architecture",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    author="Zodiac Scanner Team",
    author_email="",
    url="https://github.com/yourusername/zodiac-scanner",
    packages=find_packages(exclude=["tests", "*.tests", "*.tests.*", "tests.*"]),
    py_modules=["zodiac"],
    install_requires=read_requirements(),
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "zodiac=zodiac.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    keywords="security vulnerability scanner pentesting web security",
)

