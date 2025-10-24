#!/usr/bin/env python3
"""Setup script for TVM Disassembler."""
from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme = Path(__file__).parent / "tvm_disasm" / "README.md"
long_description = readme.read_text() if readme.exists() else ""

setup(
    name="tvm-disasm",
    version="0.1.0",
    description="TVM bytecode disassembler for The Open Network",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="TVM Disasm Contributors",
    license="CC BY-NC-SA 4.0",
    packages=find_packages(),
    package_data={
        'tvm_disasm': ['spec/*.json'],
    },
    install_requires=[
        "pytoniq-core>=0.1.0",
    ],
    python_requires=">=3.8",
    entry_points={
        'console_scripts': [
            'tvm-disasm=tvm_disasm.main:main',
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: Other/Proprietary License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Software Development :: Disassemblers",
    ],
)
