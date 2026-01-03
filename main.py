#!/usr/bin/env python3
"""NetConfigPro - Network Configuration Generator & Validator.

A tool for network engineers to create, validate, and analyze
network device configurations.
"""

import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.gui.app import main as run_app


def main() -> None:
    """Main entry point."""
    run_app()


if __name__ == "__main__":
    main()
