"""Pytest configuration for finding ghostlogic module."""

import sys
from pathlib import Path

# Add repo root to sys.path so ghostlogic module can be imported
sys.path.insert(0, str(Path(__file__).parent.parent))
