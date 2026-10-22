"""plugin-vet: static safety checks for coding-agent plugins, skills and MCP servers."""
from .scan import Finding, ScanResult, scan
from .policy import Policy, LEVELS

__version__ = "0.1.0"
__all__ = ["scan", "Finding", "ScanResult", "Policy", "LEVELS", "__version__"]
