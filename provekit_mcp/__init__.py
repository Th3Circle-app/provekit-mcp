"""provekit-mcp: a hardened MCP code-security scanner + its own red-team suite."""

__version__ = "0.1.0"

from .server import do_scan_code, do_scan_path
from .scanner import scan_text, sort_findings, summarize, Finding
from .guard import GuardRejection, safe_resolve

__all__ = [
    "do_scan_code",
    "do_scan_path",
    "scan_text",
    "sort_findings",
    "summarize",
    "Finding",
    "GuardRejection",
    "safe_resolve",
]
