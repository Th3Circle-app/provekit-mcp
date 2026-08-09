"""
provekit-mcp: a hardened MCP server that gives an AI agent a code security
scanner, built so the tools themselves cannot be turned against the host.

Two tools are exposed over MCP:

  * scan_code(code, filename)  - scan a snippet the agent already has in hand.
    No filesystem access at all, so there is no path to traverse.
  * scan_path(path)            - scan a file, but only inside a workspace root.
    Every path argument goes through guard.safe_resolve first.

The tool LOGIC lives in plain module-level functions (do_scan_code /
do_scan_path). The @app.tool wrappers are thin. This is deliberate: the tests
and the red-team harness call the same functions the MCP wire calls, so what is
verified is exactly what ships.

Run it:  python -m provekit_mcp.server           (stdio, for Claude Desktop/Code)
Root:    PROVEKIT_MCP_ROOT=/path/to/workspace     (defaults to CWD)
"""

from __future__ import annotations

import os

from . import guard
from .scanner import scan_text, sort_findings, summarize


def do_scan_code(code: str, filename: str = "snippet.txt") -> dict:
    """Scan a code string. Pure, no filesystem access. Guarded for size."""
    code = guard.enforce_text_size(code)
    if not isinstance(filename, str) or not filename:
        filename = "snippet.txt"
    # filename is used only as a label and for test-fixture suppression; strip
    # any directory component so it can never be read as a path.
    filename = os.path.basename(filename)[:256]
    findings = sort_findings(scan_text(code, filename))
    return {
        "ok": True,
        "target": filename,
        "summary": summarize(findings),
        "findings": [f.to_dict() for f in findings],
    }


def do_scan_path(path: str, root: str | None = None) -> dict:
    """
    Scan a file inside the workspace root. The path is resolved through
    guard.safe_resolve, which rejects absolute paths, `..` traversal, null
    bytes, and symlink escapes before anything is read.
    """
    resolved = guard.safe_resolve(path, root)   # raises GuardRejection on escape

    if not os.path.isfile(resolved):
        raise guard.GuardRejection("not a regular file", code="not-a-file")

    guard.enforce_file_size(resolved)

    with open(resolved, "rb") as fh:
        raw = fh.read(guard.MAX_FILE_BYTES + 1)
    if len(raw) > guard.MAX_FILE_BYTES:
        raise guard.GuardRejection("file grew past the size limit while reading",
                                   code="too-large")
    if guard.looks_binary(raw[:8192]):
        raise guard.GuardRejection("file looks binary, not source", code="binary")

    text = raw.decode("utf-8", "replace")
    label = os.path.relpath(resolved, guard.workspace_root(root))
    findings = sort_findings(scan_text(text, label))
    return {
        "ok": True,
        "target": label,
        "summary": summarize(findings),
        "findings": [f.to_dict() for f in findings],
    }


def _error(exc: guard.GuardRejection) -> dict:
    """Turn a guard rejection into a structured, non-leaky tool result."""
    return {"ok": False, "error": exc.reason, "code": exc.code, "findings": []}


def build_app():
    """Construct the MCP server. Imported lazily so tests/red-team don't need
    the transport stack just to exercise the tool logic."""
    from mcp.server import MCPServer
    from mcp.server.mcpserver import ResourceSecurity

    app = MCPServer(
        name="provekit-mcp",
        version="0.1.0",
        instructions=(
            "Security scanning tools for AI-generated code. Use scan_code to "
            "check a snippet you already have; use scan_path to check a file "
            "inside the workspace. Paths outside the workspace are refused by "
            "design, that is not an error to work around."
        ),
        # Defense in depth: the SDK's own resource layer also refuses traversal,
        # absolute paths, and null bytes. Our guard.safe_resolve is the primary
        # control; this is a second, independent one.
        resource_security=ResourceSecurity(
            reject_path_traversal=True,
            reject_absolute_paths=True,
            reject_null_bytes=True,
        ),
    )

    @app.tool()
    def scan_code(code: str, filename: str = "snippet.txt") -> dict:
        """Scan a snippet of code for leaked secrets and insecure patterns
        (OWASP Top 10). Returns findings sorted by severity. No filesystem
        access. `filename` is an optional label used for reporting."""
        try:
            return do_scan_code(code, filename)
        except guard.GuardRejection as e:
            return _error(e)

    @app.tool()
    def scan_path(path: str) -> dict:
        """Scan a single source file for leaked secrets and insecure patterns.
        `path` must be relative to the server's workspace root; paths that
        escape the workspace are refused."""
        try:
            return do_scan_path(path)
        except guard.GuardRejection as e:
            return _error(e)

    return app


def main() -> None:
    app = build_app()
    root = guard.workspace_root()
    # stderr, so it never corrupts the stdio JSON-RPC stream on stdout.
    import sys
    print(f"[provekit-mcp] workspace root: {root}", file=sys.stderr)
    app.run()   # stdio transport by default


if __name__ == "__main__":
    main()
