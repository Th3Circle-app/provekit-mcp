"""
Trust-boundary guards for provekit-mcp.

An MCP tool is a function an autonomous model can call with arguments it chose,
sometimes under the influence of untrusted content it just read. So every tool
argument is hostile input. These guards are the enforcement layer:

  * safe_resolve  - a file argument may only ever resolve to a path INSIDE the
    configured workspace root. Absolute paths, `..` traversal, null bytes, and
    symlinks that escape the root are all rejected. This is the control that
    stops "scan ../../../../etc/passwd" or "scan /Users/me/.ssh/id_rsa".

  * enforce_text_size / enforce_file_size - bound how much data a single call
    can push through the scanner, so a tool call cannot be used to exhaust
    memory or CPU (a denial-of-service against the host).

  * looks_binary - refuse to treat a binary blob as source, both to avoid junk
    findings and to avoid reading something that was never meant to be scanned.

Guards raise GuardRejection on refusal. The server catches it and returns a
structured, non-leaky error to the model; it never turns into a traceback or a
successful unsafe read.
"""

from __future__ import annotations

import os

# Per-call limits. Generous for real source files, tight enough that a single
# tool call cannot be turned into a resource-exhaustion attack on the host.
MAX_TEXT_BYTES = 5_000_000        # 5 MB of code per scan_code call
MAX_FILE_BYTES = 5_000_000        # 5 MB per scan_path file read
MAX_PATH_LEN = 4096               # reject absurd paths before touching the FS


class GuardRejection(Exception):
    """Raised when a tool argument violates a trust boundary."""

    def __init__(self, reason: str, code: str = "rejected"):
        super().__init__(reason)
        self.reason = reason
        self.code = code


def enforce_text_size(text, *, limit: int = MAX_TEXT_BYTES) -> str:
    if not isinstance(text, str):
        raise GuardRejection("code must be a string", code="bad-type")
    n = len(text.encode("utf-8", "surrogatepass"))
    if n > limit:
        raise GuardRejection(
            f"input too large: {n} bytes exceeds the {limit}-byte per-call limit",
            code="too-large",
        )
    return text


def looks_binary(sample: bytes) -> bool:
    """Heuristic: a NUL byte, or a high ratio of non-text bytes, means binary."""
    if b"\x00" in sample:
        return True
    if not sample:
        return False
    text_bytes = bytes(range(0x20, 0x7F)) + b"\n\r\t\f\b"
    nontext = sum(1 for b in sample if b not in text_bytes)
    return nontext / len(sample) > 0.30


def workspace_root(explicit: str | None = None) -> str:
    """
    The one directory tool file-arguments are allowed to resolve inside.
    Resolved through symlinks up front so every later comparison is apples to
    apples. Defaults to PROVEKIT_MCP_ROOT, else the process CWD.
    """
    root = explicit or os.environ.get("PROVEKIT_MCP_ROOT") or os.getcwd()
    return os.path.realpath(root)


def safe_resolve(user_path, root: str | None = None) -> str:
    """
    Resolve a user-supplied relative path to an absolute path guaranteed to be
    inside `root`. Raises GuardRejection on any escape attempt.

    Defenses, in order:
      1. type / emptiness / length            - reject garbage early
      2. explicit NUL-byte check              - stop C-string truncation tricks
      3. reject absolute paths                - "/etc/passwd", "C:\\..."
      4. join under root, then realpath       - collapses `..` AND follows
         symlinks, so a symlink pointing out of the tree resolves to its real
         location and fails the containment check below
      5. containment check with a trailing sep - prevents the "/a/b" vs "/a/bc"
         prefix-confusion false pass
    """
    if not isinstance(user_path, str) or not user_path:
        raise GuardRejection("path must be a non-empty string", code="bad-type")
    if len(user_path) > MAX_PATH_LEN:
        raise GuardRejection("path is unreasonably long", code="too-long")
    if "\x00" in user_path:
        raise GuardRejection("null byte in path", code="null-byte")
    if os.path.isabs(user_path) or (os.name == "nt" and _is_windows_abs(user_path)):
        raise GuardRejection("absolute paths are not allowed", code="absolute")

    root_real = workspace_root(root)
    joined = os.path.join(root_real, user_path)
    resolved = os.path.realpath(joined)   # collapses .. and follows symlinks

    if resolved != root_real and not resolved.startswith(root_real + os.sep):
        raise GuardRejection("path escapes the workspace root", code="escape")
    return resolved


def _is_windows_abs(p: str) -> bool:
    # e.g. "C:\\Windows" or "\\\\server\\share" (UNC) or a leading backslash
    return (len(p) >= 2 and p[1] == ":") or p.startswith("\\\\") or p.startswith("\\")


def enforce_file_size(path: str, *, limit: int = MAX_FILE_BYTES) -> int:
    try:
        size = os.path.getsize(path)
    except OSError as e:
        raise GuardRejection(f"cannot stat file: {e.strerror or 'error'}", code="stat")
    if size > limit:
        raise GuardRejection(
            f"file too large: {size} bytes exceeds the {limit}-byte limit",
            code="too-large",
        )
    return size
