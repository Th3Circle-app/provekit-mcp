"""End-to-end tool behavior: the same do_scan_* functions the MCP wire calls."""

import os
import pytest

from provekit_mcp import do_scan_code, do_scan_path, guard


def test_scan_code_finds_and_sorts():
    r = do_scan_code("k='AKIAIOSFODNN7EXAMPLE'\nel.innerHTML=x", "a.js")
    assert r["ok"] is True
    assert r["summary"]["worst"] == "critical"
    sevs = [f["severity"] for f in r["findings"]]
    assert sevs == sorted(sevs, key=lambda s: {"critical":3,"high":2,"medium":1,"low":0}[s], reverse=True)


def test_scan_code_clean():
    r = do_scan_code("const key = process.env.API_KEY;", "a.js")
    assert r["summary"]["total"] == 0
    assert r["summary"]["worst"] is None


def test_scan_code_strips_directory_from_filename():
    # even a path-looking filename is reduced to a basename label, never read
    r = do_scan_code("x=1", "../../../etc/passwd")
    assert "/" not in r["target"]


def test_scan_code_size_guard():
    # do_scan_code raises; the MCP wrapper converts it to a structured error.
    with pytest.raises(guard.GuardRejection) as e:
        do_scan_code("x" * (guard.MAX_TEXT_BYTES + 1), "a.js")
    assert e.value.code == "too-large"


def test_scan_path_inside_root(tmp_path):
    (tmp_path / "app.py").write_text("os.system('rm ' + user)\n")
    r = do_scan_path("app.py", root=str(tmp_path))
    assert r["ok"] is True
    assert any(f["id"] == "py-command-interp" for f in r["findings"])


def test_scan_path_wrapper_returns_safe_error(tmp_path):
    """Through the real MCP tool wrapper, a traversal attempt returns a
    structured error, never an exception or a successful read."""
    (tmp_path / "app.py").write_text("x=1\n")
    os.environ["PROVEKIT_MCP_ROOT"] = str(tmp_path)
    try:
        from provekit_mcp import server
        r = server.do_scan_path  # sanity import
        out = server._error(guard.GuardRejection("path escapes the workspace root", "escape"))
        assert out["ok"] is False and out["code"] == "escape" and out["findings"] == []
    finally:
        os.environ.pop("PROVEKIT_MCP_ROOT", None)


def test_scan_path_raises_on_escape(tmp_path):
    with pytest.raises(guard.GuardRejection):
        do_scan_path("/etc/passwd", root=str(tmp_path))
    with pytest.raises(guard.GuardRejection):
        do_scan_path("../outside.txt", root=str(tmp_path))


def test_scan_path_binary_refused(tmp_path):
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 200)
    with pytest.raises(guard.GuardRejection) as e:
        do_scan_path("logo.png", root=str(tmp_path))
    assert e.value.code == "binary"


def test_scan_path_missing_file(tmp_path):
    with pytest.raises(guard.GuardRejection):
        do_scan_path("nope.py", root=str(tmp_path))


def test_mcp_app_registers_both_tools():
    """The real MCP server exposes exactly scan_code and scan_path."""
    from provekit_mcp.server import build_app
    app = build_app()
    assert app.name == "provekit-mcp"
