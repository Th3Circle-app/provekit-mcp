"""
Red-team driver: spawn the REAL provekit-mcp server over stdio, speak the actual
MCP protocol to it (initialize -> tools/list -> tools/call), and try to break
out of it. Every attack is fired at the running server exactly the way a
hostile agent would fire it, not at the functions in-process.

Attacks attempted (each maps to a trust boundary a malicious MCP client tries):
  * path traversal        scan_path("../secret.txt")          -> must be refused
  * deep traversal        scan_path("a/../../../etc/passwd")   -> must be refused
  * absolute path         scan_path("/etc/passwd")             -> must be refused
  * symlink escape        scan_path("escape")  (link out)      -> must be refused
  * null-byte truncation  scan_path("app.py\\x00.txt")          -> must be refused
  * binary read           scan_path("logo.png")                -> must be refused
  * resource exhaustion   scan_code(6 MB string)               -> must be refused
  * ReDoS line            scan_code(pathological line)         -> must return fast
  * argument-as-code      scan_code(malicious text)            -> scanned, not run

A breach = the server returned the out-of-workspace decoy secret, executed
something, or crashed. Legitimate calls are also run to prove the guards do not
over-block (a scanner that refuses real work is a scanner nobody uses).

Usage:  python -m redteam.run
Exit code is non-zero if the run is not clean (breach / regression / inconclusive).
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
import tempfile
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from redteam.engine import (  # noqa: E402
    Report, Result, HELD, BREACH, OK, REGRESSION, INCONCLUSIVE,
)

DECOY = "AKIAIOSFODNN7EXAMPLE"   # a "secret" placed OUTSIDE the workspace root


def build_sandbox() -> dict:
    """A workspace the server is allowed to scan, plus a secret just outside it
    and a symlink that tries to bridge the two."""
    base = Path(tempfile.mkdtemp(prefix="provekit-mcp-redteam-"))
    root = base / "workspace"
    root.mkdir()
    (root / "app.py").write_text(
        "import os\n"
        "def handler(user):\n"
        "    os.system('echo ' + user)   # planted vuln for the legit scan\n"
    )
    (root / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 400)
    # the crown jewels, deliberately OUTSIDE the workspace root
    (base / "secret.txt").write_text(f"aws_key = '{DECOY}'\n")
    # a symlink inside the root that points out of it
    try:
        os.symlink(base / "secret.txt", root / "escape")
        symlink_ok = True
    except (OSError, NotImplementedError):
        symlink_ok = False
    return {"base": str(base), "root": str(root), "symlink_ok": symlink_ok}


def result_payload(call_result) -> dict:
    """Pull the tool's structured dict back out of an MCP CallToolResult,
    whether it came as structured content or as a JSON text block."""
    sc = getattr(call_result, "structuredContent", None)
    if isinstance(sc, dict):
        # MCP may wrap a bare return under {"result": ...}
        return sc.get("result", sc) if set(sc.keys()) == {"result"} else sc
    for block in getattr(call_result, "content", []) or []:
        text = getattr(block, "text", None)
        if text:
            try:
                return json.loads(text)
            except Exception:
                return {"_raw": text}
    return {"_raw": repr(call_result)}


async def call(session, tool, args, timeout=15.0):
    """Call a tool; distinguish a refusal-as-result from a crash/timeout."""
    try:
        res = await asyncio.wait_for(
            session.call_tool(tool, args), timeout=timeout)
        return {"status": "answered", "payload": result_payload(res),
                "is_error": bool(getattr(res, "isError", False))}
    except asyncio.TimeoutError:
        return {"status": "timeout"}
    except Exception as e:                        # protocol-level error / crash
        return {"status": "error", "error": f"{type(e).__name__}: {e}"}


def judge_attack(name, resp, *, decoy=DECOY) -> Result:
    """An attack is HELD only if the server answered with a clean refusal and
    did NOT leak the decoy. No answer -> INCONCLUSIVE (never a silent pass)."""
    if resp["status"] != "answered":
        return Result(name, "attack", INCONCLUSIVE,
                      f"server did not answer ({resp['status']})",
                      resp.get("error", ""))
    p = resp["payload"]
    blob = json.dumps(p)
    if decoy in blob:
        return Result(name, "attack", BREACH,
                      "server returned data from OUTSIDE the workspace root",
                      blob[:160])
    if p.get("ok") is False:
        return Result(name, "attack", HELD,
                      f"refused with code={p.get('code')!r}", p.get("error", ""))
    if p.get("ok") is True:
        # answered successfully but no leak: acceptable only if it found nothing
        # meaningful; for an escape attempt a successful read is still a breach
        return Result(name, "attack", BREACH,
                      "escape attempt was NOT refused", blob[:160])
    return Result(name, "attack", INCONCLUSIVE, "unexpected shape", blob[:160])


async def main() -> int:
    sb = build_sandbox()
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "provekit_mcp.server"],
        env={**os.environ, "PROVEKIT_MCP_ROOT": sb["root"]},
        cwd=str(Path(__file__).resolve().parent.parent),
    )
    report = Report()

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = sorted(t.name for t in tools.tools)
            report.add(Result(
                "handshake + tools/list", "control",
                OK if names == ["scan_code", "scan_path"] else REGRESSION,
                f"server exposed tools: {names}"))

            # ---------------- ATTACKS ----------------
            attacks = [
                ("path traversal",      "scan_path", {"path": "../secret.txt"}),
                ("deep traversal",      "scan_path", {"path": "app/../../../etc/passwd"}),
                ("absolute path",       "scan_path", {"path": "/etc/passwd"}),
                ("null-byte truncation","scan_path", {"path": "app.py\x00.txt"}),
                ("binary file read",    "scan_path", {"path": "logo.png"}),
            ]
            if sb["symlink_ok"]:
                attacks.insert(3, ("symlink escape", "scan_path", {"path": "escape"}))

            for name, tool, args in attacks:
                resp = await call(session, tool, args)
                report.add(judge_attack(name, resp))

            # resource-exhaustion: a 6 MB blob must be refused, fast
            t0 = time.perf_counter()
            resp = await call(session, "scan_code",
                              {"code": "x" * 6_000_000, "filename": "big.js"})
            dt = time.perf_counter() - t0
            r = judge_attack("resource exhaustion (6 MB input)", resp)
            r.detail += f"  [{dt*1000:.0f} ms]"
            report.add(r)

            # ReDoS line: must return quickly and not hang
            t0 = time.perf_counter()
            resp = await call(session, "scan_code",
                              {"code": "(" * 40000 + "a" * 40000, "filename": "x.js"})
            dt = time.perf_counter() - t0
            if resp["status"] != "answered":
                report.add(Result("ReDoS pathological line", "attack",
                                  INCONCLUSIVE, f"no answer ({resp['status']})"))
            elif dt > 2.0:
                report.add(Result("ReDoS pathological line", "attack", BREACH,
                                  f"took {dt:.2f}s — possible catastrophic backtracking"))
            else:
                report.add(Result("ReDoS pathological line", "attack", HELD,
                                  f"answered in {dt*1000:.0f} ms, no hang"))

            # argument-as-code: malicious text must be SCANNED, never executed
            resp = await call(session, "scan_code", {
                "code": "os.system('rm -rf ~'); k='AKIA" + "TESTONLYNOTREAL01'"
                        + "'\neval(userInput)",
                "filename": "evil.py"})
            if resp["status"] == "answered" and resp["payload"].get("ok"):
                ids = {f["id"] for f in resp["payload"]["findings"]}
                held = "eval" in ids or "py-command-interp" in ids
                report.add(Result("argument-as-code is inert", "attack",
                                  HELD if held else BREACH,
                                  "malicious argument was scanned as text, not executed"
                                  if held else "argument was not treated as inert data",
                                  f"findings={sorted(ids)}"))
            else:
                report.add(Result("argument-as-code is inert", "attack",
                                  INCONCLUSIVE, f"no answer ({resp['status']})"))

            # ---------------- CONTROLS (no over-blocking) ----------------
            resp = await call(session, "scan_path", {"path": "app.py"})
            if resp["status"] == "answered" and resp["payload"].get("ok"):
                ids = {f["id"] for f in resp["payload"]["findings"]}
                report.add(Result("legit scan_path finds the planted vuln",
                                  "control", OK if "py-command-interp" in ids else REGRESSION,
                                  f"scanned app.py inside root, findings={sorted(ids)}"))
            else:
                report.add(Result("legit scan_path", "control", REGRESSION,
                                  f"a valid in-root file was not scanned ({resp['status']})"))

            resp = await call(session, "scan_code",
                              {"code": "const k = process.env.API_KEY;", "filename": "ok.js"})
            if resp["status"] == "answered" and resp["payload"].get("ok"):
                total = resp["payload"]["summary"]["total"]
                report.add(Result("legit scan_code stays quiet on clean code",
                                  "control", OK if total == 0 else REGRESSION,
                                  f"clean snippet -> {total} findings"))
            else:
                report.add(Result("legit scan_code", "control", REGRESSION,
                                  f"a clean snippet was not scanned ({resp['status']})"))

    print(report.render())
    # persist machine-readable findings next to the report
    out = Path(__file__).resolve().parent.parent / "assets" / "redteam-report.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(
        {"counts": report.counts(), "clean": report.clean,
         "results": [r.__dict__ for r in report.results]}, indent=2))
    return 0 if report.clean else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
