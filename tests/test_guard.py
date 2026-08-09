"""Trust-boundary guards: the security-critical tests. If any of these regress,
the MCP server has a path-escape or DoS hole."""

import os
import pytest

from provekit_mcp import guard


@pytest.fixture
def workspace(tmp_path):
    # a small tree: root/ok.py, root/sub/nested.py, and a secret OUTSIDE root
    root = tmp_path / "ws"
    (root / "sub").mkdir(parents=True)
    (root / "ok.py").write_text("print('hi')\n")
    (root / "sub" / "nested.py").write_text("x = 1\n")
    secret = tmp_path / "secret.txt"
    secret.write_text("AKIAIOSFODNN7EXAMPLE\n")
    return {"root": str(root), "secret": str(secret), "tmp": str(tmp_path)}


# ---- paths that MUST resolve (legitimate) ----
@pytest.mark.parametrize("rel", ["ok.py", "sub/nested.py", "./ok.py"])
def test_legit_paths_resolve(workspace, rel):
    resolved = guard.safe_resolve(rel, workspace["root"])
    assert resolved.startswith(os.path.realpath(workspace["root"]))


# ---- paths that MUST be rejected (attacks) ----
@pytest.mark.parametrize("bad,code", [
    ("/etc/passwd", "absolute"),
    ("../secret.txt", "escape"),
    ("../../etc/passwd", "escape"),
    ("sub/../../secret.txt", "escape"),
    ("sub/../../../etc/passwd", "escape"),
    ("ok.py\x00.txt", "null-byte"),
    ("", "bad-type"),
    ("a" * 5000, "too-long"),
])
def test_escape_attempts_rejected(workspace, bad, code):
    with pytest.raises(guard.GuardRejection) as e:
        guard.safe_resolve(bad, workspace["root"])
    assert e.value.code == code


def test_non_string_path_rejected(workspace):
    for bad in [None, 123, ["ok.py"], {"path": "ok.py"}]:
        with pytest.raises(guard.GuardRejection):
            guard.safe_resolve(bad, workspace["root"])


def test_symlink_escape_rejected(workspace):
    """A symlink inside the root pointing OUT of it must not become a read
    primitive. realpath follows the link, containment check fails."""
    link = os.path.join(workspace["root"], "escape_link")
    try:
        os.symlink(workspace["secret"], link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported here")
    with pytest.raises(guard.GuardRejection) as e:
        guard.safe_resolve("escape_link", workspace["root"])
    assert e.value.code == "escape"


def test_symlinked_dir_escape_rejected(workspace):
    link = os.path.join(workspace["root"], "outdir")
    try:
        os.symlink(workspace["tmp"], link)   # points to parent of root
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported here")
    with pytest.raises(guard.GuardRejection) as e:
        guard.safe_resolve("outdir/secret.txt", workspace["root"])
    assert e.value.code == "escape"


def test_prefix_confusion_not_a_false_pass(tmp_path):
    """root=/a/b must not accept a sibling /a/bc via a naive startswith."""
    (tmp_path / "b").mkdir()
    (tmp_path / "bc").mkdir()
    (tmp_path / "bc" / "x.py").write_text("1\n")
    with pytest.raises(guard.GuardRejection):
        guard.safe_resolve("../bc/x.py", str(tmp_path / "b"))


# ---- size / DoS guards ----
def test_text_size_limit():
    guard.enforce_text_size("x" * 100)              # fine
    with pytest.raises(guard.GuardRejection) as e:
        guard.enforce_text_size("x" * (guard.MAX_TEXT_BYTES + 1))
    assert e.value.code == "too-large"


def test_text_size_type():
    with pytest.raises(guard.GuardRejection):
        guard.enforce_text_size(b"bytes not str")


def test_file_size_limit(tmp_path):
    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * (guard.MAX_FILE_BYTES + 10))
    with pytest.raises(guard.GuardRejection) as e:
        guard.enforce_file_size(str(big))
    assert e.value.code == "too-large"


# ---- binary detection ----
def test_binary_detection():
    assert guard.looks_binary(b"\x00\x01\x02binary")
    assert guard.looks_binary(bytes(range(256)) * 4)
    assert not guard.looks_binary(b"const x = 1;\nprint('hello')\n")
    assert not guard.looks_binary(b"")
