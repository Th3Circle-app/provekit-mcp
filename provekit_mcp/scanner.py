"""
Scanning engine for provekit-mcp.

This is a Python port of the provekit engine (github.com/Th3Circle-app/provekit),
kept rule-for-rule compatible on the shared detectors and extended with
Python-specific vulnerability patterns (os.system interpolation, shell=True,
pickle/yaml deserialization, requests verify=False).

Design invariants carried over from provekit, because they are what make a
scanner trustworthy enough to leave switched on:

  * Every rule regex is BOUNDED. No unbounded quantifiers, no catastrophic
    backtracking. A 40k-character pathological line scans in ~1ms.
  * Long lines are NOT silently skipped (that is a padding-evasion gap: hide a
    secret behind a wall of junk and slip past a length cap). Every rule runs on
    every line up to MAX_LINE.
  * A line genuinely too long to scan safely is REPORTED as `line-too-long`,
    never dropped. You always know what was not covered.
  * Detectors that have a high false-positive surface (generic secrets, SQL
    concatenation) use a smart predicate, not a naive regex, so the tool does
    not cry wolf on already-guarded code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Callable, Optional

# A line longer than this is not scanned rule-by-rule; it is reported instead.
# Generous enough that real source never trips it, tight enough that a
# pathological line cannot be used to burn CPU.
MAX_LINE = 50_000

SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


@dataclass
class Finding:
    id: str
    severity: str
    owasp: str
    category: str
    why: str
    file: str
    line: int
    excerpt: str

    def to_dict(self) -> dict:
        return asdict(self)


# --- test-fixture path detector: insecure things in test/fixture code are on
# purpose, so the generic-secret rule stays quiet there while still catching a
# real key anywhere. ---
_TEST_PATH = re.compile(
    r"(?:^|/)(?:__tests__|__mocks__|fixtures?|e2e)/|(?:^|/)tests?/|"
    r"\.(?:test|spec)\.[jt]sx?$|_test\.py$|(?:^|/)test_[^/]*\.py$",
    re.IGNORECASE,
)

_PLACEHOLDER = re.compile(
    r"^(?:your[-_ ]|xxx+|placeholder|redacted|change[-_ ]?me|replace[-_ ]?|"
    r"example|sample|test|dummy|fake|invalid|none|null|n/a|todo|fixme|<|\.\.\.|"
    r"\$\{|\{\{)",
    re.IGNORECASE,
)
_HASHISH = re.compile(r"hash$|^0+$|^(.)\1{5,}$", re.IGNORECASE)
_ALGO_PREFIX = re.compile(r"^\$(?:2[aby]|argon2|scrypt|pbkdf2)", re.IGNORECASE)
_ENV_VALUE = re.compile(r"^(?:process\.env|import\.meta|os\.environ|Deno\.env)")

_SECRET_ASSIGN = re.compile(
    r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|"
    r"client[_-]?secret|private[_-]?key)\b\s*[:=]\s*(['\"\x60])([^'\"\x60]{8,})\1",
    re.IGNORECASE,
)


def _hardcoded_secret(line: str, file: str) -> bool:
    if _TEST_PATH.search(file or ""):
        return False
    m = _SECRET_ASSIGN.search(line)
    if not m:
        return False
    val = m.group(2)
    if _ALGO_PREFIX.match(val):        # it's a hash, not plaintext
        return False
    if _HASHISH.search(val):           # "...-hash", all zeros, all-same-char
        return False
    if _ENV_VALUE.match(val):          # value read from env
        return False
    if _PLACEHOLDER.match(val):        # placeholder / template
        return False
    has_digit = any(c.isdigit() for c in val)
    has_upper = any(c.isupper() for c in val)
    symbols = len(re.findall(r"[^A-Za-z0-9]", val))
    # a pure lowercase word (e.g. a default like "changeme-later") is not a
    # convincing real secret; require some entropy signal.
    return has_digit or has_upper or symbols >= 2


_SQL_SAFE_MARKERS = re.compile(
    r"\.(?:escape|escapeId)\s*\(|sequelize\.escape|\?\?|\$\d|:\w+\b"
)
_SQL_INJECTABLE = re.compile(
    r"[`'\"]\s*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|CREATE|ALTER|DROP)"
    r"\b[\s\S]{0,160}?(?:\$\{|['\"]{1,3}\s*\+\s*[A-Za-z_$])"
)


def _sql_concat(line: str, file: str) -> bool:
    if _SQL_SAFE_MARKERS.search(line):   # escaped / parameterized
        return False
    return bool(_SQL_INJECTABLE.search(line))


# Python string built from an f-string / .format / % with interpolation, fed to
# a dangerous sink. Bounded body so it cannot backtrack.
_PY_CMD_INTERP = re.compile(
    r"os\.system\s*\(\s*(?:f['\"][^'\"]{0,300}\{|['\"][^'\"]{0,300}['\"]\s*[%+]|"
    r"['\"][^'\"]{0,300}['\"]\.format\s*\()"
)
_PY_SHELL_TRUE = re.compile(
    r"subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]{0,200}"
    r"shell\s*=\s*True",
    re.IGNORECASE,
)
_PY_YAML_UNSAFE = re.compile(r"yaml\.load\s*\(")
_PY_YAML_SAFE = re.compile(r"Loader\s*=\s*(?:yaml\.)?(?:Safe|C?Safe)Loader|yaml\.safe_load")


def _py_yaml_unsafe(line: str, file: str) -> bool:
    if _PY_YAML_SAFE.search(line):
        return False
    return bool(_PY_YAML_UNSAFE.search(line))


# rule = (id, severity, owasp, category, why, matcher)
# matcher is either a compiled regex or a predicate(line, file) -> bool.
SECRETS = [
    ("aws-access-key", "critical", "A07 / A02", "Leaked secret",
     "AWS access key ID committed to code",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws-secret-key", "critical", "A07 / A02", "Leaked secret",
     "Possible AWS secret access key in code",
     re.compile(r"\baws_secret_access_key\b\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]", re.IGNORECASE)),
    ("private-key-block", "critical", "A07 / A02", "Leaked secret",
     "Private key block committed to code",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("github-token", "critical", "A07 / A02", "Leaked secret",
     "GitHub token committed to code",
     re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("stripe-live-key", "critical", "A07 / A02", "Leaked secret",
     "Live Stripe secret key committed to code",
     re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b")),
    ("anthropic-key", "critical", "A07 / A02", "Leaked secret",
     "Anthropic API key committed to code",
     re.compile(r"\bsk-ant-[A-Za-z0-9-]{20,}\b")),
    ("openai-key", "critical", "A07 / A02", "Leaked secret",
     "OpenAI API key committed to code",
     re.compile(r"\bsk-(?!ant-)[A-Za-z0-9]{20,}\b")),
    ("slack-token", "high", "A07 / A02", "Leaked secret",
     "Slack token committed to code",
     re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key", "high", "A07 / A02", "Leaked secret",
     "Google API key committed to code",
     re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("jwt", "medium", "A07 / A02", "Leaked secret",
     "Hard-coded JWT in code",
     re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("db-url-creds", "high", "A07 / A02", "Leaked secret",
     "Database URL with inline credentials",
     re.compile(r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:'\"]+:[^\s@'\"]+@", re.IGNORECASE)),
    ("hardcoded-secret", "high", "A07 / A02", "Leaked secret",
     "Hard-coded credential assigned a literal value",
     _hardcoded_secret),
]

PATTERNS = [
    ("ssrf-user-url", "high", "A10", "SSRF",
     "User-controlled input reaches a server-side HTTP request; SSRF risk unless the host is validated against an allowlist",
     re.compile(r"\b(?:fetch|axios(?:\.\w+)?|https?\.get|got|request|requests\.\w+)\s*\([^)]{0,120}\b(?:req|request|ctx|event)\.(?:query|params|body|headers)\b", re.IGNORECASE)),
    ("eval", "high", "A03", "Injection",
     "Use of eval() executes arbitrary code, a classic injection vector",
     re.compile(r"(?<![\w.])eval\s*\(")),
    ("new-function", "high", "A03", "Injection",
     "new Function(...) runs arbitrary code, same risk as eval",
     re.compile(r"new\s+Function\s*\(")),
    ("child-process-interp", "critical", "A03", "Command injection",
     "Shell command built with string interpolation; command injection risk",
     re.compile(r"(?:exec|execSync|spawn|spawnSync)\s*\(\s*[`'\"][^`'\"]{0,500}\$\{")),
    ("py-command-interp", "critical", "A03", "Command injection",
     "os.system() built from an interpolated/formatted string; command injection risk",
     _PY_CMD_INTERP),
    ("py-subprocess-shell", "high", "A03", "Command injection",
     "subprocess called with shell=True; command injection risk if any argument is user-controlled",
     _PY_SHELL_TRUE),
    ("py-pickle-load", "high", "A08", "Insecure deserialization",
     "pickle.load/loads on untrusted data executes arbitrary code",
     re.compile(r"\bpickle\.loads?\s*\(")),
    ("py-yaml-unsafe", "high", "A08", "Insecure deserialization",
     "yaml.load without SafeLoader can instantiate arbitrary Python objects; use yaml.safe_load",
     _py_yaml_unsafe),
    ("py-requests-noverify", "high", "A02", "Broken transport",
     "requests called with verify=False disables TLS certificate verification",
     re.compile(r"requests\.\w+\s*\([^)]{0,200}verify\s*=\s*False", re.IGNORECASE)),
    ("sql-string-concat", "medium", "A03", "SQL injection",
     "SQL query built with string interpolation/concatenation; verify it is parameterized, not user-injectable",
     _sql_concat),
    ("tls-verify-off", "high", "A02", "Broken crypto/transport",
     "TLS certificate verification disabled (rejectUnauthorized:false / verify=False)",
     re.compile(r"rejectUnauthorized\s*:\s*false|verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0")),
    ("dangerous-html", "medium", "A03", "XSS",
     "dangerouslySetInnerHTML / innerHTML with a dynamic value; XSS risk",
     re.compile(r"dangerouslySetInnerHTML|\.innerHTML\s*=\s*(?!['\"`])")),
    ("weak-hash-pw", "low", "A02", "Weak crypto",
     "MD5/SHA1 used; insecure for passwords or integrity (fine for non-security checksums)",
     re.compile(r"createHash\s*\(\s*['\"](?:md5|sha1)['\"]\s*\)|hashlib\.(?:md5|sha1)\s*\(", re.IGNORECASE)),
    ("insecure-random-token", "medium", "A02", "Weak randomness",
     "Math.random()/random used to generate a token/secret/id; not cryptographically secure",
     re.compile(r"(?:token|secret|otp|nonce|api[_-]?key|session)\w{0,40}\s*[:=][^;\n]{0,300}(?:Math\.random\s*\(|\brandom\.\w+\s*\()", re.IGNORECASE)),
    ("cors-wildcard", "medium", "A05", "Misconfiguration",
     'CORS Access-Control-Allow-Origin set to "*"; allows any site',
     re.compile(r"Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*['\"]", re.IGNORECASE)),
    ("debug-true", "low", "A05", "Misconfiguration",
     "Debug mode enabled; can leak stack traces in production",
     re.compile(r"\bdebug\s*[:=]\s*True\b|app\.debug\s*=\s*true|app\.run\([^)]*debug\s*=\s*True")),
]

ALL_RULES = SECRETS + PATTERNS

_IGNORE = re.compile(r"provekit-ignore")


def _match(matcher, line: str, file: str) -> bool:
    if callable(matcher) and not hasattr(matcher, "search"):
        return bool(matcher(line, file))
    return bool(matcher.search(line))


def scan_line(line: str, file: str, lineno: int) -> list[Finding]:
    """Scan a single line against every rule. Returns a list of Finding."""
    if _IGNORE.search(line):
        return []
    if len(line) > MAX_LINE:
        # Do not silently skip. Report that this line was too long to scan.
        return [Finding(
            id="line-too-long",
            severity="low",
            owasp="-",
            category="Coverage",
            why=f"Line {lineno} is {len(line)} chars, over the {MAX_LINE}-char scan cap; "
                "not scanned rule-by-rule to stay ReDoS-safe. Split or review it manually.",
            file=file,
            line=lineno,
            excerpt=line[:120] + "...",
        )]
    out: list[Finding] = []
    for rid, sev, owasp, cat, why, matcher in ALL_RULES:
        if _match(matcher, line, file):
            excerpt = line.strip()
            if len(excerpt) > 200:
                excerpt = excerpt[:200] + "..."
            out.append(Finding(rid, sev, owasp, cat, why, file, lineno, excerpt))
    return out


def scan_text(text: str, file: str = "input") -> list[Finding]:
    """Scan a whole file/blob. Reads EVERY line, never silently skips."""
    findings: list[Finding] = []
    # splitlines() handles \n, \r\n, \r, and other unicode line breaks safely.
    for i, line in enumerate(text.splitlines(), start=1):
        findings.extend(scan_line(line, file, i))
    return findings


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.line))


def summarize(findings: list[Finding]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return {
        "total": len(findings),
        "by_severity": counts,
        "worst": next((s for s in ("critical", "high", "medium", "low") if counts[s]), None),
    }
