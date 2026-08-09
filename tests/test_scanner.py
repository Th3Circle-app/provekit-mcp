"""Scanner correctness: every rule fires on a true positive, stays quiet on
guarded code, and the coverage/ReDoS invariants hold."""

import time
import pytest

from provekit_mcp.scanner import scan_text, sort_findings, SEVERITY_RANK, MAX_LINE


def ids(text, file="x.js"):
    return [f.id for f in scan_text(text, file)]


def has(text, rule, file="x.js"):
    return rule in ids(text, file)


def clean(text, file="x.js"):
    found = scan_text(text, file)
    assert found == [], f"expected 0 findings, got {[f.id for f in found]} for: {text!r}"


# ---- secrets: positives ----
@pytest.mark.parametrize("text,rule", [
    ("k='AKIAIOSFODNN7EXAMPLE'", "aws-access-key"),
    ("aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'", "aws-secret-key"),
    ("-----BEGIN RSA PRIVATE KEY-----", "private-key-block"),
    ("ghp_1234567890abcdefghijklmnopqrstuvwxyz", "github-token"),
    ("sk_live_" + "51H8xAbCdEfGhIjKlMnOpQrSt", "stripe-live-key"),  # split so it's not a real-looking token on disk
    ("key='sk-abcdef1234567890ABCDEFGHIJ'", "openai-key"),
    ("k='sk-ant-api03-abcdefghij1234567890'", "anthropic-key"),
    ("xoxb-123456789012-abcdefghijkl", "slack-token"),
    ("AIzaSyA1234567890abcdefghijklmnopqrstuv", "google-api-key"),
    ("url='postgres://admin:hunter2@db:5432/prod'", "db-url-creds"),
    ("const password = 'super-secret-9'", "hardcoded-secret"),
])
def test_secret_positive(text, rule):
    assert has(text, rule)


# ---- secrets: negatives (credibility) ----
@pytest.mark.parametrize("text", [
    "const key = process.env.API_KEY;",
    "const url = process.env.DATABASE_URL;",
    "const passwordField = getField('password');",
    "interface Cfg { password: string; apiKey: string }",
    "const secret = 'abc';",
    'password: "$2a$12$1XdLGt8wKPV4YOsrpCHZX.abcdefghijklmnopqrstuv"',   # bcrypt hash
    "const p = { password: 'stored-password-hash' };",
    "api_key: '00000000000000000000000000000000'",
])
def test_secret_negative(text):
    clean(text)


def test_generic_secret_quiet_in_test_files():
    clean("const password = 'Sup3r-Real-Looking!'", "src/tests/auth.test.js")
    clean("SECRET = 'Sup3r-Real-9'", "tests/test_auth.py")


def test_real_secret_still_flagged_in_source():
    assert has("const password = 'Sup3r-Real-9!'", "hardcoded-secret", "src/auth.js")


# ---- JS patterns ----
@pytest.mark.parametrize("text,rule", [
    ("await fetch(req.query.url)", "ssrf-user-url"),
    ("axios.get(request.body.endpoint)", "ssrf-user-url"),
    ("eval(userInput)", "eval"),
    ('const f = new Function("return 1")', "new-function"),
    ("exec(`ls ${dir}`)", "child-process-interp"),
    ('db.query(`SELECT * FROM u WHERE id=${id}`)', "sql-string-concat"),
    ("const a = { rejectUnauthorized: false }", "tls-verify-off"),
    ("el.innerHTML = userData", "dangerous-html"),
    ("crypto.createHash('md5')", "weak-hash-pw"),
    ("const token = 'x' + Math.random()", "insecure-random-token"),
    ("'Access-Control-Allow-Origin': '*'", "cors-wildcard"),
])
def test_js_pattern_positive(text, rule):
    assert has(text, rule)


@pytest.mark.parametrize("text", [
    "return fetch(url);",
    "fetch('https://api.example.com/v1')",
    "db.query('SELECT * FROM u WHERE n=$1', [name])",
    "db.query('SELECT * FROM u WHERE n = ?', [name])",
    "const token = crypto.randomBytes(32).toString('hex')",
    "const a = { rejectUnauthorized: true }",
    "el.textContent = userData",
    "crypto.createHash('sha256')",
    "await user.update(`${prefix}:${apiKey}`)",
    "db.query(`SELECT id FROM u WHERE x = ${db.escape(v)}`)",
])
def test_js_pattern_negative(text):
    clean(text)


# ---- Python patterns (the job-market coverage) ----
@pytest.mark.parametrize("text,rule", [
    ("os.system(f'rm -rf {userdir}')", "py-command-interp"),
    ("os.system('cat ' + path)", "py-command-interp"),
    ("subprocess.run(cmd, shell=True)", "py-subprocess-shell"),
    ("subprocess.run(shlex.split(cmd), shell=True)", "py-subprocess-shell"),  # nested call before shell=True
    ("data = pickle.loads(payload)", "py-pickle-load"),
    ("cfg = yaml.load(open('c.yml'))", "py-yaml-unsafe"),
    ("r = requests.get(u, verify=False)", "py-requests-noverify"),
    ("token = 'x' + str(random.random())", "insecure-random-token"),
    ("m = hashlib.md5(pw)", "weak-hash-pw"),
    ("app.run(host='0.0.0.0', debug=True)", "debug-true"),
], )
def test_py_pattern_positive(text, rule):
    assert has(text, rule, "app.py")


@pytest.mark.parametrize("text", [
    "subprocess.run(['ls', '-la'])",
    "cfg = yaml.safe_load(open('c.yml'))",
    "cfg = yaml.load(f, Loader=yaml.SafeLoader)",
    "r = requests.get(u, verify=True)",
    "token = secrets.token_hex(32)",
    "m = hashlib.sha256(data)",
    "app.run(host='127.0.0.1')",
])
def test_py_pattern_negative(text):
    clean(text, "app.py")


# ---- coverage + ReDoS invariants ----
def test_padding_evasion_closed():
    assert has("x" * 2000 + " 'AKIAIOSFODNN7EXAMPLE'", "aws-access-key")
    assert has("x" * 30000 + " 'AKIAIOSFODNN7EXAMPLE'", "aws-access-key")


def test_pattern_on_long_line_still_caught():
    assert has("a" * 3000 + "; fetch(req.query.url)", "ssrf-user-url", "app.js")


def test_overlong_line_is_reported_not_dropped():
    assert has("x" * (MAX_LINE + 1000) + " 'AKIAIOSFODNN7EXAMPLE'", "line-too-long")


def test_redos_safe_on_pathological_line():
    start = time.perf_counter()
    scan_text("(" * 20000 + "a" * 20000, "x.js")
    assert time.perf_counter() - start < 1.0, "a pathological line took too long (ReDoS?)"


def test_unicode_does_not_crash():
    scan_text('const 变量 = "日本語 \U0001f512";\nconst e = "\U0001f680";', "x.js")


def test_ignore_comment_suppresses():
    clean("k='AKIAIOSFODNN7EXAMPLE' // provekit-ignore")


def test_100k_lines_terminates():
    big = ("const x = 1;\n" * 100000) + "k='AKIAIOSFODNN7EXAMPLE';"
    assert "aws-access-key" in ids(big)


def test_sort_by_severity_desc():
    f = sort_findings(scan_text("k='AKIAIOSFODNN7EXAMPLE'; el.innerHTML=x", "x.js"))
    sevs = [SEVERITY_RANK[x.severity] for x in f]
    assert sevs == sorted(sevs, reverse=True)


def test_empty_and_whitespace():
    clean("")
    clean("   \n\t\n   ")
