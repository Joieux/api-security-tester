#!/usr/bin/env python3
"""API Security Tester - a defensive scanner for APIs you own or are authorized to test.

This is a rewrite of the original tool. The design goals, in order:

1. Safe by default. Scanning a remote URL never reads your local disk,
   environment, or home directory. Local secret discovery is a separate,
   explicit subcommand.
2. Safe output. Every value that originates from the target (response bodies,
   headers, discovered token material) is sanitized before it is printed, so a
   hostile server cannot inject terminal escape sequences, and secrets are
   redacted unless you opt in.
3. Honest findings. Heuristics compare against a baseline before reporting, so
   "SQL injection" means "the payload changed behavior", not "the word error
   appeared somewhere".
4. No hangs. Every network call has a timeout.

Use this only against systems you own or have explicit written permission to test.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Optional, Sequence

import requests
from requests.adapters import HTTPAdapter

try:  # urllib3 ships with requests; the import path has moved over versions.
    from urllib3.util.retry import Retry
except Exception:  # pragma: no cover - extremely old urllib3
    from requests.packages.urllib3.util.retry import Retry  # type: ignore

try:
    import jwt  # PyJWT
except Exception:  # pragma: no cover - optional at import time
    jwt = None


DEFAULT_ENDPOINTS = ["/", "/login", "/api", "/admin"]
DEFAULT_TIMEOUT = 10.0  # seconds, per request


# --------------------------------------------------------------------------- #
# Output safety
# --------------------------------------------------------------------------- #

# Control characters are the vector for terminal-escape injection from a hostile
# target. We keep newline and tab (harmless, aid readability) and escape every
# other C0/C1 control byte, including ESC (0x1b), CR (0x0d), and DEL (0x7f).
_ALLOWED_CONTROL = {"\n", "\t"}


def sanitize(value: object, *, max_len: int = 2000) -> str:
    """Render untrusted text safe for a terminal.

    Control characters are replaced with a visible ``\\xNN`` escape rather than
    dropped, so the output stays faithful without being executable by the
    terminal. Printable Unicode above the C1 range is left intact.
    """
    text = value if isinstance(value, str) else str(value)
    out = []
    for ch in text:
        codepoint = ord(ch)
        if ch in _ALLOWED_CONTROL:
            out.append(ch)
        elif codepoint < 0x20 or codepoint == 0x7F or 0x80 <= codepoint <= 0x9F:
            out.append(f"\\x{codepoint:02x}")
        else:
            out.append(ch)
    rendered = "".join(out)
    if len(rendered) > max_len:
        rendered = rendered[:max_len] + f"... [truncated, {len(rendered)} chars total]"
    return rendered


def redact(secret: str) -> str:
    """Return a non-reversible preview of a secret for display.

    Shows enough to correlate a finding (a short prefix) without reproducing the
    credential. Short values are fully masked.
    """
    if secret is None:
        return "<none>"
    length = len(secret)
    if length <= 8:
        return "*" * length
    return f"{secret[:4]}{'*' * 6}…[{length} chars]"


# --------------------------------------------------------------------------- #
# Findings & reporting
# --------------------------------------------------------------------------- #


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @property
    def marker(self) -> str:
        return {
            Severity.INFO: "[+]",
            Severity.LOW: "[.]",
            Severity.MEDIUM: "[!]",
            Severity.HIGH: "[!!]",
        }[self]


@dataclass
class Finding:
    severity: Severity
    title: str
    detail: str = ""
    location: str = ""

    def render(self) -> str:
        parts = [f"{self.severity.marker} {sanitize(self.title)}"]
        if self.location:
            parts.append(f"    at: {sanitize(self.location)}")
        if self.detail:
            parts.append(f"    {sanitize(self.detail)}")
        return "\n".join(parts)


class Reporter:
    """Collects findings and prints them. All target-derived text is sanitized."""

    def __init__(self, stream=sys.stdout) -> None:
        self.stream = stream
        self.findings: list[Finding] = []

    def section(self, name: str) -> None:
        print(f"\n[ {name} ]", file=self.stream)

    def info(self, message: str) -> None:
        print(f"  {sanitize(message)}", file=self.stream)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)
        print(finding.render(), file=self.stream)

    def summary(self) -> None:
        print("\n" + "=" * 60, file=self.stream)
        print("SUMMARY", file=self.stream)
        print("=" * 60, file=self.stream)
        by_sev: dict[Severity, int] = {}
        for f in self.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        for sev in (Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
            if by_sev.get(sev):
                print(f"  {sev.marker} {sev.value}: {by_sev[sev]}", file=self.stream)
        if not self.findings:
            print("  No findings recorded.", file=self.stream)


# --------------------------------------------------------------------------- #
# HTTP client
# --------------------------------------------------------------------------- #


class HttpClient:
    """Thin wrapper over requests.Session with timeouts, retries and sane defaults."""

    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        verify_tls: bool = True,
        max_retries: int = 2,
        allow_redirects: bool = False,
        proxy: Optional[str] = None,
        user_agent: str = "api-security-tester/2.0",
    ) -> None:
        self.timeout = timeout
        self.allow_redirects = allow_redirects
        self.session = requests.Session()
        self.session.verify = verify_tls
        self.session.headers["User-Agent"] = user_agent
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        # Retry only transient connection/5xx failures. A read timeout is a
        # result (the server is slow/tarpitting), not something to retry: doing
        # so multiplies the per-request timeout and lets a single slow endpoint
        # stall the whole scan. read=False raises read timeouts immediately.
        retry = Retry(
            total=max_retries,
            connect=max_retries,
            read=False,
            backoff_factor=0.3,
            status_forcelist=(502, 503, 504),
            allowed_methods=frozenset({"GET", "OPTIONS", "HEAD"}),
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", self.allow_redirects)
        return self.session.request(method, url, **kwargs)

    def get(self, url: str, **kwargs) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def options(self, url: str, **kwargs) -> requests.Response:
        return self.request("OPTIONS", url, **kwargs)

    def close(self) -> None:
        self.session.close()


# --------------------------------------------------------------------------- #
# Token detection (shared by remote discovery and local discovery)
# --------------------------------------------------------------------------- #

# Each pattern captures the sensitive value in group 1 where a label prefix is
# involved, otherwise the whole match is the value.
TOKEN_PATTERNS: dict[str, re.Pattern] = {
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "github": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
    "slack": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "api_key": re.compile(
        r"api[_-]?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{20,})", re.IGNORECASE
    ),
    "bearer": re.compile(r"\bbearer\s+([A-Za-z0-9_\-.=]{20,})", re.IGNORECASE),
    "generic_secret": re.compile(
        r"(?:secret|token|password|passwd)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{16,})",
        re.IGNORECASE,
    ),
}

MIN_TOKEN_LENGTH = 16


@dataclass
class TokenHit:
    kind: str
    value: str
    source: str


def find_tokens(text: str, source: str) -> list[TokenHit]:
    """Scan arbitrary text for credential-like substrings."""
    hits: list[TokenHit] = []
    seen: set[tuple[str, str]] = set()
    for kind, pattern in TOKEN_PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(1) if match.groups() else match.group(0)
            if not value or len(value) < MIN_TOKEN_LENGTH:
                continue
            key = (kind, value)
            if key in seen:
                continue
            seen.add(key)
            hits.append(TokenHit(kind=kind, value=value, source=source))
    return hits


# --------------------------------------------------------------------------- #
# Remote scanner
# --------------------------------------------------------------------------- #

# Signatures that strongly indicate a database/driver error leaked into a
# response. Used for *differential* detection: we only flag a payload if it
# introduces one of these that the baseline response did not have.
SQL_ERROR_SIGNATURES = [
    "sql syntax",
    "syntax error at or near",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "ora-0",
    "pg::",
    "psycopg2",
    "mysqli",
    "mysql_fetch",
    "sqlite3.operationalerror",
    "odbc driver",
    "native client",
    "pdoexception",
]

SQL_PAYLOADS = ["'", "' OR '1'='1", "1' OR '1'='1' -- "]
XSS_PAYLOAD = "<script>astxss{}</script>"  # marker chosen to be reflection-unique


class RemoteScanner:
    def __init__(
        self,
        base_url: str,
        client: HttpClient,
        reporter: Reporter,
        *,
        endpoints: Optional[Sequence[str]] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.client = client
        self.reporter = reporter
        self.endpoints = list(endpoints) if endpoints else list(DEFAULT_ENDPOINTS)

    def _url(self, path: str) -> str:
        if path.startswith(("http://", "https://")):
            return path
        if not path.startswith("/"):
            path = "/" + path
        return self.base_url + path

    # -- CORS ------------------------------------------------------------- #
    def check_cors(self) -> None:
        self.reporter.section("CORS")
        probe_origin = "https://evil.example.test"
        try:
            r = self.client.get(self.base_url + "/", headers={"Origin": probe_origin})
        except requests.RequestException as exc:
            self.reporter.info(f"CORS probe failed: {exc}")
            return

        acao = r.headers.get("Access-Control-Allow-Origin")
        acac = (r.headers.get("Access-Control-Allow-Credentials") or "").lower() == "true"

        if acao is None:
            self.reporter.info("No Access-Control-Allow-Origin header (CORS not enabled for this origin).")
            return

        if acao == "*":
            sev = Severity.MEDIUM
            detail = "Wildcard origin. Any site can read responses."
            if acac:
                detail += " Allow-Credentials is also true, but browsers reject * with credentials."
            self.reporter.add(Finding(sev, "Wildcard CORS origin", detail, self.base_url))
        elif acao == probe_origin:
            sev = Severity.HIGH if acac else Severity.MEDIUM
            detail = "Server reflects an arbitrary Origin back."
            if acac:
                detail += " Allow-Credentials is true: cross-origin credentialed reads are possible."
            self.reporter.add(Finding(sev, "Reflected CORS origin", detail, self.base_url))
        elif acao.lower() == "null":
            self.reporter.add(
                Finding(Severity.MEDIUM, "CORS allows 'null' origin",
                        "Reachable from sandboxed iframes and some local files.", self.base_url)
            )
        else:
            self.reporter.info(f"Access-Control-Allow-Origin is restricted to: {acao}")

    # -- Auth ------------------------------------------------------------- #
    def check_authentication(self, token: Optional[str], scheme: str) -> None:
        self.reporter.section("Authentication")
        auth_header = self._build_auth_header(token, scheme) if token else None

        for path in self.endpoints:
            url = self._url(path)
            unauth = self._safe_status(url)
            if auth_header is None:
                if unauth is not None:
                    self.reporter.info(f"{path} => {unauth} (no token supplied)")
                continue

            authed = self._safe_status(url, headers={"Authorization": auth_header})
            if unauth is None or authed is None:
                continue

            if unauth < 400 and authed < 400 and path not in ("/", ""):
                self.reporter.add(
                    Finding(
                        Severity.MEDIUM,
                        "Endpoint reachable without authentication",
                        f"Returns {unauth} with no token and {authed} with a token.",
                        url,
                    )
                )
            else:
                self.reporter.info(f"{path} => no-token:{unauth} with-token:{authed}")

    @staticmethod
    def _build_auth_header(token: str, scheme: str) -> str:
        """Build an Authorization header without double-prefixing the scheme.

        Accepts a bare credential ("abc123"), or a full value already carrying a
        scheme ("Bearer abc123" / "Basic ...") and does not add a second scheme.
        """
        token = token.strip()
        first = token.split(" ", 1)[0].lower()
        known = {"bearer", "basic", "token", "digest", "negotiate"}
        if first in known:
            return token
        return f"{scheme} {token}"

    def _safe_status(self, url: str, **kwargs) -> Optional[int]:
        try:
            return self.client.get(url, **kwargs).status_code
        except requests.RequestException as exc:
            self.reporter.info(f"request to {url} failed: {exc}")
            return None

    # -- Rate limiting ---------------------------------------------------- #
    def check_rate_limit(self, path: str = "/", attempts: int = 20) -> None:
        self.reporter.section("Rate Limiting")
        url = self._url(path)
        saw_429 = False
        completed = 0
        for i in range(attempts):
            try:
                r = self.client.get(url)
            except requests.RequestException as exc:
                self.reporter.info(f"attempt {i + 1} failed: {exc}")
                break
            completed += 1
            if r.status_code == 429:
                saw_429 = True
                self.reporter.add(
                    Finding(Severity.INFO, "Rate limiting is active",
                            f"Received 429 after {i + 1} requests.", url)
                )
                break
        if not saw_429:
            # Absence of a 429 in a short burst is NOT proof of a vulnerability.
            self.reporter.info(
                f"No 429 seen in {completed} rapid requests. This is inconclusive, "
                "not a confirmed lack of rate limiting."
            )

    # -- Injection heuristics -------------------------------------------- #
    def _new_sql_signatures(self, baseline: str, candidate: str) -> list[str]:
        base = baseline.lower()
        cand = candidate.lower()
        return [s for s in SQL_ERROR_SIGNATURES if s in cand and s not in base]

    def check_sql_injection(self, param: str = "id") -> None:
        self.reporter.section("SQL Injection (differential)")
        for path in self.endpoints:
            url = self._url(path)
            try:
                baseline = self.client.get(url, params={param: "baseline123"})
            except requests.RequestException:
                continue
            base_text = baseline.text
            base_status = baseline.status_code

            for payload in SQL_PAYLOADS:
                try:
                    r = self.client.get(url, params={param: payload})
                except requests.RequestException:
                    continue
                new_sigs = self._new_sql_signatures(base_text, r.text)
                if new_sigs:
                    self.reporter.add(
                        Finding(
                            Severity.HIGH,
                            "Possible SQL injection (database error surfaced)",
                            f"Payload introduced DB error signature(s): {', '.join(new_sigs)}.",
                            url,
                        )
                    )
                    break
                if base_status < 500 and r.status_code >= 500:
                    self.reporter.add(
                        Finding(
                            Severity.MEDIUM,
                            "Payload triggered a server error",
                            f"Baseline {base_status} -> {r.status_code} with an injection payload. Investigate.",
                            url,
                        )
                    )
                    break

    def check_reflected_xss(self, param: str = "q") -> None:
        self.reporter.section("Reflected XSS")
        marker = str(int(time.time() * 1000) % 100000)
        payload = XSS_PAYLOAD.format(marker)
        for path in self.endpoints:
            url = self._url(path)
            try:
                r = self.client.get(url, params={param: payload})
            except requests.RequestException:
                continue
            ctype = (r.headers.get("Content-Type") or "").lower()
            if payload in r.text:
                if "html" in ctype:
                    self.reporter.add(
                        Finding(
                            Severity.HIGH,
                            "Reflected, unescaped input in an HTML response",
                            "Payload was returned verbatim with an HTML content type.",
                            url,
                        )
                    )
                else:
                    self.reporter.info(
                        f"{path}: input reflected, but content type is '{ctype or 'unknown'}' "
                        "(not HTML, so not directly XSS-exploitable)."
                    )

    # -- Security headers ------------------------------------------------- #
    def check_security_headers(self) -> None:
        self.reporter.section("Security Headers")
        try:
            r = self.client.get(self.base_url + "/")
        except requests.RequestException as exc:
            self.reporter.info(f"header probe failed: {exc}")
            return
        expected = {
            "X-Content-Type-Options": Severity.LOW,
            "Content-Security-Policy": Severity.LOW,
            "X-Frame-Options": Severity.LOW,
        }
        if self.base_url.startswith("https://"):
            expected["Strict-Transport-Security"] = Severity.MEDIUM
        for header, sev in expected.items():
            if header not in r.headers:
                self.reporter.add(
                    Finding(sev, f"Missing security header: {header}", "", self.base_url)
                )

    # -- Token leakage in responses -------------------------------------- #
    def check_response_token_leaks(self, show_secrets: bool) -> None:
        self.reporter.section("Token Leakage in Responses")
        for path in self.endpoints:
            url = self._url(path)
            try:
                r = self.client.get(url)
            except requests.RequestException:
                continue
            blob = r.text + "\n" + "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            for hit in find_tokens(blob, url):
                shown = hit.value if show_secrets else redact(hit.value)
                self.reporter.add(
                    Finding(
                        Severity.HIGH,
                        f"{hit.kind} credential exposed in response",
                        f"value: {shown}",
                        url,
                    )
                )

    def run(self, *, token: Optional[str], scheme: str, show_secrets: bool) -> None:
        print(f"Scanning: {sanitize(self.base_url)}")
        self.check_cors()
        self.check_security_headers()
        self.check_authentication(token, scheme)
        self.check_rate_limit()
        self.check_sql_injection()
        self.check_reflected_xss()
        self.check_response_token_leaks(show_secrets)
        self.reporter.summary()


# --------------------------------------------------------------------------- #
# OpenAPI
# --------------------------------------------------------------------------- #


def parse_openapi(url: str, client: HttpClient, reporter: Reporter) -> list[str]:
    reporter.section("OpenAPI")
    try:
        r = client.get(url, allow_redirects=True)
    except requests.RequestException as exc:
        reporter.info(f"failed to fetch spec: {exc}")
        return []
    if r.status_code != 200:
        reporter.info(f"spec fetch returned {r.status_code}")
        return []
    try:
        spec = r.json()
    except ValueError:
        reporter.info("spec was not valid JSON (YAML specs are not parsed here)")
        return []
    paths = list((spec.get("paths") or {}).keys())
    reporter.info(f"found {len(paths)} path(s) in spec")
    for p in paths:
        reporter.info(f"  - {p}")
    return paths


# --------------------------------------------------------------------------- #
# JWT inspection
# --------------------------------------------------------------------------- #


def inspect_jwt(token: str, reporter: Reporter) -> bool:
    reporter.section("JWT Inspection")
    if jwt is None:
        reporter.info("PyJWT is not installed; cannot decode.")
        return False
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
    except Exception as exc:  # jwt.PyJWTError and friends
        reporter.add(Finding(Severity.LOW, "Not a decodable JWT", str(exc)))
        return False

    reporter.info(f"header: {json.dumps(header)}")
    # Never print the full payload blindly; it may carry PII. Print claim keys.
    reporter.info(f"payload claims: {', '.join(sorted(payload.keys())) or '(none)'}")

    alg = str(header.get("alg", "")).lower()
    if alg == "none":
        reporter.add(
            Finding(Severity.HIGH, "JWT uses alg=none",
                    "Token is unsigned; signature verification can be bypassed.")
        )
    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        if exp < time.time():
            reporter.add(Finding(Severity.INFO, "JWT is expired"))
        else:
            reporter.info("JWT is within its expiry window.")
    return True


# --------------------------------------------------------------------------- #
# Local secret discovery (opt-in, separate subcommand)
# --------------------------------------------------------------------------- #

LOCAL_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
LOCAL_EXTENSIONS = {".js", ".ts", ".json", ".env", ".config", ".yaml", ".yml", ".txt", ".ini", ".toml"}
MAX_LOCAL_FILE_BYTES = 2_000_000


def discover_local_secrets(
    reporter: Reporter,
    *,
    paths: Sequence[str],
    include_env: bool,
    include_home_configs: bool,
    show_secrets: bool,
) -> list[TokenHit]:
    """Scan local disk/env for exposed credentials. Opt-in only.

    This is deliberately isolated from remote scanning: pointing the tool at a
    remote URL must never trigger a crawl of your own machine.
    """
    print("=" * 60)
    print("LOCAL SECRET DISCOVERY")
    print("This inspects local files/env on THIS machine, not the remote target.")
    print("=" * 60)

    hits: list[TokenHit] = []

    if include_env:
        reporter.section("Environment Variables")
        for key, value in os.environ.items():
            if any(w in key.lower() for w in ("token", "key", "secret", "auth", "pass")):
                hits.extend(find_tokens(value, f"env:{key}"))

    if include_home_configs:
        reporter.section("Common Config Locations")
        home_files = [
            os.path.expanduser("~/.aws/credentials"),
            os.path.expanduser("~/.ssh/config"),
            os.path.expanduser("~/.gitconfig"),
            os.path.expanduser("~/.npmrc"),
        ]
        for fp in home_files:
            hits.extend(_scan_file(fp, reporter))

    reporter.section("File Tree")
    for root_path in paths:
        if not os.path.exists(root_path):
            reporter.info(f"path does not exist: {root_path}")
            continue
        if os.path.isfile(root_path):
            hits.extend(_scan_file(root_path, reporter))
            continue
        for root, dirs, files in os.walk(root_path):
            dirs[:] = [d for d in dirs if d not in LOCAL_SKIP_DIRS]
            for name in files:
                if any(name.endswith(ext) for ext in LOCAL_EXTENSIONS) or name.startswith(".env"):
                    hits.extend(_scan_file(os.path.join(root, name), reporter))

    reporter.section("Discovery Results")
    if not hits:
        reporter.info("No credential-like strings found.")
    for hit in hits:
        shown = hit.value if show_secrets else redact(hit.value)
        reporter.add(
            Finding(Severity.HIGH, f"{hit.kind} found in {hit.source}", f"value: {shown}")
        )
    return hits


def _scan_file(path: str, reporter: Reporter) -> list[TokenHit]:
    try:
        if os.path.getsize(path) > MAX_LOCAL_FILE_BYTES:
            return []
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    except (OSError, ValueError):
        return []
    return find_tokens(content, f"file:{path}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _validate_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        raise argparse.ArgumentTypeError("URL must start with http:// or https://")
    return url


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="api_security_tester",
        description="Defensive API security scanner. Use only on systems you are authorized to test.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    p_scan = sub.add_parser("scan", help="Scan a remote API (never touches local disk).")
    p_scan.add_argument("url", type=_validate_url, help="Target base URL, e.g. https://api.example.com")
    p_scan.add_argument("--token", "-t", help="Auth credential (bare, or a full 'Scheme value').")
    p_scan.add_argument("--auth-scheme", default="Bearer", help="Scheme to prepend to a bare token (default: Bearer).")
    p_scan.add_argument("--endpoints", "-e", nargs="+", help="Endpoints to test (default: / /login /api /admin).")
    p_scan.add_argument("--openapi", "-o", help="OpenAPI spec URL; discovered paths are added to the scan.")
    p_scan.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-request timeout seconds.")
    p_scan.add_argument("--insecure", action="store_true", help="Disable TLS verification (testing only).")
    p_scan.add_argument("--follow-redirects", action="store_true", help="Follow HTTP redirects.")
    p_scan.add_argument("--proxy", help="Proxy URL, e.g. http://127.0.0.1:8080")
    p_scan.add_argument("--show-secrets", action="store_true", help="Print full credential values (default: redacted).")

    # discover-local
    p_local = sub.add_parser("discover-local", help="Scan THIS machine for exposed secrets (opt-in).")
    p_local.add_argument("--paths", nargs="+", default=["."], help="Paths to scan (default: current directory).")
    p_local.add_argument("--include-env", action="store_true", help="Also scan environment variables.")
    p_local.add_argument("--include-home-configs", action="store_true", help="Also scan ~/.aws, ~/.ssh, ~/.gitconfig, ~/.npmrc.")
    p_local.add_argument("--show-secrets", action="store_true", help="Print full credential values (default: redacted).")

    # jwt
    p_jwt = sub.add_parser("jwt", help="Decode and inspect a JWT (no signature verification).")
    p_jwt.add_argument("token", help="The JWT string.")

    return parser


def run_scan(args: argparse.Namespace) -> int:
    reporter = Reporter()
    client = HttpClient(
        timeout=args.timeout,
        verify_tls=not args.insecure,
        allow_redirects=args.follow_redirects,
        proxy=args.proxy,
    )
    try:
        endpoints = list(args.endpoints) if args.endpoints else list(DEFAULT_ENDPOINTS)
        if args.openapi:
            endpoints += parse_openapi(args.openapi, client, reporter)
        scanner = RemoteScanner(args.url, client, reporter, endpoints=endpoints)
        scanner.run(token=args.token, scheme=args.auth_scheme, show_secrets=args.show_secrets)
    finally:
        client.close()
    return 0


def run_discover_local(args: argparse.Namespace) -> int:
    reporter = Reporter()
    discover_local_secrets(
        reporter,
        paths=args.paths,
        include_env=args.include_env,
        include_home_configs=args.include_home_configs,
        show_secrets=args.show_secrets,
    )
    reporter.summary()
    return 0


def run_jwt(args: argparse.Namespace) -> int:
    reporter = Reporter()
    ok = inspect_jwt(args.token, reporter)
    return 0 if ok else 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return run_scan(args)
        if args.command == "discover-local":
            return run_discover_local(args)
        if args.command == "jwt":
            return run_jwt(args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user", file=sys.stderr)
        return 130
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
