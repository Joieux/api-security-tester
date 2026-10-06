"""Regression tests for api_security_tester.

Every confirmed defect in the original tool has a named test here so a
regression is caught immediately. Network tests run against a local mock HTTP
server (no external calls).
"""

from __future__ import annotations

import http.server
import threading
from contextlib import contextmanager

import pytest

import api_security_tester as ast


# --------------------------------------------------------------------------- #
# Mock server
# --------------------------------------------------------------------------- #


class _MockHandler(http.server.BaseHTTPRequestHandler):
    # Set per-server via the `config` class attr injected in the fixture.
    config: dict = {}

    def log_message(self, *args):  # silence
        pass

    def _record(self):
        _MockHandler.config.setdefault("requests", []).append(
            {"path": self.path, "authorization": self.headers.get("Authorization")}
        )

    def do_OPTIONS(self):
        self.do_GET()

    def do_GET(self):
        self._record()
        cfg = _MockHandler.config
        import urllib.parse
        path_only = self.path.split("?", 1)[0]
        raw_query = self.path.split("?", 1)[1] if "?" in self.path else ""
        query = urllib.parse.unquote_plus(raw_query)

        status = 200
        # Auth gating: /admin requires a token unless configured open.
        if path_only == "/admin" and not cfg.get("admin_open") and not self.headers.get("Authorization"):
            status = 401

        body = cfg.get("body", '{"status":"ok","message":"no error here"}')

        # Emulate a SQL error only when a quote-bearing payload arrives AND the
        # server is configured vulnerable.
        if cfg.get("sql_vulnerable") and "'" in query:
            body = "Error: You have an SQL syntax error near '1'"
            status = 500
        # Reflect the q parameter when configured (for XSS tests).
        if cfg.get("reflect_q") and "q=" in query:
            import urllib.parse
            params = urllib.parse.parse_qs(query)
            body = "<html>" + params.get("q", [""])[0] + "</html>"

        encoded = body.encode()
        self.send_response(status)
        ctype = cfg.get("content_type", "application/json")
        if cfg.get("reflect_q") and "q=" in query:
            ctype = cfg.get("reflect_content_type", "text/html")
        self.send_header("Content-Type", ctype)
        for k, v in cfg.get("extra_headers", {}).items():
            self.send_header(k, v)
        # CORS behavior
        cors = cfg.get("cors")
        if cors == "wildcard":
            self.send_header("Access-Control-Allow-Origin", "*")
        elif cors == "reflect":
            origin = self.headers.get("Origin", "")
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


@contextmanager
def mock_server(**config):
    _MockHandler.config = dict(config)
    _MockHandler.config["requests"] = []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _MockHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}", _MockHandler.config
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def client():
    c = ast.HttpClient(timeout=3.0)
    yield c
    c.close()


# --------------------------------------------------------------------------- #
# Output safety
# --------------------------------------------------------------------------- #


def test_sanitize_escapes_ansi_escape_sequence():
    # Regression: original printed raw target bytes, allowing terminal injection.
    malicious = "\x1b[31mRED\x1b[0m\x07\r"
    out = ast.sanitize(malicious)
    assert "\x1b" not in out
    assert "\x07" not in out
    assert "\\x1b" in out
    assert "RED" in out


def test_sanitize_keeps_newline_and_tab_and_unicode():
    assert ast.sanitize("a\nb\tç") == "a\nb\tç"


def test_sanitize_truncates():
    out = ast.sanitize("x" * 5000, max_len=100)
    assert out.startswith("x" * 100)
    assert "truncated" in out


def test_redact_masks_secret():
    r = ast.redact("AKIAIOSFODNN7EXAMPLE")
    assert "AKIA" in r
    assert "IOSFODNN7EXAMPLE" not in r
    assert "chars" in r


def test_redact_short_value_fully_masked():
    assert ast.redact("abc123") == "*" * 6


def test_finding_render_is_sanitized():
    f = ast.Finding(ast.Severity.HIGH, "title\x1bX", "detail", "loc")
    assert "\x1b" not in f.render()


# --------------------------------------------------------------------------- #
# HTTP client
# --------------------------------------------------------------------------- #


def test_client_sets_default_timeout(monkeypatch, client):
    captured = {}

    def fake_request(method, url, **kwargs):
        captured.update(kwargs)

        class R:  # minimal stub
            status_code = 200

        return R()

    monkeypatch.setattr(client.session, "request", fake_request)
    client.get("http://example.test")
    assert captured["timeout"] == client.timeout  # regression: no infinite hang


def test_client_default_no_redirect(client):
    assert client.allow_redirects is False


# --------------------------------------------------------------------------- #
# Auth header construction (double-Bearer regression)
# --------------------------------------------------------------------------- #


def test_auth_header_bare_token_gets_scheme():
    assert ast.RemoteScanner._build_auth_header("abc123", "Bearer") == "Bearer abc123"


def test_auth_header_does_not_double_prefix():
    # Regression: original produced "Bearer Bearer abc123".
    assert ast.RemoteScanner._build_auth_header("Bearer abc123", "Bearer") == "Bearer abc123"
    assert ast.RemoteScanner._build_auth_header("bearer abc123", "Bearer") == "bearer abc123"


def test_auth_header_preserves_other_schemes():
    assert ast.RemoteScanner._build_auth_header("Basic dXNlcg==", "Bearer") == "Basic dXNlcg=="


def test_authentication_sends_single_scheme(client):
    with mock_server(admin_open=True) as (url, cfg):
        rep = ast.Reporter()
        scanner = ast.RemoteScanner(url, client, rep, endpoints=["/"])
        scanner.check_authentication("sometoken123", "Bearer")
    auths = [r["authorization"] for r in cfg["requests"] if r["authorization"]]
    assert auths, "expected at least one authenticated request"
    assert all(a == "Bearer sometoken123" for a in auths)
    assert not any("Bearer Bearer" in a for a in auths)


# --------------------------------------------------------------------------- #
# CORS
# --------------------------------------------------------------------------- #


def test_cors_wildcard_flagged(client):
    with mock_server(cors="wildcard") as (url, _):
        rep = ast.Reporter()
        ast.RemoteScanner(url, client, rep).check_cors()
    assert any("Wildcard" in f.title for f in rep.findings)


def test_cors_reflected_origin_is_high(client):
    with mock_server(cors="reflect") as (url, _):
        rep = ast.Reporter()
        ast.RemoteScanner(url, client, rep).check_cors()
    reflected = [f for f in rep.findings if "Reflected" in f.title]
    assert reflected
    assert reflected[0].severity == ast.Severity.HIGH  # credentials + reflection


def test_cors_restricted_no_finding(client):
    with mock_server() as (url, _):
        rep = ast.Reporter()
        ast.RemoteScanner(url, client, rep).check_cors()
    assert not rep.findings


# --------------------------------------------------------------------------- #
# SQL injection (differential — no false positives)
# --------------------------------------------------------------------------- #


def test_sqli_no_false_positive_on_benign_error_text(client):
    # Regression: original flagged any response containing "error".
    with mock_server(body='{"message":"no error occurred"}') as (url, _):
        rep = ast.Reporter()
        ast.RemoteScanner(url, client, rep, endpoints=["/"]).check_sql_injection()
    assert not any("SQL" in f.title for f in rep.findings)


def test_sqli_detected_when_db_error_surfaces(client):
    with mock_server(sql_vulnerable=True) as (url, _):
        rep = ast.Reporter()
        ast.RemoteScanner(url, client, rep, endpoints=["/"]).check_sql_injection()
    assert any("SQL injection" in f.title for f in rep.findings)


# --------------------------------------------------------------------------- #
# XSS (content-type gated)
# --------------------------------------------------------------------------- #


def test_xss_flagged_only_for_html(client):
    with mock_server(reflect_q=True, reflect_content_type="text/html") as (url, _):
        rep = ast.Reporter()
        ast.RemoteScanner(url, client, rep, endpoints=["/"]).check_reflected_xss()
    assert any("HTML response" in f.title for f in rep.findings)


def test_xss_not_flagged_for_json(client):
    with mock_server(reflect_q=True, reflect_content_type="application/json") as (url, _):
        rep = ast.Reporter()
        ast.RemoteScanner(url, client, rep, endpoints=["/"]).check_reflected_xss()
    assert not any(f.severity == ast.Severity.HIGH for f in rep.findings)


# --------------------------------------------------------------------------- #
# Security headers
# --------------------------------------------------------------------------- #


def test_missing_security_headers_flagged(client):
    with mock_server() as (url, _):
        rep = ast.Reporter()
        ast.RemoteScanner(url, client, rep).check_security_headers()
    titles = " ".join(f.title for f in rep.findings)
    assert "X-Content-Type-Options" in titles


def test_present_security_headers_not_flagged(client):
    headers = {
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
    }
    with mock_server(extra_headers=headers) as (url, _):
        rep = ast.Reporter()
        ast.RemoteScanner(url, client, rep).check_security_headers()
    assert not rep.findings


# --------------------------------------------------------------------------- #
# Token detection
# --------------------------------------------------------------------------- #


def test_find_tokens_detects_aws_and_github():
    text = "AKIAIOSFODNN7EXAMPLE and ghp_" + "a" * 36
    hits = ast.find_tokens(text, "unit")
    kinds = {h.kind for h in hits}
    assert "aws_access_key" in kinds
    assert "github" in kinds


def test_find_tokens_ignores_short_values():
    assert ast.find_tokens("api_key=short", "unit") == []


def test_response_token_leak_redacts_by_default(client):
    body = '{"leaked":"AKIAIOSFODNN7EXAMPLE"}'
    with mock_server(body=body) as (url, _):
        rep = ast.Reporter()
        ast.RemoteScanner(url, client, rep, endpoints=["/"]).check_response_token_leaks(show_secrets=False)
    leaks = [f for f in rep.findings if "credential exposed" in f.title]
    assert leaks
    assert "AKIAIOSFODNN7EXAMPLE" not in leaks[0].detail
    assert "AKIA" in leaks[0].detail


# --------------------------------------------------------------------------- #
# Local discovery is opt-in and isolated from remote scan
# --------------------------------------------------------------------------- #


def test_scan_does_not_read_local_disk(client, tmp_path, monkeypatch):
    # A remote scan must never invoke local discovery.
    called = {"local": False}
    monkeypatch.setattr(
        ast, "discover_local_secrets", lambda *a, **k: called.__setitem__("local", True)
    )
    with mock_server() as (url, _):
        scanner = ast.RemoteScanner(url, client, ast.Reporter(), endpoints=["/"])
        scanner.run(token=None, scheme="Bearer", show_secrets=False)
    assert called["local"] is False


def test_discover_local_finds_secret_in_file(tmp_path):
    secret_file = tmp_path / "config.json"
    secret_file.write_text('{"api_key": "' + "k" * 30 + '"}')
    rep = ast.Reporter()
    hits = ast.discover_local_secrets(
        rep, paths=[str(tmp_path)], include_env=False,
        include_home_configs=False, show_secrets=False,
    )
    assert any(h.kind == "api_key" for h in hits)


def test_discover_local_env_opt_in(tmp_path, monkeypatch):
    monkeypatch.setenv("MY_SECRET_TOKEN", "ghp_" + "b" * 36)
    rep = ast.Reporter()
    # Without include_env, env is not scanned.
    hits = ast.discover_local_secrets(
        rep, paths=[str(tmp_path)], include_env=False,
        include_home_configs=False, show_secrets=False,
    )
    assert not any(h.source.startswith("env:") for h in hits)
    # With include_env, it is.
    hits = ast.discover_local_secrets(
        rep, paths=[str(tmp_path)], include_env=True,
        include_home_configs=False, show_secrets=False,
    )
    assert any(h.source.startswith("env:") for h in hits)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def test_cli_rejects_bad_url():
    with pytest.raises(SystemExit):
        ast.build_parser().parse_args(["scan", "ftp://nope"])


def test_cli_scan_parses():
    args = ast.build_parser().parse_args(["scan", "https://api.example.com", "-t", "abc"])
    assert args.command == "scan"
    assert args.token == "abc"


def test_cli_requires_subcommand():
    with pytest.raises(SystemExit):
        ast.build_parser().parse_args([])


# --------------------------------------------------------------------------- #
# JWT
# --------------------------------------------------------------------------- #


def test_jwt_alg_none_flagged():
    pytest.importorskip("jwt")
    import jwt as pyjwt
    token = pyjwt.encode({"sub": "x", "exp": 9999999999}, key="", algorithm="none")
    rep = ast.Reporter()
    ast.inspect_jwt(token, rep)
    assert any("alg=none" in f.title for f in rep.findings)


def test_jwt_invalid_string():
    rep = ast.Reporter()
    assert ast.inspect_jwt("not-a-jwt", rep) is False
