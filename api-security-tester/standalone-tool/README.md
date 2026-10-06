# API Security Tester — Standalone Tool

A command-line defensive scanner for APIs you own or are explicitly authorized to test.

This is a rewrite focused on **safe defaults** and **honest findings**. Three principles drive the design:

- **Scanning a remote URL never reads your local machine.** Local secret discovery is a separate, opt-in subcommand.
- **Output is safe.** Everything the target sends back (bodies, headers, token material) is sanitized before printing, so a hostile server can't inject terminal escape sequences, and discovered secrets are redacted unless you ask for them.
- **Findings are differential.** "SQL injection" means a payload changed the server's behavior versus a baseline, not that the word *error* appeared somewhere.

## Install

```bash
cd standalone-tool
pip install -r requirements.txt
```

Requires Python 3.9+, `requests`, and `PyJWT`.

## Usage

The tool has three subcommands: `scan`, `discover-local`, and `jwt`.

### Scan a remote API

```bash
python api_security_tester.py scan https://api.example.com
```

With an auth token (pass the bare credential — the tool adds the scheme, and will **not** double-prefix if you include one):

```bash
python api_security_tester.py scan https://api.example.com --token "abc123"
python api_security_tester.py scan https://api.example.com --token "Bearer abc123"   # also fine
```

Common options:

| Option | Purpose |
| --- | --- |
| `--endpoints / /users /admin` | Endpoints to test (default: `/ /login /api /admin`) |
| `--openapi URL` | Fetch an OpenAPI spec and add its paths to the scan |
| `--auth-scheme Bearer` | Scheme to prepend to a bare token |
| `--timeout 10` | Per-request timeout in seconds (every request is bounded) |
| `--insecure` | Disable TLS verification (testing only) |
| `--follow-redirects` | Follow HTTP redirects (off by default) |
| `--proxy http://127.0.0.1:8080` | Route through a proxy |
| `--show-secrets` | Print full credential values (redacted by default) |

### What the scan checks

1. **CORS** — wildcard `*`, reflected arbitrary origin (High when combined with `Allow-Credentials`), and `null` origin.
2. **Security headers** — missing `X-Content-Type-Options`, `Content-Security-Policy`, `X-Frame-Options`, and (for HTTPS targets) `Strict-Transport-Security`.
3. **Authentication** — compares each endpoint's response with and without a token to spot endpoints reachable unauthenticated.
4. **Rate limiting** — a short burst; absence of a `429` is reported as *inconclusive*, not as a confirmed gap.
5. **SQL injection** — differential: only flags a payload that introduces a database error signature the baseline didn't have, or turns a non-5xx into a 5xx.
6. **Reflected XSS** — only flags reflected input when the response content type is HTML.
7. **Token leakage** — scans responses for credential-like strings (JWT, API keys, AWS/GitHub/Slack tokens).

### Discover secrets on the local machine (opt-in)

This is deliberately **separate** from `scan`, so pointing the tool at a remote URL never crawls your own disk.

```bash
# Scan the current directory only; secrets are redacted:
python api_security_tester.py discover-local --paths .

# Also include environment variables and common home-dir config files:
python api_security_tester.py discover-local --paths ./src --include-env --include-home-configs
```

Add `--show-secrets` only if you genuinely need the raw values printed.

### Inspect a JWT

```bash
python api_security_tester.py jwt "eyJhbGciOi..."
```

Decodes (without verifying the signature), lists the claim keys (not their values, to avoid printing PII), and flags `alg=none` and expiry.

## Output markers

- `[+]` informational / good practice
- `[.]` low-severity finding
- `[!]` medium-severity finding
- `[!!]` high-severity finding

## Tests

```bash
pip install pytest
python -m pytest
```

The suite runs against a local mock server (no external calls) and includes a named regression test for every bug this rewrite fixes.

## Ethical use

For defensive security only. Test your own APIs, or systems you have explicit written authorization to assess. **Do not use this against systems you do not own or lack permission to test.**
