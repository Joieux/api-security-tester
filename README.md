# API Security Tester - Standalone Tool

A command-line Python tool for API security testing with token discovery and vulnerability detection.

## Features

- **CORS Testing**: Detects wildcard CORS headers and misconfigurations
- **Authentication Testing**: Tests endpoints with various token states
- **Token Discovery**: Scans for exposed tokens in multiple locations
- **Rate Limiting**: Tests for proper rate limiting implementation
- **Vulnerability Testing**: Basic SQL injection and XSS detection
- **OpenAPI Support**: Parse and test endpoints from OpenAPI specifications
- **JWT Validation**: Decode and validate JWT tokens

## Installation

### Clone the Repository
```bash
git clone https://github.com/your-username/api-security-tester.git
cd api-security-tester/standalone-tool
```

### Install Dependencies
```bash
pip install -r requirements.txt
```

## Requirements

- Python 3.6+
- requests
- PyJWT

## Usage

### Basic Security Scan
```bash
python api_security_tester.py https://api.example.com
```

### With Authentication Token
```bash
python api_security_tester.py https://api.example.com --token "Bearer abc123"
```

### Token Discovery Only
```bash
python api_security_tester.py https://api.example.com --token-discovery
```

### Custom Endpoints
```bash
python api_security_tester.py https://api.example.com --endpoints /users /admin /health
```

### With OpenAPI Specification
```bash
python api_security_tester.py https://api.example.com --openapi https://api.example.com/swagger.json
```

## Command Line Options

- `url`: Target API base URL (required)
- `--token, -t`: Authentication token to test with
- `--openapi, -o`: OpenAPI specification URL
- `--token-discovery, -d`: Run token discovery only
- `--endpoints, -e`: Custom endpoints to test

## Token Discovery

The tool can discover tokens in various locations:

- API responses and headers
- Environment variables
- Configuration files (.env, config.json, etc.)
- Local files (JavaScript, JSON, YAML, etc.)
- Common config locations (~/.aws/credentials, ~/.ssh/config, etc.)

### Supported Token Types

- JWT tokens
- API keys
- Bearer tokens
- GitHub tokens
- Slack tokens
- AWS access keys
- Generic secrets

## Security Tests

1. **CORS Check**: Identifies wildcard CORS headers
2. **Authentication Testing**: Tests endpoints with different token states
3. **Token Variants**: Tests expired, tampered, and valid tokens
4. **Rate Limiting**: Attempts to trigger rate limits
5. **Common Vulnerabilities**: Basic SQL injection and XSS testing
6. **Token Discovery**: Scans for exposed tokens

## Output

The tool provides detailed output for each test:

- `[+]` Indicates a positive finding or good security practice
- `[!]` Indicates a potential security issue
- `[x]` Indicates an error or failed test

## Ethical Use

This tool is designed for defensive security purposes only. Use it to:

- Test your own APIs
- Conduct authorized security assessments
- Identify potential security issues in development

**Do not use this tool against systems you do not own or do not have explicit permission to test.**