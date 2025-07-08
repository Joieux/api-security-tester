import requests
import time
import jwt  # pip install PyJWT
import json
import re
import os

class APISecurityTester:
    def __init__(self, base_url, openapi_url=None):
        self.base_url = base_url.rstrip("/")
        self.test_endpoints = ["/", "/login", "/api", "/admin"]
        self.openapi_url = openapi_url
        self.token_patterns = {
            'jwt': r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
            'api_key': r'[aA][pP][iI][_-]?[kK][eE][yY][_-]?[:\s=][\s]*[\'"]?([A-Za-z0-9_-]{20,})[\'"]?',
            'bearer': r'[bB][eE][aA][rR][eE][rR][\s]+([A-Za-z0-9_-]{20,})',
            'github': r'gh[pousr]_[A-Za-z0-9_]{36}',
            'slack': r'xox[baprs]-[A-Za-z0-9_-]{10,}',
            'aws_access': r'AKIA[0-9A-Z]{16}',
            'generic_secret': r'[sS][eE][cC][rR][eE][tT][_-]?[:\s=][\s]*[\'"]?([A-Za-z0-9_-]{20,})[\'"]?'
        }

    def check_cors(self):
        print("\n[ CORS Check ]")
        try:
            r = requests.options(self.base_url)
            cors = r.headers.get("Access-Control-Allow-Origin")
            if cors == "*":
                print("[!] Wildcard CORS header found: *")
            else:
                print("[+] CORS seems restricted:", cors)
        except Exception as e:
            print(f"[x] Failed to check CORS: {e}")

    def test_authentication(self, token=None):
        print("\n[ Auth Token Testing ]")
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        for path in self.test_endpoints:
            url = self.base_url + path
            try:
                r = requests.get(url, headers=headers)
                print(f"{url} => {r.status_code}")
            except Exception as e:
                print(f"[x] Failed to hit {url}: {e}")

    def test_token_variants(self, valid_token):
        print("\n[ Token Variant Testing ]")

        # No token
        self.test_authentication(token=None)

        # Expired token
        expired = jwt.encode({"sub": "test", "exp": 1}, "secret", algorithm="HS256")
        self.test_authentication(token=expired)

        # Tampered token
        parts = valid_token.split('.')
        if len(parts) == 3:
            tampered = parts[0] + '.' + parts[1] + '.' + "tampered"
            self.test_authentication(token=tampered)

        # Valid token
        self.test_authentication(token=valid_token)

    def test_rate_limit(self, path="/"):
        print("\n[ Rate Limit Test ]")
        url = self.base_url + path
        print(f"Sending rapid requests to {url}...")
        for i in range(10):
            r = requests.get(url)
            print(f"Attempt {i+1}: {r.status_code}")
            if r.status_code == 429:
                print("[+] Rate limit triggered.")
                break
            time.sleep(0.2)

    def parse_openapi(self):
        print("\n[ OpenAPI Parsing ]")
        if not self.openapi_url:
            print("[!] No OpenAPI URL provided")
            return
        
        try:
            r = requests.get(self.openapi_url)
            if r.status_code == 200:
                spec = r.json()
                paths = spec.get("paths", {})
                print(f"[+] Found {len(paths)} endpoints in OpenAPI spec")
                for path in paths.keys():
                    print(f"  - {path}")
            else:
                print(f"[x] Failed to fetch OpenAPI spec: {r.status_code}")
        except Exception as e:
            print(f"[x] Error parsing OpenAPI: {e}")

    def test_common_vulnerabilities(self):
        print("\n[ Common Vulnerability Tests ]")
        
        # Test for SQL injection
        sql_payloads = ["' OR '1'='1", "'; DROP TABLE users; --", "1' UNION SELECT 1,2,3--"]
        for payload in sql_payloads:
            for endpoint in self.test_endpoints:
                url = f"{self.base_url}{endpoint}?id={payload}"
                try:
                    r = requests.get(url)
                    if "error" in r.text.lower() or "sql" in r.text.lower():
                        print(f"[!] Potential SQL injection at {url}")
                except Exception:
                    pass

        # Test for XSS
        xss_payload = "<script>alert('XSS')</script>"
        for endpoint in self.test_endpoints:
            url = f"{self.base_url}{endpoint}?q={xss_payload}"
            try:
                r = requests.get(url)
                if xss_payload in r.text:
                    print(f"[!] Potential XSS at {url}")
            except Exception:
                pass

    def find_tokens_in_text(self, text, source="unknown"):
        print(f"\n[ Token Search in {source} ]")
        found_tokens = []
        
        for token_type, pattern in self.token_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                token_value = match if isinstance(match, str) else match[0] if match else None
                if token_value and len(token_value) > 15:
                    found_tokens.append({
                        'type': token_type,
                        'value': token_value,
                        'source': source
                    })
                    print(f"[!] Found {token_type} token: {token_value[:20]}...")
        
        return found_tokens

    def find_tokens_in_responses(self):
        print("\n[ Token Discovery in API Responses ]")
        all_tokens = []
        
        for endpoint in self.test_endpoints:
            url = self.base_url + endpoint
            try:
                r = requests.get(url)
                tokens = self.find_tokens_in_text(r.text, f"Response from {endpoint}")
                all_tokens.extend(tokens)
                
                # Check headers too
                headers_text = str(r.headers)
                header_tokens = self.find_tokens_in_text(headers_text, f"Headers from {endpoint}")
                all_tokens.extend(header_tokens)
                
            except Exception as e:
                print(f"[x] Failed to check {url}: {e}")
        
        return all_tokens

    def find_tokens_in_files(self, search_paths=['.'], extensions=['.js', '.json', '.env', '.config', '.yaml', '.yml', '.txt']):
        print("\n[ Token Discovery in Local Files ]")
        all_tokens = []
        
        for search_path in search_paths:
            if not os.path.exists(search_path):
                continue
                
            for root, dirs, files in os.walk(search_path):
                # Skip common directories that shouldn't contain tokens
                dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '.env', '__pycache__']]
                
                for file in files:
                    if any(file.endswith(ext) for ext in extensions):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                tokens = self.find_tokens_in_text(content, f"File: {file_path}")
                                all_tokens.extend(tokens)
                        except Exception as e:
                            print(f"[x] Error reading {file_path}: {e}")
        
        return all_tokens

    def find_tokens_in_environment(self):
        print("\n[ Token Discovery in Environment Variables ]")
        all_tokens = []
        
        for key, value in os.environ.items():
            if any(keyword in key.lower() for keyword in ['token', 'key', 'secret', 'auth', 'pass']):
                tokens = self.find_tokens_in_text(value, f"Env var: {key}")
                all_tokens.extend(tokens)
        
        return all_tokens

    def find_tokens_in_common_locations(self):
        print("\n[ Token Discovery in Common Locations ]")
        all_tokens = []
        
        # Check common config files
        common_files = [
            '.env',
            '.env.local',
            '.env.production',
            'config.json',
            'secrets.json',
            'auth.json',
            os.path.expanduser('~/.aws/credentials'),
            os.path.expanduser('~/.ssh/config'),
            os.path.expanduser('~/.gitconfig')
        ]
        
        for file_path in common_files:
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        tokens = self.find_tokens_in_text(content, f"Config file: {file_path}")
                        all_tokens.extend(tokens)
                except Exception as e:
                    print(f"[x] Error reading {file_path}: {e}")
        
        return all_tokens

    def validate_jwt_token(self, token):
        try:
            # Decode without verification to check structure
            decoded = jwt.decode(token, options={"verify_signature": False})
            print(f"[+] JWT payload: {json.dumps(decoded, indent=2)}")
            
            # Check if expired
            if 'exp' in decoded:
                exp_time = decoded['exp']
                current_time = int(time.time())
                if exp_time < current_time:
                    print("[!] JWT token is expired")
                else:
                    print("[+] JWT token is not expired")
            
            return True
        except Exception as e:
            print(f"[x] Invalid JWT token: {e}")
            return False

    def run_token_discovery(self):
        print("=" * 60)
        print("TOKEN DISCOVERY SCAN")
        print("=" * 60)
        
        all_found_tokens = []
        
        # Search in API responses
        response_tokens = self.find_tokens_in_responses()
        all_found_tokens.extend(response_tokens)
        
        # Search in environment variables
        env_tokens = self.find_tokens_in_environment()
        all_found_tokens.extend(env_tokens)
        
        # Search in common config locations
        config_tokens = self.find_tokens_in_common_locations()
        all_found_tokens.extend(config_tokens)
        
        # Search in local files (current directory)
        file_tokens = self.find_tokens_in_files()
        all_found_tokens.extend(file_tokens)
        
        # Summary
        print(f"\n[ Token Discovery Summary ]")
        print(f"Total tokens found: {len(all_found_tokens)}")
        
        # Validate JWT tokens
        for token in all_found_tokens:
            if token['type'] == 'jwt':
                print(f"\n[+] Validating JWT from {token['source']}")
                self.validate_jwt_token(token['value'])
        
        return all_found_tokens

    def run_full_test(self, token=None):
        print(f"Starting security test for: {self.base_url}")
        
        self.check_cors()
        self.test_authentication(token)
        if token:
            self.test_token_variants(token)
        self.test_rate_limit()
        self.parse_openapi()
        self.test_common_vulnerabilities()
        
        # Run token discovery
        self.run_token_discovery()

if __name__ == "__main__":
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(
        description='API Security Testing Tool - Defensive security scanner for APIs',
        epilog='''
Examples:
  python api_security_tester.py https://api.example.com
  python api_security_tester.py https://api.example.com --token "Bearer abc123"
  python api_security_tester.py https://api.example.com --token-discovery
  python api_security_tester.py https://api.example.com --endpoints /users /admin /health
  python api_security_tester.py https://api.example.com --openapi https://api.example.com/swagger.json
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('url', help='Target API base URL (e.g., https://api.example.com)')
    parser.add_argument('--token', '-t', help='Authentication token to test with')
    parser.add_argument('--openapi', '-o', help='OpenAPI specification URL')
    parser.add_argument('--token-discovery', '-d', action='store_true', help='Run token discovery only')
    parser.add_argument('--endpoints', '-e', nargs='+', default=["/", "/login", "/api", "/admin"], 
                        help='Custom endpoints to test (default: / /login /api /admin)')
    
    args = parser.parse_args()
    
    # Validate URL format
    if not args.url.startswith(('http://', 'https://')):
        print("Error: URL must start with http:// or https://")
        sys.exit(1)
    
    try:
        # Initialize tester with provided URL
        tester = APISecurityTester(args.url, args.openapi)
        
        # Set custom endpoints if provided
        if args.endpoints:
            tester.test_endpoints = args.endpoints
        
        if args.token_discovery:
            # Run only token discovery
            tester.run_token_discovery()
        else:
            # Run full security test
            tester.run_full_test(token=args.token)
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)