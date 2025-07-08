# API Security Tester - Burp Suite Plugin

A Burp Suite extension that provides automated API security testing and token discovery capabilities directly within Burp Suite.

## Features

- **Real-time Token Discovery**: Automatically scans HTTP requests and responses for exposed tokens
- **CORS Vulnerability Detection**: Identifies wildcard CORS headers and misconfigurations
- **Interactive GUI**: Easy-to-use interface integrated into Burp Suite
- **Manual Scanning**: Scan existing HTTP history for security issues
- **Multiple Token Types**: Detects JWT, API keys, Bearer tokens, GitHub tokens, Slack tokens, AWS keys, and more

## Supported Token Types

- JWT tokens (eyJ...)
- API keys
- Bearer tokens
- GitHub tokens (gh_...)
- Slack tokens (xox...)
- AWS access keys (AKIA...)
- Generic secrets

## Installation

### Building from Source

1. Prerequisites:
   - Java 11 or higher
   - Gradle 8.4 or higher

2. Build the plugin:
   ```bash
   cd burp-plugin
   ./gradlew build
   ```

3. The plugin JAR will be created in `build/libs/api-security-tester-burp-plugin-1.0.0.jar`

### Installing in Burp Suite

1. Open Burp Suite
2. Go to Extensions tab
3. Click "Add"
4. Select "Java" as extension type
5. Browse to the JAR file and click "Next"
6. The plugin should load successfully

## Usage

### Plugin Interface

Once loaded, the plugin adds a new tab called "API Security" to Burp Suite with the following features:

#### Settings Panel
- **Token Discovery**: Toggle automatic token discovery in requests/responses
- **CORS Check**: Toggle CORS vulnerability detection
- **Auth Testing**: Toggle authentication testing features
- **Clear Results**: Clear all findings from the output area
- **Manual Scan**: Scan existing HTTP history for security issues

#### Output Area
- Displays all security findings in real-time
- Shows token discoveries with source location
- Highlights CORS vulnerabilities
- Provides detailed information about each finding

### Automatic Scanning

The plugin automatically analyzes:
- All HTTP requests passing through Burp proxy
- All HTTP responses received
- Request and response headers
- Request and response bodies

### Manual Scanning

Click "Manual Scan" to analyze the current HTTP history for:
- Exposed tokens in previous requests/responses
- CORS misconfigurations
- Authentication issues

## Security Findings Format

### Token Discovery
```
[!] TOKEN FOUND: JWT token discovered in Response from https://api.example.com/login
    Token: eyJhbGciOiJIUzI1NiIsInR5...
```

### CORS Vulnerabilities
```
[!] CORS VULNERABILITY: Wildcard CORS header found at https://api.example.com/api
```

## Development

### Project Structure
```
src/
├── main/
│   └── java/
│       └── com/
│           └── apisecurity/
│               └── ApiSecurityTester.java
build.gradle
settings.gradle
gradle.properties
```

### Building
```bash
./gradlew build          # Build the plugin
./gradlew fatJar         # Create fat JAR with all dependencies
./gradlew clean          # Clean build artifacts
```

### Testing
```bash
./gradlew test           # Run tests
```

## API Reference

The plugin uses the Burp Suite Montoya API:
- `ProxyRequestHandler`: Intercepts HTTP requests
- `ProxyResponseHandler`: Intercepts HTTP responses
- `UserInterface`: Creates the plugin GUI tab
- `Logging`: Logs findings to Burp's output

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test with Burp Suite
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Troubleshooting

### Common Issues

1. **Plugin won't load**: Ensure Java 11+ is being used by Burp Suite
2. **No findings**: Check that settings are enabled and traffic is passing through proxy
3. **Performance issues**: Disable unused features in the settings panel

### Debug Information

Enable logging in Burp Suite's Extensions tab to see detailed debug information from the plugin.