# API Security Tester

Professional security testing plugins for popular web application security tools. This repository provides comprehensive API security testing capabilities through plugins for Burp Suite and Caido.

## 🔌 Security Tool Plugins

### **Burp Suite Plugin**
Java-based extension for Burp Suite Pro/Community with comprehensive security testing features.

📁 **[burp-plugin](./burp-plugin)** - Complete installation guide and documentation

**Features:**
- Real-time token discovery in HTTP traffic
- CORS vulnerability detection
- Interactive GUI with findings management
- JWT token analysis and validation
- Manual scanning capabilities

### **Caido Plugin** 
Modern JavaScript plugin for Caido with automated security analysis.

📁 **[caido-plugin](./caido-plugin)** - Complete installation guide and documentation

**Features:**
- Automatic HTTP traffic monitoring
- Token discovery and analysis
- Security vulnerability detection
- Console-based findings display
- Command-line plugin management

## 🖥️ Standalone Tool

### **Python CLI Tool**
Command-line Python tool for independent API security testing.

📁 **[standalone-tool](./standalone-tool)** - Python script and documentation

**Features:**
- Command-line API security testing
- Token discovery across multiple sources
- JWT validation and analysis
- OpenAPI specification support
- Comprehensive vulnerability scanning

## 🛡️ Security Analysis Capabilities

Both plugins provide comprehensive security testing:

### **Token Discovery**
- **JWT tokens** - Automatic detection and parsing
- **API keys** - Various formats and patterns
- **Bearer tokens** - Authorization headers
- **Service tokens** - GitHub, Slack, AWS, etc.
- **Generic secrets** - Custom patterns

### **Vulnerability Detection**
- **CORS misconfigurations** - Wildcard origins, dangerous settings
- **Security headers** - Missing or misconfigured headers
- **Information disclosure** - SQL errors, stack traces, debug info
- **Authentication issues** - Weak schemes, insecure cookies

### **Real-time Analysis**
- Automatic scanning of all HTTP traffic
- Live findings display
- Duplicate detection
- Performance optimization

## 🚀 Quick Start

### For Burp Suite Users
1. Download the plugin JAR from [burp-plugin/](./burp-plugin)
2. Load in Burp Suite Extensions
3. Start scanning immediately

### For Caido Users
1. Download the plugin ZIP from [caido-plugin/](./caido-plugin)
2. Install via Caido's Plugin interface
3. Enable and start monitoring

### For Standalone Usage
1. Navigate to [standalone-tool/](./standalone-tool)
2. Install Python dependencies: `pip install -r requirements.txt`
3. Run: `python api_security_tester.py <target-url>`

## 📊 Use Cases

### **Penetration Testing**
- Automated token discovery during assessments
- Real-time vulnerability identification
- Comprehensive security header analysis

### **Security Development**
- API security validation during development
- Token exposure prevention
- Security misconfiguration detection

### **Red Team Operations**
- Passive token harvesting
- Service identification through tokens
- Security posture assessment

## 🎯 Professional Features

- **Zero Configuration** - Works out of the box
- **Non-Intrusive** - Passive analysis only
- **Performance Optimized** - Minimal impact on testing workflow
- **Export Capabilities** - JSON export for reporting
- **Extensible** - Easy to modify and enhance

## 📋 Requirements

### Burp Suite Plugin
- Burp Suite Professional or Community
- Java 11+
- Modern browser for GUI features

### Caido Plugin
- Caido application
- JavaScript runtime support

### Standalone Tool
- Python 3.6+
- pip package manager
- Network access to target APIs

## 🔒 Ethical Use

These plugins are designed for **defensive security purposes only**:

✅ **Authorized Use:**
- Testing your own applications
- Authorized penetration testing
- Security research with permission
- Educational purposes

❌ **Prohibited Use:**
- Unauthorized system testing
- Malicious token harvesting
- Privacy violations

## 🤝 Contributing

We welcome contributions to improve the plugins:

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

These tools are for educational and defensive security purposes only. The authors are not responsible for any misuse of these tools. Always ensure you have proper authorization before testing any systems.

---

**Made with ❤️ for the security community**