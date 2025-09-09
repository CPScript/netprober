# NetProber Free - Multi-Protocol Authentication Testing Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

NetProber is a powerful, multi-protocol authentication testing framework designed for security professionals, penetration testers, and developers. This free version provides essential authentication testing capabilities for SSH, FTP, and HTTP protocols.

## 🚀 Features (Free Version)

- **3 Core Protocols**: SSH, FTP, HTTP Basic Authentication
- **16 Concurrent Connections**: Efficient parallel testing
- **Flexible Input**: Username/password lists or single credentials
- **Clean Output**: Organized text-based results
- **Cross-Platform**: Linux, Windows, macOS support
- **MIT License**: Free for educational and commercial use
- **Lightweight**: Minimal dependencies, fast execution

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/CPScript/netprober.git
cd netprober

# Install dependencies
pip install -r requirements.txt

# Make executable (Linux/macOS)
chmod +x netprober.py
```

### Requirements
- Python 3.8 or higher
- Dependencies listed in `requirements.txt`

## 🔧 Usage

### Basic Usage

```bash
# SSH brute force with username and password lists
./netprober.py attack -t 192.168.1.100 -P ssh -U usernames.txt -S passwords.txt

# Single credential test
./netprober.py attack -t example.com -P ssh -u admin -s password123

# FTP authentication testing
./netprober.py attack -t ftp.example.com -P ftp -U users.txt -S passwords.txt

# HTTP Basic Auth testing with custom path
./netprober.py attack -t api.example.com -P http -u admin -S passwords.txt --path /admin
```

### Advanced Options

```bash
# Custom port and timeout
./netprober.py attack -t target.com -p 2222 -P ssh -U users.txt -S passwords.txt --timeout 10

# High concurrency testing
./netprober.py attack -t target.com -P ssh -U users.txt -S passwords.txt -T 16

# Verbose output
./netprober.py attack -t target.com -P ssh -u admin -s password -v
```

### Help and Information

```bash
# General help
./netprober.py --help

# Command-specific help
./netprober.py attack --help

# List available protocols
./netprober.py list
```

## 📋 Supported Protocols (Free Version)

| Protocol | Port | Description |
|----------|------|-------------|
| SSH | 22 | Secure Shell authentication |
| FTP | 21 | File Transfer Protocol |
| HTTP | 80/443 | HTTP Basic Authentication |

## 💡 Example Scenarios

### 1. SSH Infrastructure Assessment
```bash
# Test SSH access across multiple servers
./netprober.py attack -t ssh-server.corp.local -P ssh \
  -U domain_users.txt -S common_passwords.txt \
  --timeout 30 -T 8
```

### 2. FTP Service Testing
```bash
# Test FTP anonymous and user access
./netprober.py attack -t ftp.example.com -P ftp \
  -u anonymous -s '' --timeout 15
```

### 3. Web Application Authentication
```bash
# Test HTTP Basic Auth on API endpoints
./netprober.py attack -t api.company.com -P http \
  -U api_users.txt -S passwords.txt \
  --path /v1/admin --ssl
```

## 📊 Output Format

NetProber Free provides clear, organized text output:

```
[SUCCESS] SSH 192.168.1.100:22 admin:password123
[FAILED]  SSH 192.168.1.100:22 admin:123456
[SUCCESS] SSH 192.168.1.100:22 user:welcome
```

## 🏢 Enterprise Versions Available

### NetProber Professional ($299/year)
**Perfect for security consultancies and corporate teams**

- ✅ **9 Total Protocols** (6 additional: LDAP, RDP, VNC, Telnet, SNMP, SMB)
- ✅ **100 Concurrent Connections** (84 more than free)
- ✅ **Database Persistence** - SQLite storage for session management
- ✅ **REST API Access** - Full API for automation and integration
- ✅ **Advanced Reporting** - HTML, JSON, CSV exports
- ✅ **Session Management** - Save, resume, and manage testing sessions
- ✅ **Circuit Breakers** - Intelligent failure handling
- ✅ **Email Support** - Professional assistance

### NetProber Enterprise AI (Custom Pricing)
**AI-powered authentication testing for large organizations**

- 🚀 **20+ Protocol Support** - Complete enterprise protocol suite
- 🚀 **1000+ Concurrent Connections** - Massive scale testing
- 🚀 **Groq AI Integration** - Context-aware password generation (3-5x success rate)
- 🚀 **Advanced I/O Formats** - Parquet, Avro, Excel, XML, YAML, Protocol Buffers, HDF5
- 🚀 **Enterprise Dashboard** - Real-time monitoring and analytics
- 🚀 **Custom Integrations** - Tailored solutions for your environment
- 🚀 **24/7 Priority Support** - Dedicated enterprise support team

#### Enterprise AI Features:
- **AI-Enhanced Password Generation**: Groq AI analyzes organizational context to generate targeted passwords
- **Advanced Analytics**: Statistical analysis, trend identification, and risk scoring
- **Compliance Reporting**: Automated reports for SOC2, PCI-DSS, ISO 27001
- **Enterprise Integration**: SIEM, SOAR, and ticketing system integrations

## 💳 Purchasing Information

**Ready to upgrade?** Contact our me to learn about NetProber Professional or Enterprise AI:

📧 **Email**: [trust.frameworks@gmail.com](mailto:trust.frameworks@gmail.com)

**Include in your inquiry:**
- Organization name and size
- Desired version (Professional or Enterprise AI)
- Number of users
- Specific protocol requirements
- Integration needs

**Response time**: Within 48 hours for all inquiries

## 🔒 Legal and Ethical Use

⚠️ **IMPORTANT**: NetProber is designed exclusively for authorized security testing and vulnerability assessment. Users must:

- Only test systems you own or have explicit written permission to test
- Comply with all applicable laws and regulations
- Obtain proper authorization before testing any third-party systems
- Use the tool responsibly for legitimate security purposes

## 🛠️ Technical Specifications

### System Requirements
- **Operating System**: Linux, Windows, macOS
- **Python**: 3.8 or higher
- **RAM**: 2GB minimum (4GB recommended)
- **Storage**: 500MB free space
- **Network**: Internet connectivity for updates

### Architecture
- **Async Framework**: Built on asyncio for high performance
- **Protocol Modules**: Modular design for easy extension
- **Connection Pooling**: Efficient resource management
- **Error Handling**: Robust failure recovery and reporting

## 🤝 Community and Support

### Free Version Support
- **GitHub Issues**: Bug reports and feature requests
- **Community Forum**: User discussions and tips
- **Documentation**: Comprehensive guides and examples

### Professional Support
- **Professional Version**: Email support with business hours response
- **Enterprise Version**: 24/7 priority support with dedicated team

## 📈 Comparison Chart

| Feature | Free | Professional | Enterprise AI |
|---------|------|-------------|---------------|
| Protocols | 3 | 9 | 20+ |
| Concurrent Connections | 16 | 100 | 1000+ |
| Output Formats | Text | HTML, JSON, CSV | 10+ formats |
| AI Integration | ❌ | ❌ | ✅ Groq AI |
| Database Storage | ❌ | ✅ | ✅ |
| REST API | ❌ | ✅ | ✅ |
| Session Management | ❌ | ✅ | ✅ |
| Enterprise Dashboard | ❌ | ❌ | ✅ |
| Support | Community | Email | 24/7 Priority |
| Price | Free | $299/year | Custom |

## 🚀 Getting Started

1. **Download**: Clone this repository
2. **Install**: Run `pip install -r requirements.txt`
3. **Test**: Try `./netprober.py list` to see available protocols
4. **Learn**: Check out the examples above
5. **Upgrade**: Contact sales for advanced features

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- **Website**: [cpscript.github.io/netprober](https://cpscript.github.io/netprober/)
- **Issues**: [GitHub Issues](https://github.com/CPScript/netprober/issues)

---

**Made with ❤️ for the cybersecurity community**

*NetProber - Comprehensive authentication testing for the modern enterprise*
