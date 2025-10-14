# Scapy Port Scanner

A fast, multi-threaded port scanner built with Python and Scapy, supporting both SYN (stealth) and TCP Connect scanning methods.

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

## 🚀 Features

- **Dual Scan Methods**
  - SYN (stealth) scan using raw packets
  - TCP Connect scan (no root required)
- **High Performance**
  - Multi-threaded scanning with ThreadPoolExecutor
  - Configurable thread count and timeouts
  - Optional rate limiting
- **Smart Banner Grabbing**
  - Protocol-specific probes for HTTP, FTP, SSH, SMTP, MySQL, and more
  - Automatic service detection
- **Flexible Output**
  - CSV format for data analysis
  - JSON format for automation
  - Plain text for quick review
- **Robust Port Parsing**
  - Single ports: `80`
  - Ranges: `1-1024`
  - Multiple ports: `22,80,443`
  - Complex combinations: `1-100,443,8000-9000`
- **Cross-Platform Support**
  - Windows (Administrator required for SYN scan)
  - Linux/Unix (root required for SYN scan)
  - macOS (root required for SYN scan)
- **Safety Features**
  - Graceful Ctrl+C handling
  - Automatic privilege checking
  - Rate limiting to avoid overwhelming targets

## 📋 Requirements

- Python 3.8 or higher
- Scapy library

## 🔧 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/SOSARS/Scapy-Port-Scanner.git
cd Scapy-Port-Scanner
```

### 2. Install Dependencies

**Linux/macOS:**
```bash
pip3 install scapy
```

**Windows:**
```bash
py -m pip install scapy
```

For SYN scanning on Windows, you may also need to install Npcap:
- Download from: https://npcap.com/
- Install with "WinPcap API-compatible Mode" enabled

## 📖 Usage

### Version 2 (Recommended) ⭐

```bash
# Basic connect scan (no admin required)
py scapy_port_scanner-v2.py -t 192.168.1.1 -p 80,443 --scan connect

# SYN scan with custom threads and timeout
sudo python3 scapy_port_scanner-v2.py -t 192.168.1.1 -p 1-1024 --scan syn -T 200 --timeout 1.0

# Scan with output to CSV
py scapy_port_scanner-v2.py -t example.com -p 1-65535 --scan connect -o results.csv

# Rate-limited scan (100 ports/second)
sudo python3 scapy_port_scanner-v2.py -t 10.0.0.1 -p 1-10000 --scan syn --rate-limit 100 -o scan.json
```

### Command-Line Arguments

| Argument | Short | Description | Default |
|----------|-------|-------------|---------|
| `--target` | `-t` | Target IP address or hostname (required) | - |
| `--ports` | `-p` | Ports to scan (e.g., `80`, `1-1024`, `22,80,443`) | `1-1024` |
| `--scan` | - | Scan type: `syn` or `connect` | `connect` |
| `--threads` | `-T` | Number of concurrent threads | `100` |
| `--timeout` | - | Timeout per port in seconds | `1.5` |
| `--rate-limit` | - | Maximum scans per second (optional) | None |
| `--output` | `-o` | Output file (`.csv`, `.json`, or `.txt`) | None |

## 🎯 Examples

### Quick Scan of Common Ports
```bash
py scapy_port_scanner-v2.py -t 192.168.1.1 -p 21,22,23,25,80,443,3306,3389 --scan connect
```

### Full Port Scan with High Speed
```bash
sudo python3 scapy_port_scanner-v2.py -t 192.168.1.1 -p 1-65535 --scan syn -T 500 --timeout 0.5
```

### Scan with JSON Output for Automation
```bash
py scapy_port_scanner-v2.py -t target.com -p 1-1000 --scan connect -o results.json
```

### Safe Scan with Rate Limiting
```bash
sudo python3 scapy_port_scanner-v2.py -t 10.0.0.1 -p 1-10000 --scan syn --rate-limit 50 -T 100
```

### Scanning the Legal Test Server
```bash
py scapy_port_scanner-v2.py -t scanme.nmap.org -p 22,80,443 --scan connect
```

## 🔒 Privilege Requirements

### SYN Scan
- **Linux/macOS**: Requires `sudo` or root privileges
- **Windows**: Must run Command Prompt/PowerShell as Administrator

### Connect Scan
- No special privileges required on any platform

## 📊 Output Formats

### Console Output
```
[*] Resolved 'example.com' to 93.184.216.34
[*] Starting CONNECT scan on 93.184.216.34
[*] Threads: 100 | Timeout: 1.5s | Ports: 3
[+] Port 22    is open    SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
[+] Port 80    is open    HTTP/1.1 200 OK
[+] Port 443   is open    Banner received (binary data)
[*] Scan complete in 2.34 seconds
[*] Found 3 open ports
```

### CSV Output
```csv
port,state,banner,scan_type,timestamp
22,open,SSH-2.0-OpenSSH_8.2p1,connect,2025-10-14T10:30:15.123456
80,open,HTTP/1.1 200 OK,connect,2025-10-14T10:30:15.234567
443,open,Banner received (binary data),connect,2025-10-14T10:30:15.345678
```

### JSON Output
```json
[
  {
    "port": 22,
    "state": "open",
    "banner": "SSH-2.0-OpenSSH_8.2p1",
    "scan_type": "connect",
    "timestamp": "2025-10-14T10:30:15.123456"
  }
]
```

## 📁 Project Structure

```
Scapy-Port-Scanner/
├── scapy_port_scanner.py       # Version 1 (original, kept for reference)
├── scapy_port_scanner-v2.py    # Version 2 (production-ready) ⭐
└── README.md                    # This file
```

### Version Differences

#### Version 1 (`scapy_port_scanner.py`)
- Original implementation
- Basic functionality with known bugs
- Kept for learning reference and historical progression

#### Version 2 (`scapy_port_scanner-v2.py`) ⭐ **Use This!**
- All bugs fixed from v1
- Full feature implementation
- Cross-platform compatibility
- Enhanced error handling
- Thread-safe operations

## ⚠️ Legal Disclaimer

**IMPORTANT**: Only scan networks and systems you own or have explicit permission to test. Unauthorised port scanning may be illegal in your jurisdiction and could be considered an attack. 

This tool is intended for:
- Educational purposes
- Security auditing of your own systems
- Authorised penetration testing
- Network administration

Always ensure you have proper authorisation before scanning any target.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Built with [Scapy](https://scapy.net/) - the powerful Python packet manipulation library
- Inspired by classic network security tools like Nmap
- Thanks to the cybersecurity community for testing and feedback

## 📧 Contact

- GitHub: [@SOSARS](https://github.com/SOSARS)
- Project Link: [https://github.com/SOSARS/Scapy-Port-Scanner](https://github.com/SOSARS/Scapy-Port-Scanner)

## 🔮 Future Enhancements

- [ ] UDP port scanning
- [ ] OS detection fingerprinting
- [ ] Service version detection
- [ ] HTML report generation
- [ ] Integration with CVE databases
- [ ] Scan result comparison tool
- [ ] GUI interface

---

**Star ⭐ this repository if you find it useful!**
