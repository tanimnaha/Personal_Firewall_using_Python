# Personal Firewall

A lightweight, advanced personal firewall built with Python that provides real-time network traffic monitoring, rule-based filtering, and comprehensive logging capabilities.

## 🌟 Features

### Core Functionality

- **Real-time Packet Monitoring**: Uses Scapy for deep packet inspection
- **Rule-based Traffic Filtering**: Block/allow traffic based on IPs, ports, and protocols
- **Suspicious Activity Detection**: Automatically detects port scans, SYN floods, and unusual traffic
- **Comprehensive Logging**: Detailed audit trail with JSON and text logs
- **IPTables Integration**: Sync rules to system-level iptables (Linux)

### User Interface

- **Modern GUI**: Built with Tkinter featuring a tabbed interface with real-time statistics
- **Full CLI Support**: Complete command-line interface for automation and scripting
- **Live Monitoring Dashboard**: Real-time statistics and activity feed
- **Rule Management**: Easy-to-use interface for managing firewall rules

### Advanced Features

- **Network Interface Selection**: Monitor specific network interfaces
- **Connection Tracking**: Track active connections and detect patterns
- **Configuration Export/Import**: Save and restore firewall configurations
- **Performance Monitoring**: Real-time packet processing statistics

## 🔧 Tech Stack

- **Python 3.7+**: Core application language
- **Scapy**: Packet capture and analysis
- **Tkinter**: Modern GUI interface
- **psutil**: System and network interface information
- **iptables**: System-level rule enforcement (Linux)
- **JSON**: Configuration and log storage

## 📋 Requirements

### System Requirements

- Python 3.7 or higher
- Administrator/Root privileges (for packet capture)
- Windows 10+ or Linux (Ubuntu 18.04+, CentOS 7+)

### Python Dependencies

```
scapy==2.5.0
psutil==5.9.6
tkinter-tooltip==2.3.0
requests==2.31.0
python-iptables==1.0.1
```

## 🚀 Installation

### 1. Clone or Download

```bash
# Download the project files to your desired directory
cd /path/to/project
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Platform-specific Setup

#### Windows

- Install Npcap (https://npcap.org/) for packet capture
- Run Command Prompt as Administrator

#### Linux

```bash
# Install required system packages
sudo apt update
sudo apt install python3-dev libpcap-dev

# Ensure iptables is available (usually pre-installed)
sudo iptables --version
```

## 🎯 Usage

### GUI Mode (Recommended)

```bash
# Launch the graphical interface
python main.py

# Or directly run the GUI
python firewall_gui.py
```

### CLI Mode

```bash
# Show help
python main.py --cli --help

# Start monitoring
python main.py --cli monitor --interface eth0

# Manage rules
python main.py --cli rules list
python main.py --cli rules add ip 192.168.1.100 block
python main.py --cli rules add port 22 block

# View logs
python main.py --cli logs show --count 50

# Check status
python main.py --cli status

# Sync to iptables (Linux)
python main.py --cli sync-iptables
```

## 📖 Detailed Usage Guide

### GUI Interface

#### 1. Monitoring Tab

- **Start/Stop Monitoring**: Control packet capture
- **Interface Selection**: Choose which network interface to monitor
- **Real-time Statistics**: View live packet counts, blocking statistics
- **Activity Feed**: See recent firewall actions and alerts

#### 2. Rules Tab

- **IP Rules**: Block or allow specific IP addresses (supports CIDR notation)
- **Port Rules**: Control traffic on specific ports
- **General Settings**: Configure default actions and logging behavior

#### 3. Logs Tab

- **Activity History**: View detailed logs of all firewall actions
- **Filter and Search**: Find specific events in the log history
- **Export Logs**: Save logs for external analysis

#### 4. Settings Tab

- **Performance Tuning**: Adjust packet buffer sizes
- **IPTables Integration**: Sync rules to system firewall
- **Application Settings**: Configure monitoring behavior

### CLI Commands

#### Monitoring

```bash
# Start monitoring all interfaces
python main.py --cli monitor

# Monitor specific interface for 5 minutes
python main.py --cli monitor --interface eth0 --duration 300

# List available interfaces
python main.py --cli interfaces
```

#### Rule Management

```bash
# List all current rules
python main.py --cli rules list

# Block specific IP
python main.py --cli rules add ip 192.168.1.100 block

# Allow IP range (CIDR notation)
python main.py --cli rules add ip 192.168.1.0/24 allow

# Block port
python main.py --cli rules add port 22 block

# Remove rule
python main.py --cli rules remove ip 192.168.1.100 block
```

#### Log Management

```bash
# Show recent logs
python main.py --cli logs show

# Show last 100 entries
python main.py --cli logs show --count 100

# Clear all logs
python main.py --cli logs clear
```

#### Configuration

```bash
# Export current configuration
python main.py --cli config export my_firewall_config.json

# Import configuration
python main.py --cli config import my_firewall_config.json

# Show current status
python main.py --cli status
```

## 🔒 Security Features

### Threat Detection

- **Port Scanning**: Detects when multiple ports are accessed from single IP
- **SYN Flood Protection**: Identifies potential SYN flood attacks
- **ICMP Flood Detection**: Monitors for ICMP-based attacks
- **Unusual Port Access**: Alerts on access to commonly attacked ports

### Rule Types

- **IP-based Rules**: Block/allow traffic from specific IPs or IP ranges
- **Port-based Rules**: Control access to specific network ports
- **Protocol Rules**: Filter traffic by protocol type (TCP, UDP, ICMP)
- **Default Actions**: Set system-wide default behavior (allow/block)

### Logging and Audit

- **Comprehensive Logging**: All traffic decisions are logged with timestamps
- **JSON Format**: Machine-readable logs for integration with other tools
- **Audit Trail**: Complete history of all firewall actions and rule changes
- **Suspicious Activity Alerts**: Special logging for detected threats

## 🛠️ Configuration

### Default Rules

The firewall comes with sensible default rules:

**Blocked Ports**: 22 (SSH), 23 (Telnet), 135 (RPC), 139 (NetBIOS), 445 (SMB)
**Allowed IPs**: 127.0.0.1 (localhost), 192.168.1.0/24 (local network)
**Default Action**: Allow (with monitoring)

### Configuration File

Rules are stored in `firewall_rules.json`:

```json
{
  "ip_rules": {
    "blocked_ips": [],
    "allowed_ips": ["127.0.0.1", "192.168.1.0/24"]
  },
  "port_rules": {
    "blocked_ports": [22, 23, 135, 139, 445],
    "allowed_ports": [80, 443, 53, 21, 25]
  },
  "general_settings": {
    "default_action": "allow",
    "log_all_traffic": false,
    "log_blocked_only": true
  }
}
```

## 🐧 Linux IPTables Integration

On Linux systems, the firewall can sync rules to iptables for system-level enforcement:

```bash
# Check iptables status
python main.py --cli status

# Sync current rules to iptables
python main.py --cli sync-iptables

# Create iptables backup before making changes
sudo iptables-save > iptables_backup.txt
```

## 📊 Performance

### System Impact

- **Low CPU Usage**: Efficient packet processing with minimal overhead
- **Memory Efficient**: Smart buffering and connection tracking
- **Configurable Performance**: Adjustable packet buffer sizes

### Scalability

- **High Throughput**: Handles thousands of packets per second
- **Smart Filtering**: Pre-filtering to reduce processing load
- **Background Processing**: Non-blocking GUI updates

## 🔧 Troubleshooting

### Common Issues

#### "Permission Denied" or "Access Denied"

**Solution**: Run as Administrator (Windows) or root (Linux)

```bash
# Windows (Command Prompt as Administrator)
python main.py

# Linux
sudo python3 main.py
```

#### "No module named 'scapy'"

**Solution**: Install required dependencies

```bash
pip install -r requirements.txt
```

#### "Interface not found" or "No interfaces available"

**Solution**: Check network interfaces and drivers

```bash
# List available interfaces
python main.py --cli interfaces

# Windows: Install/update Npcap
# Linux: Check network interface status
ip link show
```

#### GUI doesn't start on Linux

**Solution**: Install tkinter

```bash
# Ubuntu/Debian
sudo apt install python3-tk

# CentOS/RHEL
sudo yum install tkinter
```

### Debugging

Enable verbose logging by modifying the logging settings in the GUI or by setting debug flags in the configuration.

## 🤝 Contributing

We welcome contributions! Here's how you can help:

1. **Report Bugs**: Open an issue with detailed information
2. **Suggest Features**: Propose new functionality
3. **Submit Code**: Create pull requests with improvements
4. **Documentation**: Help improve documentation and examples

### Development Setup

```bash
# Clone repository
git clone <repository-url>

# Install development dependencies
pip install -r requirements.txt
pip install pytest black flake8

# Run tests
python -m pytest

# Format code
black *.py

# Lint code
flake8 *.py
```

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- **Scapy Team**: For the excellent packet manipulation library
- **Python Community**: For the robust ecosystem and libraries
- **Security Researchers**: For insights into network security patterns
- **Open Source Community**: For inspiration and best practices

## 📞 Support

For support, feature requests, or bug reports:

1. Check the troubleshooting section above
2. Search existing issues in the repository
3. Create a new issue with detailed information
4. Join our community discussions

---

**⚠️ Important Security Notice**: This firewall is designed for personal and educational use. For production environments, consider enterprise-grade solutions and consult with security professionals.

**🔒 Privacy**: The firewall processes network traffic locally and does not send data to external servers. All logs and configurations are stored locally on your system.
