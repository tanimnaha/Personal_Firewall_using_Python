# Personal Firewall - Project Structure

## 📁 Project Organization

```
personal-firewall/
├── main.py                    # Main entry point
├── firewall_gui.py           # GUI interface using Tkinter
├── firewall_cli.py           # Command-line interface
├── packet_sniffer.py         # Core packet sniffing with Scapy
├── rule_manager.py           # Rule management system
├── logger.py                 # Logging and audit functionality
├── iptables_manager.py       # IPTables integration (Linux)
├── setup.py                  # Installation and setup script
├── requirements.txt          # Python dependencies
├── firewall_rules.json       # Default configuration file
├── README.md                 # Comprehensive documentation
├── PROJECT_STRUCTURE.md      # This file
├── run_gui.py               # Convenience GUI launcher (created by setup)
├── run_cli.py               # Convenience CLI launcher (created by setup)
└── logs/                    # Generated log files (created at runtime)
    ├── firewall.log         # Text log file
    └── firewall_events.json # JSON structured logs
```

## 🧩 Module Architecture

### Core Components

#### 1. `main.py` - Application Entry Point

- **Purpose**: Main entry point with CLI/GUI mode selection
- **Key Functions**:
  - `check_dependencies()`: Verify required packages
  - `check_privileges()`: Ensure admin/root access
  - `main()`: Application launcher with argument parsing

#### 2. `packet_sniffer.py` - Core Engine

- **Purpose**: Real-time packet capture and analysis
- **Key Classes**:
  - `PacketSniffer`: Main monitoring class
- **Key Functions**:
  - `start_monitoring()`: Begin packet capture
  - `_process_packet()`: Analyze individual packets
  - `_evaluate_packet()`: Apply rules and make decisions
  - `_check_suspicious_patterns()`: Threat detection

#### 3. `rule_manager.py` - Rule Engine

- **Purpose**: Manage firewall rules and configuration
- **Key Classes**:
  - `RuleManager`: Rule storage and evaluation
- **Key Functions**:
  - `load_rules()`: Load configuration from JSON
  - `add_ip_rule()`, `add_port_rule()`: Add new rules
  - `is_ip_blocked()`, `is_port_blocked()`: Rule evaluation

#### 4. `logger.py` - Audit System

- **Purpose**: Comprehensive logging and audit trail
- **Key Classes**:
  - `Logger`: Logging management
- **Key Functions**:
  - `log_packet()`: Record packet decisions
  - `get_recent_logs()`: Retrieve log history
  - `get_log_stats()`: Generate statistics

#### 5. `firewall_gui.py` - Graphical Interface

- **Purpose**: Modern Tkinter-based GUI
- **Key Classes**:
  - `FirewallGUI`: Main GUI application
- **Key Features**:
  - Tabbed interface (Monitoring, Rules, Logs, Settings)
  - Real-time statistics dashboard
  - Rule management interface
  - Log viewing and analysis

#### 6. `firewall_cli.py` - Command Line Interface

- **Purpose**: Full-featured CLI for automation
- **Key Classes**:
  - `FirewallCLI`: CLI command processor
- **Key Features**:
  - Comprehensive command structure
  - Real-time monitoring with statistics
  - Rule management commands
  - Configuration import/export

#### 7. `iptables_manager.py` - System Integration

- **Purpose**: IPTables integration for Linux systems
- **Key Classes**:
  - `IPTablesManager`: System firewall integration
- **Key Functions**:
  - `add_ip_block_rule()`: Add system-level IP blocks
  - `add_port_block_rule()`: Add system-level port blocks
  - `sync_rules()`: Synchronize application rules to iptables

## 🔄 Data Flow

### Packet Processing Pipeline

```
Network Traffic
    ↓
Scapy Packet Capture
    ↓
Packet Information Extraction
    ↓
Rule Evaluation
    ↓
Suspicious Pattern Detection
    ↓
Action Decision (ALLOW/BLOCK)
    ↓
Logging & Statistics Update
    ↓
GUI/CLI Display Update
```

### Configuration Management

```
JSON Configuration File
    ↓
RuleManager Load
    ↓
GUI/CLI Rule Modification
    ↓
Rule Validation
    ↓
Configuration Save
    ↓
Optional IPTables Sync
```

## 🎨 GUI Architecture

### Main Window Structure

```
Main Window (1200x800)
├── Notebook (Tabbed Interface)
    ├── Monitoring Tab
    │   ├── Control Panel
    │   ├── Statistics Dashboard
    │   └── Live Activity Feed
    ├── Rules Tab
    │   ├── IP Rules Sub-tab
    │   ├── Port Rules Sub-tab
    │   └── General Settings Sub-tab
    ├── Logs Tab
    │   ├── Log Viewer (TreeView)
    │   └── Log Controls
    └── Settings Tab
        ├── Performance Settings
        ├── IPTables Integration
        └── About Information
```

### GUI Threading Model

- **Main Thread**: GUI event handling and display updates
- **Monitoring Thread**: Packet capture and processing
- **Statistics Thread**: Periodic statistics updates
- **Background Tasks**: Log rotation, cleanup operations

## 📊 Data Structures

### Rule Configuration

```python
{
    "ip_rules": {
        "blocked_ips": ["192.168.1.100", "10.0.0.0/8"],
        "allowed_ips": ["127.0.0.1", "192.168.1.0/24"]
    },
    "port_rules": {
        "blocked_ports": [22, 23, 135, 139, 445],
        "allowed_ports": [80, 443, 53]
    },
    "protocol_rules": {
        "blocked_protocols": [],
        "allowed_protocols": ["TCP", "UDP", "ICMP"]
    },
    "general_settings": {
        "default_action": "allow",
        "log_all_traffic": false,
        "log_blocked_only": true
    }
}
```

### Packet Information

```python
{
    "src_ip": "192.168.1.100",
    "dst_ip": "8.8.8.8",
    "protocol": "TCP",
    "src_port": 12345,
    "dst_port": 80,
    "size": 1024,
    "timestamp": 1640995200.123,
    "flags": 2  # TCP flags
}
```

### Log Entry

```python
{
    "timestamp": "2025-01-01 12:00:00",
    "action": "BLOCKED",
    "packet_info": { /* packet details */ },
    "reason": "Blocked source IP: 192.168.1.100"
}
```

## 🔧 Extension Points

### Adding New Rule Types

1. Extend `RuleManager` class with new rule methods
2. Add evaluation logic in `PacketSniffer._evaluate_packet()`
3. Update GUI rule management interface
4. Add CLI commands for new rule type

### Custom Threat Detection

1. Add detection logic in `PacketSniffer._check_suspicious_patterns()`
2. Define new suspicious pattern types
3. Add configuration options for thresholds
4. Update logging to include new threat types

### Additional Protocols

1. Import protocol classes from scapy.layers
2. Add protocol-specific packet information extraction
3. Update rule evaluation for new protocols
4. Add GUI/CLI support for protocol-specific rules

## 🔍 Debugging and Monitoring

### Debug Features

- Verbose logging modes
- Packet capture statistics
- Rule evaluation tracing
- Performance profiling

### Monitoring Points

- Packet processing rate
- Memory usage tracking
- Rule evaluation performance
- GUI responsiveness metrics

## 📈 Performance Considerations

### Optimization Strategies

- **Packet Filtering**: Pre-filter packets to reduce processing load
- **Rule Caching**: Cache frequently accessed rules
- **Background Processing**: Non-blocking operations for GUI
- **Memory Management**: Efficient packet buffer management

### Scalability Limits

- **Packet Rate**: Designed for personal use (< 10,000 packets/sec)
- **Rule Count**: Optimized for < 1,000 rules
- **Log Storage**: Automatic rotation to prevent disk space issues
- **Memory Usage**: Bounded connection tracking

## 🛡️ Security Architecture

### Security Principles

- **Least Privilege**: Only request necessary permissions
- **Fail Safe**: Default to secure behavior on errors
- **Defense in Depth**: Multiple layers of protection
- **Audit Trail**: Comprehensive logging for accountability

### Threat Model

- **Target Environment**: Personal computers and small networks
- **Threat Actors**: Script kiddies, automated attacks, malware
- **Attack Vectors**: Network scanning, service exploitation, data exfiltration
- **Protection Goals**: Monitor, alert, and block suspicious activity

This architecture provides a solid foundation for a personal firewall while maintaining extensibility and performance.
