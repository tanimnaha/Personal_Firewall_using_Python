#!/usr/bin/env python3
"""
Personal Firewall Demo
Demonstrates the key features without requiring admin privileges
"""

import time
import json
from datetime import datetime

def demo_banner():
    """Show demo banner"""
    print("""
╔═════════════════════════════════════════════════════════════════╗
║              Personal Firewall - DEMO MODE                     ║
║                Advanced Network Protection                      ║
║                                                                 ║
║  This demo shows the firewall functionality without            ║
║  requiring administrator privileges or packet capture.         ║
╚═════════════════════════════════════════════════════════════════╝
    """)

def demo_rule_management():
    """Demonstrate rule management"""
    print("\n🔧 RULE MANAGEMENT DEMO")
    print("=" * 50)
    
    # Import rule manager (this will work without scapy)
    try:
        from rule_manager import RuleManager
        
        print("✅ Initializing Rule Manager...")
        rm = RuleManager()
        
        print("\n📋 Current Rules:")
        print(f"   Blocked IPs: {len(rm.rules['ip_rules']['blocked_ips'])}")
        print(f"   Allowed IPs: {len(rm.rules['ip_rules']['allowed_ips'])}")
        print(f"   Blocked Ports: {len(rm.rules['port_rules']['blocked_ports'])}")
        print(f"   Allowed Ports: {len(rm.rules['port_rules']['allowed_ports'])}")
        
        print("\n🔄 Adding demo rules...")
        rm.add_ip_rule("192.168.1.999", "block")
        rm.add_port_rule(2222, "block")
        
        print("✅ Demo rules added successfully!")
        
        print("\n🧪 Testing rule evaluation...")
        test_ips = ["192.168.1.999", "192.168.1.1", "127.0.0.1"]
        for ip in test_ips:
            result = "BLOCKED" if rm.is_ip_blocked(ip) else "ALLOWED"
            print(f"   {ip}: {result}")
        
        return True
        
    except Exception as e:
        print(f"❌ Rule management demo failed: {e}")
        return False

def demo_logging():
    """Demonstrate logging functionality"""
    print("\n📝 LOGGING DEMO")
    print("=" * 50)
    
    try:
        from logger import Logger
        
        print("✅ Initializing Logger...")
        logger = Logger()
        
        print("\n📊 Simulating packet events...")
        
        # Simulate some packet logs
        sample_packets = [
            {
                "src_ip": "192.168.1.100",
                "dst_ip": "8.8.8.8",
                "protocol": "TCP",
                "dst_port": 80,
                "size": 1024
            },
            {
                "src_ip": "10.0.0.1",
                "dst_ip": "192.168.1.1",
                "protocol": "UDP", 
                "dst_port": 53,
                "size": 512
            },
            {
                "src_ip": "192.168.1.999",
                "dst_ip": "192.168.1.1",
                "protocol": "TCP",
                "dst_port": 22,
                "size": 256
            }
        ]
        
        actions = ["ALLOWED", "ALLOWED", "BLOCKED"]
        reasons = ["Default allow policy", "DNS query allowed", "Blocked source IP"]
        
        for i, (packet, action, reason) in enumerate(zip(sample_packets, actions, reasons)):
            logger.log_packet(packet, action, reason)
            print(f"   📦 Logged packet {i+1}: {action}")
            time.sleep(0.5)
        
        print("\n📊 Log Statistics:")
        stats = logger.get_log_stats()
        for key, value in stats.items():
            print(f"   {key.replace('_', ' ').title()}: {value}")
        
        return True
        
    except Exception as e:
        print(f"❌ Logging demo failed: {e}")
        return False

def demo_iptables_integration():
    """Demonstrate iptables integration"""
    print("\n🔗 IPTABLES INTEGRATION DEMO")
    print("=" * 50)
    
    try:
        from iptables_manager import IPTablesManager
        
        print("✅ Initializing IPTables Manager...")
        ipt = IPTablesManager()
        
        status = ipt.get_status()
        print("\n🔍 IPTables Status:")
        for key, value in status.items():
            icon = "✅" if value else "❌"
            print(f"   {icon} {key.replace('_', ' ').title()}: {value}")
        
        if not status['available']:
            print("\n💡 IPTables integration is available on Linux systems")
            print("   with proper privileges and iptables installed.")
        
        return True
        
    except Exception as e:
        print(f"❌ IPTables demo failed: {e}")
        return False

def demo_gui_preview():
    """Show GUI capabilities"""
    print("\n🖼️  GUI INTERFACE PREVIEW")
    print("=" * 50)
    
    print("""
The Personal Firewall GUI provides:

📊 MONITORING TAB:
   • Real-time packet statistics
   • Network interface selection  
   • Live activity feed
   • Start/stop monitoring controls

⚙️  RULES TAB:
   • IP address blocking/allowing
   • Port-based filtering
   • Protocol rules management
   • Default action configuration

📋 LOGS TAB:
   • Comprehensive event history
   • Filterable log viewer
   • Export capabilities
   • Log management tools

🔧 SETTINGS TAB:
   • Performance tuning
   • IPTables integration
   • Application preferences
   • About information

To launch the GUI: python main.py
(Requires administrator privileges for full functionality)
    """)

def demo_cli_preview():
    """Show CLI capabilities"""
    print("\n💻 CLI INTERFACE PREVIEW")
    print("=" * 50)
    
    print("""
The Personal Firewall CLI supports:

MONITORING:
   python main.py --cli monitor --interface eth0
   python main.py --cli status
   python main.py --cli interfaces

RULE MANAGEMENT:
   python main.py --cli rules list
   python main.py --cli rules add ip 192.168.1.100 block
   python main.py --cli rules add port 22 block
   python main.py --cli rules remove ip 192.168.1.100 block

LOG MANAGEMENT:
   python main.py --cli logs show --count 50
   python main.py --cli logs clear

CONFIGURATION:
   python main.py --cli config export config.json
   python main.py --cli config import config.json
   python main.py --cli sync-iptables

All commands support --help for detailed information.
    """)

def demo_security_features():
    """Demonstrate security detection capabilities"""
    print("\n🛡️  SECURITY FEATURES DEMO")
    print("=" * 50)
    
    print("""
Advanced Threat Detection:

🔍 PORT SCANNING DETECTION:
   • Monitors multiple port access from single IP
   • Configurable thresholds (default: 10 ports, 20 packets)
   • Automatic blocking of suspected scanners

🌊 FLOOD PROTECTION:
   • SYN flood detection (default: 50 packets)
   • ICMP flood protection (default: 30 packets)
   • Rate limiting and automatic mitigation

🚨 SUSPICIOUS ACTIVITY ALERTS:
   • Unusual port access (SSH, Telnet, RPC, SMB)
   • Protocol anomaly detection
   • Comprehensive logging of all threats

📊 REAL-TIME MONITORING:
   • Live packet analysis with Scapy
   • Connection state tracking
   • Performance statistics and metrics

🔒 RULE-BASED FILTERING:
   • IP address blacklists/whitelists
   • Port-based access control
   • Protocol filtering capabilities
   • Configurable default actions
    """)

def main():
    """Run the complete demo"""
    demo_banner()
    
    print("🚀 Starting Personal Firewall Demo...")
    time.sleep(1)
    
    # Run all demo sections
    demos = [
        ("Rule Management", demo_rule_management),
        ("Logging System", demo_logging),
        ("IPTables Integration", demo_iptables_integration),
        ("GUI Interface", demo_gui_preview),
        ("CLI Interface", demo_cli_preview),
        ("Security Features", demo_security_features)
    ]
    
    results = {}
    
    for name, demo_func in demos:
        print(f"\n{'='*60}")
        try:
            if callable(demo_func):
                results[name] = demo_func()
            else:
                demo_func()
                results[name] = True
        except Exception as e:
            print(f"❌ Demo section '{name}' failed: {e}")
            results[name] = False
        
        time.sleep(1)
    
    # Summary
    print(f"\n{'='*60}")
    print("📊 DEMO SUMMARY")
    print("=" * 60)
    
    for name, success in results.items():
        icon = "✅" if success else "❌"
        print(f"{icon} {name}")
    
    successful_demos = sum(1 for success in results.values() if success)
    total_demos = len(results)
    
    print(f"\n🎯 Demo Results: {successful_demos}/{total_demos} sections completed successfully")
    
    if successful_demos == total_demos:
        print("\n🎉 All demo sections completed successfully!")
        print("   The Personal Firewall is ready for use.")
    else:
        print("\n⚠️  Some demo sections had issues.")
        print("   This may be due to missing dependencies or system configuration.")
        print("   Run setup.py to resolve any installation issues.")
    
    print(f"\n🚀 To start using the Personal Firewall:")
    print("   GUI Mode: python main.py")
    print("   CLI Mode: python main.py --cli status")
    print("   Setup:    python setup.py")
    print("\n   Remember to run with administrator privileges for full functionality!")

if __name__ == "__main__":
    main()
