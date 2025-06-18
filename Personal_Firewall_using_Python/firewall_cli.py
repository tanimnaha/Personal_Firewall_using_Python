#!/usr/bin/env python3
"""
Personal Firewall CLI
Command-line interface for the personal firewall application
"""

import argparse
import sys
import time
import signal
import json
from packet_sniffer import PacketSniffer
from rule_manager import RuleManager
from logger import Logger
from iptables_manager import IPTablesManager

class FirewallCLI:
    """Command-line interface for Personal Firewall"""
    
    def __init__(self):
        self.packet_sniffer = PacketSniffer()
        self.rule_manager = RuleManager()
        self.logger = Logger()
        self.iptables_manager = IPTablesManager()
        self.running = False
    
    def print_banner(self):
        """Print application banner"""
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║                     Personal Firewall CLI                    ║
║                   Advanced Network Protection                 ║
╚═══════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def start_monitoring(self, interface=None, duration=None):
        """Start packet monitoring"""
        print(f"🚀 Starting firewall monitoring...")
        print(f"Interface: {interface or 'All interfaces'}")
        
        if duration:
            print(f"Duration: {duration} seconds")
        
        # Set up signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        
        try:
            success = self.packet_sniffer.start_monitoring(interface)
            if not success:
                print("❌ Failed to start monitoring. Please run as administrator.")
                return
            
            self.running = True
            print("✅ Monitoring started successfully!")
            print("Press Ctrl+C to stop monitoring")
            print("-" * 60)
            
            start_time = time.time()
            last_stats_time = start_time
            
            while self.running:
                current_time = time.time()
                
                # Print statistics every 10 seconds
                if current_time - last_stats_time >= 10:
                    self._print_statistics()
                    last_stats_time = current_time
                
                # Check duration limit
                if duration and (current_time - start_time) >= duration:
                    print(f"\n⏰ Monitoring duration ({duration}s) reached. Stopping...")
                    break
                
                time.sleep(1)
                
        except KeyboardInterrupt:
            pass
        finally:
            self._stop_monitoring()
    
    def _signal_handler(self, signum, frame):
        """Handle interrupt signal"""
        print("\n🛑 Interrupt received. Stopping monitoring...")
        self.running = False
    
    def _stop_monitoring(self):
        """Stop monitoring and print final statistics"""
        self.packet_sniffer.stop_monitoring()
        self.running = False
        
        print("\n" + "=" * 60)
        print("📊 Final Statistics:")
        self._print_statistics()
        print("👋 Firewall monitoring stopped.")
    
    def _print_statistics(self):
        """Print current statistics"""
        stats = self.packet_sniffer.get_stats()
        log_stats = self.logger.get_log_stats()
        
        uptime = int(stats['uptime_seconds'])
        hours = uptime // 3600
        minutes = (uptime % 3600) // 60
        seconds = uptime % 60
        
        print(f"""
📈 Live Statistics:
   Status: {'🟢 Running' if stats['is_running'] else '🔴 Stopped'}
   Uptime: {hours:02d}:{minutes:02d}:{seconds:02d}
   Total Packets: {stats['packet_count']:,}
   Allowed: {stats['allowed_count']:,} | Blocked: {stats['blocked_count']:,}
   Suspicious: {log_stats['suspicious_packets']:,}
   Rate: {stats['packets_per_second']:.1f} packets/sec
   Active Connections: {stats['active_connections']}
        """)
    
    def list_rules(self):
        """List current firewall rules"""
        print("📋 Current Firewall Rules:")
        print("=" * 50)
        
        # IP Rules
        print("\n🌐 IP Rules:")
        blocked_ips = self.rule_manager.rules['ip_rules']['blocked_ips']
        allowed_ips = self.rule_manager.rules['ip_rules']['allowed_ips']
        
        if blocked_ips:
            print("  🚫 Blocked IPs:")
            for ip in blocked_ips:
                print(f"    - {ip}")
        
        if allowed_ips:
            print("  ✅ Allowed IPs:")
            for ip in allowed_ips:
                print(f"    - {ip}")
        
        # Port Rules
        print("\n🔌 Port Rules:")
        blocked_ports = self.rule_manager.rules['port_rules']['blocked_ports']
        allowed_ports = self.rule_manager.rules['port_rules']['allowed_ports']
        
        if blocked_ports:
            print("  🚫 Blocked Ports:")
            for port in blocked_ports:
                print(f"    - {port}")
        
        if allowed_ports:
            print("  ✅ Allowed Ports:")
            for port in allowed_ports:
                print(f"    - {port}")
        
        # General Settings
        print("\n⚙️ General Settings:")
        settings = self.rule_manager.rules['general_settings']
        print(f"  Default Action: {settings['default_action'].upper()}")
        print(f"  Log All Traffic: {settings['log_all_traffic']}")
        print(f"  Log Blocked Only: {settings['log_blocked_only']}")
    
    def add_rule(self, rule_type, value, action):
        """Add a new rule"""
        try:
            if rule_type == 'ip':
                self.rule_manager.add_ip_rule(value, action)
                print(f"✅ IP rule added: {action.upper()} {value}")
            elif rule_type == 'port':
                port = int(value)
                self.rule_manager.add_port_rule(port, action)
                print(f"✅ Port rule added: {action.upper()} {port}")
            else:
                print(f"❌ Unknown rule type: {rule_type}")
        except Exception as e:
            print(f"❌ Error adding rule: {e}")
    
    def remove_rule(self, rule_type, value, action):
        """Remove a rule"""
        try:
            if rule_type == 'ip':
                self.rule_manager.remove_ip_rule(value, action)
                print(f"✅ IP rule removed: {action.upper()} {value}")
            elif rule_type == 'port':
                port = int(value)
                self.rule_manager.remove_port_rule(port, action)
                print(f"✅ Port rule removed: {action.upper()} {port}")
            else:
                print(f"❌ Unknown rule type: {rule_type}")
        except Exception as e:
            print(f"❌ Error removing rule: {e}")
    
    def show_logs(self, count=50):
        """Show recent logs"""
        print(f"📋 Recent Firewall Logs (last {count}):")
        print("=" * 80)
        
        logs = self.logger.get_recent_logs(count)
        
        if not logs:
            print("No logs found.")
            return
        
        for log in logs[-count:]:
            timestamp = log.get('timestamp', '')
            action = log.get('action', '')
            packet_info = log.get('packet_info', {})
            reason = log.get('reason', '')
            
            src_ip = packet_info.get('src_ip', 'N/A')
            dst_ip = packet_info.get('dst_ip', 'N/A')
            protocol = packet_info.get('protocol_name', 'N/A')
            port = packet_info.get('dst_port', 'N/A')
            
            action_symbol = "🚫" if action == "BLOCKED" else "✅"
            
            print(f"{action_symbol} [{timestamp}] {action}: {src_ip} -> {dst_ip} | "
                  f"{protocol}:{port} | {reason}")
    
    def show_status(self):
        """Show firewall status"""
        print("🔍 Firewall Status:")
        print("=" * 40)
        
        stats = self.packet_sniffer.get_stats()
        log_stats = self.logger.get_log_stats()
        rules_summary = self.rule_manager.get_rules_summary()
        iptables_status = self.iptables_manager.get_status()
        
        print(f"Monitoring: {'🟢 Active' if stats['is_running'] else '🔴 Inactive'}")
        print(f"Total Packets Processed: {stats['packet_count']:,}")
        print(f"Blocked: {stats['blocked_count']:,} | Allowed: {stats['allowed_count']:,}")
        print(f"Active Rules: {rules_summary['blocked_ips_count'] + rules_summary['blocked_ports_count']}")
        print(f"Default Action: {rules_summary['default_action'].upper()}")
        print(f"IPTables Available: {'✅ Yes' if iptables_status['available'] else '❌ No'}")
    
    def clear_logs(self):
        """Clear all logs"""
        confirmation = input("Are you sure you want to clear all logs? (y/N): ")
        if confirmation.lower() == 'y':
            self.logger.clear_logs()
            print("✅ Logs cleared successfully.")
        else:
            print("❌ Log clearing cancelled.")
    
    def sync_iptables(self):
        """Sync rules to iptables"""
        if not self.iptables_manager.is_available():
            print("❌ IPTables is not available on this system.")
            return
        
        print("🔄 Syncing rules to IPTables...")
        
        try:
            # Sync blocked IPs
            blocked_ips = self.rule_manager.rules['ip_rules']['blocked_ips']
            for ip in blocked_ips:
                self.iptables_manager.add_ip_block_rule(ip)
            
            # Sync blocked ports
            blocked_ports = self.rule_manager.rules['port_rules']['blocked_ports']
            for port in blocked_ports:
                self.iptables_manager.add_port_block_rule(port)
            
            print("✅ Rules synchronized to IPTables successfully.")
        except Exception as e:
            print(f"❌ Error syncing to IPTables: {e}")
    
    def list_interfaces(self):
        """List available network interfaces"""
        print("🌐 Available Network Interfaces:")
        print("=" * 40)
        
        interfaces = self.packet_sniffer.get_network_interfaces()
        
        for i, interface in enumerate(interfaces, 1):
            print(f"{i}. {interface['name']}")
            for addr in interface['addresses']:
                print(f"   └─ {addr}")
    
    def export_config(self, filename):
        """Export configuration to file"""
        try:
            config = {
                'rules': self.rule_manager.rules,
                'export_timestamp': time.time()
            }
            
            with open(filename, 'w') as f:
                json.dump(config, f, indent=4)
            
            print(f"✅ Configuration exported to {filename}")
        except Exception as e:
            print(f"❌ Error exporting configuration: {e}")
    
    def import_config(self, filename):
        """Import configuration from file"""
        try:
            with open(filename, 'r') as f:
                config = json.load(f)
            
            self.rule_manager.rules = config['rules']
            self.rule_manager.save_rules()
            
            print(f"✅ Configuration imported from {filename}")
        except Exception as e:
            print(f"❌ Error importing configuration: {e}")

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Personal Firewall - Advanced Network Protection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s monitor --interface eth0 --duration 300
  %(prog)s rules list
  %(prog)s rules add ip 192.168.1.100 block
  %(prog)s rules add port 22 block
  %(prog)s logs show --count 100
  %(prog)s status
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Monitor command
    monitor_parser = subparsers.add_parser('monitor', help='Start packet monitoring')
    monitor_parser.add_argument('--interface', '-i', help='Network interface to monitor')
    monitor_parser.add_argument('--duration', '-d', type=int, help='Monitoring duration in seconds')
    
    # Rules command
    rules_parser = subparsers.add_parser('rules', help='Manage firewall rules')
    rules_subparsers = rules_parser.add_subparsers(dest='rules_action')
    
    rules_subparsers.add_parser('list', help='List current rules')
    
    add_parser = rules_subparsers.add_parser('add', help='Add a rule')
    add_parser.add_argument('type', choices=['ip', 'port'], help='Rule type')
    add_parser.add_argument('value', help='IP address or port number')
    add_parser.add_argument('action', choices=['block', 'allow'], help='Action to take')
    
    remove_parser = rules_subparsers.add_parser('remove', help='Remove a rule')
    remove_parser.add_argument('type', choices=['ip', 'port'], help='Rule type')
    remove_parser.add_argument('value', help='IP address or port number')
    remove_parser.add_argument('action', choices=['block', 'allow'], help='Action to remove')
    
    # Logs command
    logs_parser = subparsers.add_parser('logs', help='Manage logs')
    logs_subparsers = logs_parser.add_subparsers(dest='logs_action')
    
    show_parser = logs_subparsers.add_parser('show', help='Show recent logs')
    show_parser.add_argument('--count', '-c', type=int, default=50, help='Number of logs to show')
    
    logs_subparsers.add_parser('clear', help='Clear all logs')
    
    # Status command
    subparsers.add_parser('status', help='Show firewall status')
    
    # IPTables command
    subparsers.add_parser('sync-iptables', help='Sync rules to iptables')
    
    # Interfaces command
    subparsers.add_parser('interfaces', help='List network interfaces')
    
    # Config commands
    config_parser = subparsers.add_parser('config', help='Configuration management')
    config_subparsers = config_parser.add_subparsers(dest='config_action')
    
    export_parser = config_subparsers.add_parser('export', help='Export configuration')
    export_parser.add_argument('filename', help='Output filename')
    
    import_parser = config_subparsers.add_parser('import', help='Import configuration')
    import_parser.add_argument('filename', help='Input filename')
    
    # GUI command
    subparsers.add_parser('gui', help='Launch GUI interface')
    
    args = parser.parse_args()
    
    # Initialize CLI
    cli = FirewallCLI()
    cli.print_banner()
    
    if not args.command:
        parser.print_help()
        return
    
    # Execute commands
    try:
        if args.command == 'monitor':
            cli.start_monitoring(args.interface, args.duration)
        
        elif args.command == 'rules':
            if args.rules_action == 'list':
                cli.list_rules()
            elif args.rules_action == 'add':
                cli.add_rule(args.type, args.value, args.action)
            elif args.rules_action == 'remove':
                cli.remove_rule(args.type, args.value, args.action)
        
        elif args.command == 'logs':
            if args.logs_action == 'show':
                cli.show_logs(args.count)
            elif args.logs_action == 'clear':
                cli.clear_logs()
        
        elif args.command == 'status':
            cli.show_status()
        
        elif args.command == 'sync-iptables':
            cli.sync_iptables()
        
        elif args.command == 'interfaces':
            cli.list_interfaces()
        
        elif args.command == 'config':
            if args.config_action == 'export':
                cli.export_config(args.filename)
            elif args.config_action == 'import':
                cli.import_config(args.filename)
        
        elif args.command == 'gui':
            print("🚀 Launching GUI interface...")
            from firewall_gui import FirewallGUI
            app = FirewallGUI()
            app.run()
    
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
