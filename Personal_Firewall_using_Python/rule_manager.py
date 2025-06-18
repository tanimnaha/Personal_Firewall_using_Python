import json
import os
from datetime import datetime
from typing import Dict, List, Any

class RuleManager:
    """Manages firewall rules and configurations"""
    
    def __init__(self, rules_file='firewall_rules.json'):
        self.rules_file = rules_file
        self.rules = self.load_rules()
    
    def load_rules(self) -> Dict:
        """Load rules from JSON file"""
        default_rules = {
            'ip_rules': {
                'blocked_ips': [],
                'allowed_ips': ['127.0.0.1', '192.168.1.0/24']
            },
            'port_rules': {
                'blocked_ports': [22, 23, 135, 139, 445],
                'allowed_ports': [80, 443, 53, 21, 25]
            },
            'protocol_rules': {
                'blocked_protocols': [],
                'allowed_protocols': ['TCP', 'UDP', 'ICMP']
            },
            'general_settings': {
                'default_action': 'allow',  # 'allow' or 'block'
                'log_all_traffic': False,
                'log_blocked_only': True,
                'monitor_mode': True
            }
        }
        
        if os.path.exists(self.rules_file):
            try:
                with open(self.rules_file, 'r') as f:
                    loaded_rules = json.load(f)
                # Merge with defaults to ensure all keys exist
                for key in default_rules:
                    if key not in loaded_rules:
                        loaded_rules[key] = default_rules[key]
                return loaded_rules
            except Exception as e:
                print(f"Error loading rules: {e}")
                return default_rules
        else:
            self.save_rules(default_rules)
            return default_rules
    
    def save_rules(self, rules=None):
        """Save rules to JSON file"""
        if rules is None:
            rules = self.rules
        try:
            with open(self.rules_file, 'w') as f:
                json.dump(rules, f, indent=4)
        except Exception as e:
            print(f"Error saving rules: {e}")
    
    def add_ip_rule(self, ip: str, action: str):
        """Add IP rule (action: 'block' or 'allow')"""
        if action == 'block':
            if ip not in self.rules['ip_rules']['blocked_ips']:
                self.rules['ip_rules']['blocked_ips'].append(ip)
        elif action == 'allow':
            if ip not in self.rules['ip_rules']['allowed_ips']:
                self.rules['ip_rules']['allowed_ips'].append(ip)
        self.save_rules()
    
    def add_port_rule(self, port: int, action: str):
        """Add port rule (action: 'block' or 'allow')"""
        if action == 'block':
            if port not in self.rules['port_rules']['blocked_ports']:
                self.rules['port_rules']['blocked_ports'].append(port)
        elif action == 'allow':
            if port not in self.rules['port_rules']['allowed_ports']:
                self.rules['port_rules']['allowed_ports'].append(port)
        self.save_rules()
    
    def remove_ip_rule(self, ip: str, action: str):
        """Remove IP rule"""
        try:
            if action == 'block':
                self.rules['ip_rules']['blocked_ips'].remove(ip)
            elif action == 'allow':
                self.rules['ip_rules']['allowed_ips'].remove(ip)
            self.save_rules()
        except ValueError:
            pass
    
    def remove_port_rule(self, port: int, action: str):
        """Remove port rule"""
        try:
            if action == 'block':
                self.rules['port_rules']['blocked_ports'].remove(port)
            elif action == 'allow':
                self.rules['port_rules']['allowed_ports'].remove(port)
            self.save_rules()
        except ValueError:
            pass
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP should be blocked"""
        # Check blocked IPs
        for blocked_ip in self.rules['ip_rules']['blocked_ips']:
            if self._ip_matches(ip, blocked_ip):
                return True
        
        # Check allowed IPs
        for allowed_ip in self.rules['ip_rules']['allowed_ips']:
            if self._ip_matches(ip, allowed_ip):
                return False
        
        # Default action
        return self.rules['general_settings']['default_action'] == 'block'
    
    def is_port_blocked(self, port: int) -> bool:
        """Check if port should be blocked"""
        if port in self.rules['port_rules']['blocked_ports']:
            return True
        if port in self.rules['port_rules']['allowed_ports']:
            return False
        return self.rules['general_settings']['default_action'] == 'block'
    
    def _ip_matches(self, ip: str, rule_ip: str) -> bool:
        """Check if IP matches rule (supports CIDR notation)"""
        import ipaddress
        try:
            if '/' in rule_ip:
                # CIDR notation
                network = ipaddress.ip_network(rule_ip, strict=False)
                return ipaddress.ip_address(ip) in network
            else:
                # Exact match
                return ip == rule_ip
        except:
            return ip == rule_ip
    
    def get_rules_summary(self) -> Dict:
        """Get summary of current rules"""
        return {
            'blocked_ips_count': len(self.rules['ip_rules']['blocked_ips']),
            'allowed_ips_count': len(self.rules['ip_rules']['allowed_ips']),
            'blocked_ports_count': len(self.rules['port_rules']['blocked_ports']),
            'allowed_ports_count': len(self.rules['port_rules']['allowed_ports']),
            'default_action': self.rules['general_settings']['default_action']
        }
