import threading
import time
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from rule_manager import RuleManager
from logger import Logger
import psutil
from datetime import datetime

class PacketSniffer:
    """Core packet sniffing and filtering engine"""
    
    def __init__(self):
        self.rule_manager = RuleManager()
        self.logger = Logger()
        self.is_running = False
        self.packet_count = 0
        self.blocked_count = 0
        self.allowed_count = 0
        self.suspicious_patterns = [
            'port_scan',
            'syn_flood',
            'icmp_flood',
            'unusual_traffic'
        ]
        self.connection_tracker = {}
        self.start_time = None
        
    def start_monitoring(self, interface=None):
        """Start packet monitoring"""
        self.is_running = True
        self.start_time = datetime.now()
        self.packet_count = 0
        self.blocked_count = 0
        self.allowed_count = 0
        
        print(f"Starting firewall monitoring on interface: {interface or 'all'}")
        
        try:
            # Start packet sniffing in a separate thread
            sniff_thread = threading.Thread(
                target=self._sniff_packets,
                args=(interface,),
                daemon=True
            )
            sniff_thread.start()
            return True
        except Exception as e:
            print(f"Error starting packet sniffer: {e}")
            return False
    
    def stop_monitoring(self):
        """Stop packet monitoring"""
        self.is_running = False
        print("Firewall monitoring stopped")
    
    def _sniff_packets(self, interface):
        """Main packet sniffing function"""
        try:
            sniff(
                iface=interface,
                prn=self._process_packet,
                stop_filter=lambda x: not self.is_running,
                store=0
            )
        except Exception as e:
            print(f"Error in packet sniffing: {e}")
    
    def _process_packet(self, packet):
        """Process each captured packet"""
        if not self.is_running:
            return
            
        self.packet_count += 1
        
        try:
            packet_info = self._extract_packet_info(packet)
            if packet_info:
                action, reason = self._evaluate_packet(packet_info)
                
                if action == 'BLOCKED':
                    self.blocked_count += 1
                elif action == 'ALLOWED':
                    self.allowed_count += 1
                
                # Log based on settings
                should_log = False
                if self.rule_manager.rules['general_settings']['log_all_traffic']:
                    should_log = True
                elif self.rule_manager.rules['general_settings']['log_blocked_only'] and action == 'BLOCKED':
                    should_log = True
                elif 'suspicious' in reason.lower():
                    should_log = True
                
                if should_log:
                    self.logger.log_packet(packet_info, action, reason)
                
                # Update connection tracker
                self._update_connection_tracker(packet_info)
                
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def _extract_packet_info(self, packet) -> dict:
        """Extract relevant information from packet"""
        info = {}
        
        try:
            if IP in packet:
                info['src_ip'] = packet[IP].src
                info['dst_ip'] = packet[IP].dst
                info['protocol'] = packet[IP].proto
                info['size'] = len(packet)
                info['timestamp'] = time.time()
                
                # Protocol specific info
                if TCP in packet:
                    info['protocol_name'] = 'TCP'
                    info['src_port'] = packet[TCP].sport
                    info['dst_port'] = packet[TCP].dport
                    info['flags'] = packet[TCP].flags
                elif UDP in packet:
                    info['protocol_name'] = 'UDP'
                    info['src_port'] = packet[UDP].sport
                    info['dst_port'] = packet[UDP].dport
                elif ICMP in packet:
                    info['protocol_name'] = 'ICMP'
                    info['icmp_type'] = packet[ICMP].type
                    info['icmp_code'] = packet[ICMP].code
                else:
                    info['protocol_name'] = f"Protocol_{packet[IP].proto}"
                
                return info
        except Exception as e:
            print(f"Error extracting packet info: {e}")
        
        return None
    
    def _evaluate_packet(self, packet_info) -> tuple:
        """Evaluate packet against rules and return (action, reason)"""
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        dst_port = packet_info.get('dst_port')
        protocol = packet_info.get('protocol_name', '').upper()
        
        # Check for suspicious patterns first
        suspicious_reason = self._check_suspicious_patterns(packet_info)
        if suspicious_reason:
            return 'BLOCKED', f"Suspicious activity: {suspicious_reason}"
        
        # Check IP rules
        if src_ip and self.rule_manager.is_ip_blocked(src_ip):
            return 'BLOCKED', f"Blocked source IP: {src_ip}"
        
        if dst_ip and self.rule_manager.is_ip_blocked(dst_ip):
            return 'BLOCKED', f"Blocked destination IP: {dst_ip}"
        
        # Check port rules
        if dst_port and self.rule_manager.is_port_blocked(dst_port):
            return 'BLOCKED', f"Blocked port: {dst_port}"
        
        # Check protocol rules
        blocked_protocols = self.rule_manager.rules['protocol_rules']['blocked_protocols']
        if protocol in [p.upper() for p in blocked_protocols]:
            return 'BLOCKED', f"Blocked protocol: {protocol}"
        
        # Default action
        default_action = self.rule_manager.rules['general_settings']['default_action']
        if default_action == 'block':
            return 'BLOCKED', "Default block policy"
        else:
            return 'ALLOWED', "Default allow policy"
    
    def _check_suspicious_patterns(self, packet_info) -> str:
        """Check for suspicious traffic patterns"""
        src_ip = packet_info.get('src_ip')
        dst_port = packet_info.get('dst_port')
        protocol = packet_info.get('protocol_name', '').upper()
        flags = packet_info.get('flags', 0)
        
        # Port scanning detection
        if src_ip:
            current_time = time.time()
            if src_ip not in self.connection_tracker:
                self.connection_tracker[src_ip] = {
                    'ports': set(),
                    'last_seen': current_time,
                    'packet_count': 0
                }
            
            tracker = self.connection_tracker[src_ip]
            tracker['packet_count'] += 1
            tracker['last_seen'] = current_time
            
            if dst_port:
                tracker['ports'].add(dst_port)
                
                # Port scan detection: many different ports from same IP
                if len(tracker['ports']) > 10 and tracker['packet_count'] > 20:
                    return "port_scan"
            
            # SYN flood detection
            if protocol == 'TCP' and flags == 2:  # SYN flag
                if tracker['packet_count'] > 50:
                    return "syn_flood"
        
        # ICMP flood detection
        if protocol == 'ICMP' and src_ip:
            if src_ip in self.connection_tracker:
                if self.connection_tracker[src_ip]['packet_count'] > 30:
                    return "icmp_flood"
        
        # Unusual port access
        if dst_port and dst_port in [22, 23, 135, 139, 445, 1433, 3389]:
            return "unusual_port_access"
        
        return ""
    
    def _update_connection_tracker(self, packet_info):
        """Update connection tracking information"""
        current_time = time.time()
        
        # Clean old entries (older than 5 minutes)
        expired_ips = []
        for ip, data in self.connection_tracker.items():
            if current_time - data['last_seen'] > 300:  # 5 minutes
                expired_ips.append(ip)
        
        for ip in expired_ips:
            del self.connection_tracker[ip]
    
    def get_stats(self) -> dict:
        """Get current monitoring statistics"""
        uptime = 0
        if self.start_time:
            uptime = (datetime.now() - self.start_time).total_seconds()
        
        return {
            'is_running': self.is_running,
            'packet_count': self.packet_count,
            'blocked_count': self.blocked_count,
            'allowed_count': self.allowed_count,
            'uptime_seconds': uptime,
            'active_connections': len(self.connection_tracker),
            'packets_per_second': self.packet_count / max(uptime, 1)
        }
    
    def get_network_interfaces(self) -> list:
        """Get available network interfaces"""
        try:
            interfaces = []
            for interface, addrs in psutil.net_if_addrs().items():
                interface_info = {
                    'name': interface,
                    'addresses': []
                }
                for addr in addrs:
                    if addr.family == 2:  # IPv4
                        interface_info['addresses'].append(addr.address)
                interfaces.append(interface_info)
            return interfaces
        except Exception as e:
            print(f"Error getting network interfaces: {e}")
            return []
