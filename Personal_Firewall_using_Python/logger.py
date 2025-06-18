import json
import os
from datetime import datetime
from typing import Dict, Any

class Logger:
    """Handles logging of firewall events"""
    
    def __init__(self, log_file='firewall.log', json_log_file='firewall_events.json'):
        self.log_file = log_file
        self.json_log_file = json_log_file
        self.ensure_log_files()
    
    def ensure_log_files(self):
        """Ensure log files exist"""
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w') as f:
                f.write(f"Firewall Log Started - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 60 + "\n")
        
        if not os.path.exists(self.json_log_file):
            with open(self.json_log_file, 'w') as f:
                json.dump([], f)
    
    def log_packet(self, packet_info: Dict[str, Any], action: str, reason: str = ""):
        """Log packet information"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Text log
        log_entry = f"[{timestamp}] {action.upper()}: {packet_info.get('src_ip', 'N/A')} -> {packet_info.get('dst_ip', 'N/A')} | "
        log_entry += f"Protocol: {packet_info.get('protocol', 'N/A')} | "
        log_entry += f"Port: {packet_info.get('dst_port', 'N/A')} | "
        log_entry += f"Size: {packet_info.get('size', 'N/A')} bytes"
        if reason:
            log_entry += f" | Reason: {reason}"
        log_entry += "\n"
        
        with open(self.log_file, 'a') as f:
            f.write(log_entry)
        
        # JSON log
        json_entry = {
            'timestamp': timestamp,
            'action': action,
            'packet_info': packet_info,
            'reason': reason
        }
        
        try:
            with open(self.json_log_file, 'r') as f:
                logs = json.load(f)
        except:
            logs = []
        
        logs.append(json_entry)
        
        # Keep only last 1000 entries
        if len(logs) > 1000:
            logs = logs[-1000:]
        
        with open(self.json_log_file, 'w') as f:
            json.dump(logs, f, indent=2)
    
    def get_recent_logs(self, count: int = 100) -> list:
        """Get recent log entries"""
        try:
            with open(self.json_log_file, 'r') as f:
                logs = json.load(f)
            return logs[-count:] if logs else []
        except:
            return []
    
    def get_log_stats(self) -> Dict[str, int]:
        """Get logging statistics"""
        try:
            with open(self.json_log_file, 'r') as f:
                logs = json.load(f)
            
            stats = {
                'total_packets': len(logs),
                'blocked_packets': sum(1 for log in logs if log['action'] == 'BLOCKED'),
                'allowed_packets': sum(1 for log in logs if log['action'] == 'ALLOWED'),
                'suspicious_packets': sum(1 for log in logs if 'suspicious' in log.get('reason', '').lower())
            }
            return stats
        except:
            return {'total_packets': 0, 'blocked_packets': 0, 'allowed_packets': 0, 'suspicious_packets': 0}
    
    def clear_logs(self):
        """Clear all logs"""
        with open(self.log_file, 'w') as f:
            f.write(f"Firewall Log Cleared - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 60 + "\n")
        
        with open(self.json_log_file, 'w') as f:
            json.dump([], f)
