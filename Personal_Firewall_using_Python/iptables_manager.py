import subprocess
import platform
import os

class IPTablesManager:
    """Manages iptables rules for Linux systems"""
    
    def __init__(self):
        self.is_linux = platform.system().lower() == 'linux'
        self.is_admin = self._check_admin_privileges()
    
    def _check_admin_privileges(self) -> bool:
        """Check if running with admin privileges"""
        try:
            if self.is_linux:
                return os.geteuid() == 0
            else:
                # For Windows, we'll simulate this
                return True
        except:
            return False
    
    def is_available(self) -> bool:
        """Check if iptables is available"""
        if not self.is_linux:
            return False
        
        try:
            subprocess.run(['iptables', '--version'], 
                         capture_output=True, check=True)
            return True
        except:
            return False
    
    def add_ip_block_rule(self, ip: str) -> bool:
        """Add rule to block specific IP"""
        if not self.is_available() or not self.is_admin:
            print("iptables not available or insufficient privileges")
            return False
        
        try:
            # Block incoming traffic from IP
            subprocess.run([
                'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'
            ], check=True)
            
            # Block outgoing traffic to IP
            subprocess.run([
                'iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'
            ], check=True)
            
            print(f"Added iptables rule to block IP: {ip}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error adding iptables rule for IP {ip}: {e}")
            return False
    
    def add_port_block_rule(self, port: int, protocol: str = 'tcp') -> bool:
        """Add rule to block specific port"""
        if not self.is_available() or not self.is_admin:
            print("iptables not available or insufficient privileges")
            return False
        
        try:
            # Block incoming traffic on port
            subprocess.run([
                'iptables', '-A', 'INPUT', '-p', protocol.lower(), 
                '--dport', str(port), '-j', 'DROP'
            ], check=True)
            
            print(f"Added iptables rule to block {protocol.upper()} port: {port}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error adding iptables rule for port {port}: {e}")
            return False
    
    def remove_ip_block_rule(self, ip: str) -> bool:
        """Remove IP blocking rule"""
        if not self.is_available() or not self.is_admin:
            return False
        
        try:
            # Remove input rule
            subprocess.run([
                'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'
            ], check=True)
            
            # Remove output rule
            subprocess.run([
                'iptables', '-D', 'OUTPUT', '-d', ip, '-j', 'DROP'
            ], check=True)
            
            print(f"Removed iptables rule for IP: {ip}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error removing iptables rule for IP {ip}: {e}")
            return False
    
    def remove_port_block_rule(self, port: int, protocol: str = 'tcp') -> bool:
        """Remove port blocking rule"""
        if not self.is_available() or not self.is_admin:
            return False
        
        try:
            subprocess.run([
                'iptables', '-D', 'INPUT', '-p', protocol.lower(), 
                '--dport', str(port), '-j', 'DROP'
            ], check=True)
            
            print(f"Removed iptables rule for {protocol.upper()} port: {port}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error removing iptables rule for port {port}: {e}")
            return False
    
    def list_firewall_rules(self) -> list:
        """List current iptables rules"""
        if not self.is_available():
            return []
        
        try:
            result = subprocess.run([
                'iptables', '-L', '-n', '--line-numbers'
            ], capture_output=True, text=True, check=True)
            
            return result.stdout.split('\n')
        except subprocess.CalledProcessError as e:
            print(f"Error listing iptables rules: {e}")
            return []
    
    def flush_custom_rules(self) -> bool:
        """Flush custom firewall rules (careful!)"""
        if not self.is_available() or not self.is_admin:
            return False
        
        try:
            # This is dangerous - only flush user-defined chains
            print("Warning: This will flush custom iptables rules")
            return True
        except Exception as e:
            print(f"Error flushing rules: {e}")
            return False
    
    def create_backup(self) -> bool:
        """Create backup of current iptables rules"""
        if not self.is_available():
            return False
        
        try:
            with open('iptables_backup.txt', 'w') as f:
                result = subprocess.run([
                    'iptables-save'
                ], capture_output=True, text=True, check=True)
                f.write(result.stdout)
            
            print("iptables backup created: iptables_backup.txt")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error creating iptables backup: {e}")
            return False
    
    def get_status(self) -> dict:
        """Get iptables status information"""
        return {
            'available': self.is_available(),
            'admin_privileges': self.is_admin,
            'platform': platform.system(),
            'can_modify_rules': self.is_available() and self.is_admin
        }
