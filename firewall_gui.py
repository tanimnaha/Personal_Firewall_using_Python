import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
from datetime import datetime
from packet_sniffer import PacketSniffer
from rule_manager import RuleManager
from logger import Logger
from iptables_manager import IPTablesManager

class FirewallGUI:
    """Modern GUI for Personal Firewall"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Personal Firewall - Advanced Protection")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2c3e50')
        
        # Initialize components
        self.packet_sniffer = PacketSniffer()
        self.rule_manager = RuleManager()
        self.logger = Logger()
        self.iptables_manager = IPTablesManager()
        
        # GUI variables
        self.is_monitoring = tk.BooleanVar()
        self.selected_interface = tk.StringVar()
        self.stats_update_thread = None
        
        # Style configuration
        self.setup_styles()
        
        # Create GUI components
        self.create_main_interface()
        
        # Start stats update thread
        self.start_stats_thread()
    
    def setup_styles(self):
        """Configure modern styling"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors and fonts
        style.configure('Header.TLabel', 
                       background='#2c3e50', 
                       foreground='#ecf0f1',
                       font=('Arial', 14, 'bold'))
        
        style.configure('Status.TLabel',
                       background='#34495e',
                       foreground='#ecf0f1',
                       font=('Arial', 10))
        
        style.configure('Success.TLabel',
                       background='#27ae60',
                       foreground='white',
                       font=('Arial', 10, 'bold'))
        
        style.configure('Warning.TLabel',
                       background='#e74c3c',
                       foreground='white',
                       font=('Arial', 10, 'bold'))
        
        style.configure('Modern.TButton',
                       background='#3498db',
                       foreground='white',
                       font=('Arial', 10, 'bold'))
        
        style.configure('Danger.TButton',
                       background='#e74c3c',
                       foreground='white',
                       font=('Arial', 10, 'bold'))
    
    def create_main_interface(self):
        """Create the main interface"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.create_monitoring_tab()
        self.create_rules_tab()
        self.create_logs_tab()
        self.create_settings_tab()
    
    def create_monitoring_tab(self):
        """Create monitoring and statistics tab"""
        monitor_frame = ttk.Frame(self.notebook)
        self.notebook.add(monitor_frame, text="🛡️ Monitoring")
        
        # Header
        header_frame = ttk.Frame(monitor_frame)
        header_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(header_frame, text="Firewall Monitoring Dashboard", 
                 style='Header.TLabel').pack(side=tk.LEFT)
        
        # Control panel
        control_frame = ttk.LabelFrame(monitor_frame, text="Control Panel")
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Interface selection
        interface_frame = ttk.Frame(control_frame)
        interface_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(interface_frame, text="Network Interface:").pack(side=tk.LEFT)
        self.interface_combo = ttk.Combobox(interface_frame, textvariable=self.selected_interface)
        self.interface_combo.pack(side=tk.LEFT, padx=(5, 10))
        
        # Update interface list
        self.update_interface_list()
        
        # Control buttons
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.start_button = ttk.Button(button_frame, text="🚀 Start Monitoring", 
                                      command=self.toggle_monitoring,
                                      style='Modern.TButton')
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="🔄 Refresh Interfaces", 
                  command=self.update_interface_list).pack(side=tk.LEFT, padx=5)
        
        # Statistics panel
        stats_frame = ttk.LabelFrame(monitor_frame, text="Real-time Statistics")
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create stats display
        stats_container = ttk.Frame(stats_frame)
        stats_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left side - numerical stats
        left_stats = ttk.Frame(stats_container)
        left_stats.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.stats_labels = {}
        stats_info = [
            ("Status", "🔴 Stopped"),
            ("Uptime", "00:00:00"),
            ("Total Packets", "0"),
            ("Allowed", "0"),
            ("Blocked", "0"),
            ("Suspicious", "0"),
            ("Packets/Sec", "0.0"),
            ("Active Connections", "0")
        ]
        
        for i, (label, default_value) in enumerate(stats_info):
            frame = ttk.Frame(left_stats)
            frame.pack(fill=tk.X, pady=2)
            
            ttk.Label(frame, text=f"{label}:", font=('Arial', 10, 'bold')).pack(side=tk.LEFT)
            self.stats_labels[label.lower().replace(' ', '_')] = ttk.Label(
                frame, text=default_value, style='Status.TLabel'
            )
            self.stats_labels[label.lower().replace(' ', '_')].pack(side=tk.RIGHT)
        
        # Right side - live activity
        right_stats = ttk.Frame(stats_container)
        right_stats.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0))
        
        ttk.Label(right_stats, text="Live Activity", 
                 font=('Arial', 12, 'bold')).pack()
        
        self.activity_text = scrolledtext.ScrolledText(
            right_stats, height=15, width=50,
            bg='#34495e', fg='#ecf0f1', font=('Consolas', 9)
        )
        self.activity_text.pack(fill=tk.BOTH, expand=True, pady=5)
    
    def create_rules_tab(self):
        """Create rules management tab"""
        rules_frame = ttk.Frame(self.notebook)
        self.notebook.add(rules_frame, text="⚙️ Rules")
        
        # Header
        ttk.Label(rules_frame, text="Firewall Rules Management", 
                 style='Header.TLabel').pack(pady=10)
        
        # Create sub-tabs for different rule types
        rules_notebook = ttk.Notebook(rules_frame)
        rules_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # IP Rules tab
        self.create_ip_rules_tab(rules_notebook)
        
        # Port Rules tab
        self.create_port_rules_tab(rules_notebook)
        
        # General Settings tab
        self.create_general_settings_tab(rules_notebook)
    
    def create_ip_rules_tab(self, parent):
        """Create IP rules management tab"""
        ip_frame = ttk.Frame(parent)
        parent.add(ip_frame, text="IP Rules")
        
        # Add IP rule section
        add_frame = ttk.LabelFrame(ip_frame, text="Add IP Rule")
        add_frame.pack(fill=tk.X, padx=10, pady=5)
        
        input_frame = ttk.Frame(add_frame)
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(input_frame, text="IP Address:").pack(side=tk.LEFT)
        self.ip_entry = ttk.Entry(input_frame, width=20)
        self.ip_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(input_frame, text="Block IP", 
                  command=lambda: self.add_ip_rule('block')).pack(side=tk.LEFT, padx=2)
        ttk.Button(input_frame, text="Allow IP", 
                  command=lambda: self.add_ip_rule('allow')).pack(side=tk.LEFT, padx=2)
        
        # Current rules display
        rules_display_frame = ttk.LabelFrame(ip_frame, text="Current IP Rules")
        rules_display_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Blocked IPs
        blocked_frame = ttk.Frame(rules_display_frame)
        blocked_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        ttk.Label(blocked_frame, text="Blocked IPs", 
                 font=('Arial', 11, 'bold')).pack()
        
        self.blocked_ips_listbox = tk.Listbox(blocked_frame, height=10,
                                             bg='#e74c3c', fg='white')
        self.blocked_ips_listbox.pack(fill=tk.BOTH, expand=True, pady=5)
        
        ttk.Button(blocked_frame, text="Remove Selected", 
                  command=lambda: self.remove_ip_rule('block')).pack(pady=2)
        
        # Allowed IPs
        allowed_frame = ttk.Frame(rules_display_frame)
        allowed_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)
        
        ttk.Label(allowed_frame, text="Allowed IPs", 
                 font=('Arial', 11, 'bold')).pack()
        
        self.allowed_ips_listbox = tk.Listbox(allowed_frame, height=10,
                                             bg='#27ae60', fg='white')
        self.allowed_ips_listbox.pack(fill=tk.BOTH, expand=True, pady=5)
        
        ttk.Button(allowed_frame, text="Remove Selected", 
                  command=lambda: self.remove_ip_rule('allow')).pack(pady=2)
        
        # Update IP rules display
        self.update_ip_rules_display()
    
    def create_port_rules_tab(self, parent):
        """Create port rules management tab"""
        port_frame = ttk.Frame(parent)
        parent.add(port_frame, text="Port Rules")
        
        # Add port rule section
        add_frame = ttk.LabelFrame(port_frame, text="Add Port Rule")
        add_frame.pack(fill=tk.X, padx=10, pady=5)
        
        input_frame = ttk.Frame(add_frame)
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(input_frame, text="Port:").pack(side=tk.LEFT)
        self.port_entry = ttk.Entry(input_frame, width=10)
        self.port_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(input_frame, text="Block Port", 
                  command=lambda: self.add_port_rule('block')).pack(side=tk.LEFT, padx=2)
        ttk.Button(input_frame, text="Allow Port", 
                  command=lambda: self.add_port_rule('allow')).pack(side=tk.LEFT, padx=2)
        
        # Current port rules display
        rules_display_frame = ttk.LabelFrame(port_frame, text="Current Port Rules")
        rules_display_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Blocked ports
        blocked_frame = ttk.Frame(rules_display_frame)
        blocked_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        ttk.Label(blocked_frame, text="Blocked Ports", 
                 font=('Arial', 11, 'bold')).pack()
        
        self.blocked_ports_listbox = tk.Listbox(blocked_frame, height=10,
                                               bg='#e74c3c', fg='white')
        self.blocked_ports_listbox.pack(fill=tk.BOTH, expand=True, pady=5)
        
        ttk.Button(blocked_frame, text="Remove Selected", 
                  command=lambda: self.remove_port_rule('block')).pack(pady=2)
        
        # Allowed ports
        allowed_frame = ttk.Frame(rules_display_frame)
        allowed_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)
        
        ttk.Label(allowed_frame, text="Allowed Ports", 
                 font=('Arial', 11, 'bold')).pack()
        
        self.allowed_ports_listbox = tk.Listbox(allowed_frame, height=10,
                                               bg='#27ae60', fg='white')
        self.allowed_ports_listbox.pack(fill=tk.BOTH, expand=True, pady=5)
        
        ttk.Button(allowed_frame, text="Remove Selected", 
                  command=lambda: self.remove_port_rule('allow')).pack(pady=2)
        
        # Update port rules display
        self.update_port_rules_display()
    
    def create_general_settings_tab(self, parent):
        """Create general settings tab"""
        settings_frame = ttk.Frame(parent)
        parent.add(settings_frame, text="General Settings")
        
        # Default action
        default_frame = ttk.LabelFrame(settings_frame, text="Default Action")
        default_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.default_action = tk.StringVar(value=self.rule_manager.rules['general_settings']['default_action'])
        
        ttk.Radiobutton(default_frame, text="Allow by default", 
                       variable=self.default_action, value='allow',
                       command=self.update_default_action).pack(anchor=tk.W, padx=5)
        ttk.Radiobutton(default_frame, text="Block by default", 
                       variable=self.default_action, value='block',
                       command=self.update_default_action).pack(anchor=tk.W, padx=5)
        
        # Logging settings
        logging_frame = ttk.LabelFrame(settings_frame, text="Logging Settings")
        logging_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.log_all = tk.BooleanVar(value=self.rule_manager.rules['general_settings']['log_all_traffic'])
        self.log_blocked = tk.BooleanVar(value=self.rule_manager.rules['general_settings']['log_blocked_only'])
        
        ttk.Checkbutton(logging_frame, text="Log all traffic", 
                       variable=self.log_all,
                       command=self.update_logging_settings).pack(anchor=tk.W, padx=5)
        ttk.Checkbutton(logging_frame, text="Log blocked traffic only", 
                       variable=self.log_blocked,
                       command=self.update_logging_settings).pack(anchor=tk.W, padx=5)
        
        # IPTables integration
        iptables_frame = ttk.LabelFrame(settings_frame, text="System Integration")
        iptables_frame.pack(fill=tk.X, padx=10, pady=5)
        
        iptables_status = self.iptables_manager.get_status()
        status_text = "✅ Available" if iptables_status['available'] else "❌ Not Available"
        
        ttk.Label(iptables_frame, 
                 text=f"IPTables Status: {status_text}").pack(anchor=tk.W, padx=5)
        ttk.Label(iptables_frame, 
                 text=f"Admin Privileges: {'✅ Yes' if iptables_status['admin_privileges'] else '❌ No'}").pack(anchor=tk.W, padx=5)
        
        if iptables_status['available']:
            ttk.Button(iptables_frame, text="Sync Rules to IPTables", 
                      command=self.sync_to_iptables).pack(anchor=tk.W, padx=5, pady=2)
    
    def create_logs_tab(self):
        """Create logs and audit tab"""
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="📋 Logs")
        
        # Header and controls
        header_frame = ttk.Frame(logs_frame)
        header_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(header_frame, text="Firewall Logs & Audit Trail", 
                 style='Header.TLabel').pack(side=tk.LEFT)
        
        # Control buttons
        button_frame = ttk.Frame(header_frame)
        button_frame.pack(side=tk.RIGHT)
        
        ttk.Button(button_frame, text="🔄 Refresh", 
                  command=self.update_logs_display).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="🗑️ Clear Logs", 
                  command=self.clear_logs,
                  style='Danger.TButton').pack(side=tk.LEFT, padx=2)
        
        # Logs display
        logs_display_frame = ttk.LabelFrame(logs_frame, text="Recent Activity")
        logs_display_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create treeview for logs
        columns = ('Timestamp', 'Action', 'Source IP', 'Dest IP', 'Protocol', 'Port', 'Reason')
        self.logs_tree = ttk.Treeview(logs_display_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.logs_tree.heading(col, text=col)
            self.logs_tree.column(col, width=120)
        
        # Scrollbar for treeview
        logs_scrollbar = ttk.Scrollbar(logs_display_frame, orient=tk.VERTICAL, command=self.logs_tree.yview)
        self.logs_tree.configure(yscrollcommand=logs_scrollbar.set)
        
        self.logs_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        logs_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Update logs display
        self.update_logs_display()
    
    def create_settings_tab(self):
        """Create application settings tab"""
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="🔧 Settings")
        
        ttk.Label(settings_frame, text="Application Settings", 
                 style='Header.TLabel').pack(pady=10)
        
        # Performance settings
        perf_frame = ttk.LabelFrame(settings_frame, text="Performance")
        perf_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(perf_frame, text="Packet Buffer Size:").pack(anchor=tk.W, padx=5)
        self.buffer_size = tk.IntVar(value=1000)
        ttk.Scale(perf_frame, from_=100, to=5000, 
                 variable=self.buffer_size, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=5)
        
        # About section
        about_frame = ttk.LabelFrame(settings_frame, text="About")
        about_frame.pack(fill=tk.X, padx=10, pady=5)
        
        about_text = """
Personal Firewall v1.0
Built with Python, Scapy, and Tkinter

Features:
• Real-time packet monitoring
• Rule-based traffic filtering
• Suspicious activity detection
• IPTables integration (Linux)
• Comprehensive logging
• Modern GUI interface

© 2025 Personal Firewall Project
        """
        
        ttk.Label(about_frame, text=about_text, justify=tk.LEFT).pack(padx=10, pady=10)
    
    # Event handlers and utility methods
    
    def toggle_monitoring(self):
        """Toggle firewall monitoring on/off"""
        if not self.is_monitoring.get():
            # Start monitoring
            interface = self.selected_interface.get() if self.selected_interface.get() else None
            
            try:
                success = self.packet_sniffer.start_monitoring(interface)
                if success:
                    self.is_monitoring.set(True)
                    self.start_button.config(text="🛑 Stop Monitoring", style='Danger.TButton')
                    self.add_activity_message("🚀 Firewall monitoring started", "success")
                else:
                    messagebox.showerror("Error", "Failed to start packet monitoring. Please run as administrator.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to start monitoring: {str(e)}")
        else:
            # Stop monitoring
            self.packet_sniffer.stop_monitoring()
            self.is_monitoring.set(False)
            self.start_button.config(text="🚀 Start Monitoring", style='Modern.TButton')
            self.add_activity_message("🛑 Firewall monitoring stopped", "info")
    
    def update_interface_list(self):
        """Update the list of available network interfaces"""
        interfaces = self.packet_sniffer.get_network_interfaces()
        interface_names = [iface['name'] for iface in interfaces]
        
        self.interface_combo['values'] = interface_names
        if interface_names and not self.selected_interface.get():
            self.selected_interface.set(interface_names[0])
    
    def add_ip_rule(self, action):
        """Add IP rule"""
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showwarning("Warning", "Please enter an IP address")
            return
        
        try:
            self.rule_manager.add_ip_rule(ip, action)
            self.ip_entry.delete(0, tk.END)
            self.update_ip_rules_display()
            self.add_activity_message(f"📝 IP rule added: {action.upper()} {ip}", "info")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add IP rule: {str(e)}")
    
    def remove_ip_rule(self, action):
        """Remove selected IP rule"""
        listbox = self.blocked_ips_listbox if action == 'block' else self.allowed_ips_listbox
        selection = listbox.curselection()
        
        if not selection:
            messagebox.showwarning("Warning", "Please select an IP to remove")
            return
        
        ip = listbox.get(selection[0])
        self.rule_manager.remove_ip_rule(ip, action)
        self.update_ip_rules_display()
        self.add_activity_message(f"🗑️ IP rule removed: {action.upper()} {ip}", "info")
    
    def add_port_rule(self, action):
        """Add port rule"""
        try:
            port = int(self.port_entry.get().strip())
            self.rule_manager.add_port_rule(port, action)
            self.port_entry.delete(0, tk.END)
            self.update_port_rules_display()
            self.add_activity_message(f"📝 Port rule added: {action.upper()} {port}", "info")
        except ValueError:
            messagebox.showwarning("Warning", "Please enter a valid port number")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add port rule: {str(e)}")
    
    def remove_port_rule(self, action):
        """Remove selected port rule"""
        listbox = self.blocked_ports_listbox if action == 'block' else self.allowed_ports_listbox
        selection = listbox.curselection()
        
        if not selection:
            messagebox.showwarning("Warning", "Please select a port to remove")
            return
        
        port = int(listbox.get(selection[0]))
        self.rule_manager.remove_port_rule(port, action)
        self.update_port_rules_display()
        self.add_activity_message(f"🗑️ Port rule removed: {action.upper()} {port}", "info")
    
    def update_ip_rules_display(self):
        """Update IP rules display"""
        # Clear listboxes
        self.blocked_ips_listbox.delete(0, tk.END)
        self.allowed_ips_listbox.delete(0, tk.END)
        
        # Populate with current rules
        for ip in self.rule_manager.rules['ip_rules']['blocked_ips']:
            self.blocked_ips_listbox.insert(tk.END, ip)
        
        for ip in self.rule_manager.rules['ip_rules']['allowed_ips']:
            self.allowed_ips_listbox.insert(tk.END, ip)
    
    def update_port_rules_display(self):
        """Update port rules display"""
        # Clear listboxes
        self.blocked_ports_listbox.delete(0, tk.END)
        self.allowed_ports_listbox.delete(0, tk.END)
        
        # Populate with current rules
        for port in self.rule_manager.rules['port_rules']['blocked_ports']:
            self.blocked_ports_listbox.insert(tk.END, str(port))
        
        for port in self.rule_manager.rules['port_rules']['allowed_ports']:
            self.allowed_ports_listbox.insert(tk.END, str(port))
    
    def update_default_action(self):
        """Update default action setting"""
        self.rule_manager.rules['general_settings']['default_action'] = self.default_action.get()
        self.rule_manager.save_rules()
        self.add_activity_message(f"⚙️ Default action changed to: {self.default_action.get().upper()}", "info")
    
    def update_logging_settings(self):
        """Update logging settings"""
        self.rule_manager.rules['general_settings']['log_all_traffic'] = self.log_all.get()
        self.rule_manager.rules['general_settings']['log_blocked_only'] = self.log_blocked.get()
        self.rule_manager.save_rules()
        self.add_activity_message("⚙️ Logging settings updated", "info")
    
    def sync_to_iptables(self):
        """Sync rules to iptables"""
        if not self.iptables_manager.is_available():
            messagebox.showwarning("Warning", "IPTables is not available on this system")
            return
        
        try:
            # Sync blocked IPs
            for ip in self.rule_manager.rules['ip_rules']['blocked_ips']:
                self.iptables_manager.add_ip_block_rule(ip)
            
            # Sync blocked ports
            for port in self.rule_manager.rules['port_rules']['blocked_ports']:
                self.iptables_manager.add_port_block_rule(port)
            
            messagebox.showinfo("Success", "Rules synchronized to IPTables")
            self.add_activity_message("🔄 Rules synced to IPTables", "success")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to sync to IPTables: {str(e)}")
    
    def update_logs_display(self):
        """Update logs display"""
        # Clear existing items
        for item in self.logs_tree.get_children():
            self.logs_tree.delete(item)
        
        # Get recent logs
        logs = self.logger.get_recent_logs(100)
        
        for log in logs:
            packet_info = log.get('packet_info', {})
            values = (
                log.get('timestamp', ''),
                log.get('action', ''),
                packet_info.get('src_ip', ''),
                packet_info.get('dst_ip', ''),
                packet_info.get('protocol_name', ''),
                packet_info.get('dst_port', ''),
                log.get('reason', '')
            )
            
            # Color code based on action
            tags = ('blocked',) if log.get('action') == 'BLOCKED' else ('allowed',)
            self.logs_tree.insert('', tk.END, values=values, tags=tags)
        
        # Configure tags
        self.logs_tree.tag_configure('blocked', background='#ffebee')
        self.logs_tree.tag_configure('allowed', background='#e8f5e8')
    
    def clear_logs(self):
        """Clear all logs"""
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all logs?"):
            self.logger.clear_logs()
            self.update_logs_display()
            self.add_activity_message("🗑️ Logs cleared", "info")
    
    def add_activity_message(self, message, msg_type="info"):
        """Add message to activity feed"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        color_map = {
            "info": "#3498db",
            "success": "#27ae60",
            "warning": "#f39c12",
            "error": "#e74c3c"
        }
        
        colored_message = f"[{timestamp}] {message}\n"
        
        self.activity_text.insert(tk.END, colored_message)
        self.activity_text.see(tk.END)
        
        # Keep only last 100 lines
        lines = self.activity_text.get("1.0", tk.END).split('\n')
        if len(lines) > 100:
            self.activity_text.delete("1.0", f"{len(lines)-100}.0")
    
    def start_stats_thread(self):
        """Start thread for updating statistics"""
        def update_stats():
            while True:
                if hasattr(self, 'root'):
                    try:
                        self.root.after(0, self.update_statistics)
                    except:
                        break
                time.sleep(1)
        
        self.stats_update_thread = threading.Thread(target=update_stats, daemon=True)
        self.stats_update_thread.start()
    
    def update_statistics(self):
        """Update statistics display"""
        try:
            stats = self.packet_sniffer.get_stats()
            log_stats = self.logger.get_log_stats()
            
            # Update status
            status = "🟢 Running" if stats['is_running'] else "🔴 Stopped"
            self.stats_labels['status'].config(text=status)
            
            # Update uptime
            uptime_seconds = int(stats['uptime_seconds'])
            hours = uptime_seconds // 3600
            minutes = (uptime_seconds % 3600) // 60
            seconds = uptime_seconds % 60
            uptime_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            self.stats_labels['uptime'].config(text=uptime_str)
            
            # Update packet counts
            self.stats_labels['total_packets'].config(text=str(stats['packet_count']))
            self.stats_labels['allowed'].config(text=str(stats['allowed_count']))
            self.stats_labels['blocked'].config(text=str(stats['blocked_count']))
            self.stats_labels['suspicious'].config(text=str(log_stats['suspicious_packets']))
            self.stats_labels['packets/sec'].config(text=f"{stats['packets_per_second']:.1f}")
            self.stats_labels['active_connections'].config(text=str(stats['active_connections']))
            
        except Exception as e:
            print(f"Error updating statistics: {e}")
    
    def run(self):
        """Start the GUI application"""
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self.packet_sniffer.stop_monitoring()

if __name__ == "__main__":
    app = FirewallGUI()
    app.run()
