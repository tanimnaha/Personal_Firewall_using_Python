#!/usr/bin/env python3
"""
Personal Firewall - Main Entry Point
Advanced Network Protection System

This is the main entry point for the Personal Firewall application.
It can be run in both GUI and CLI modes.
"""

import sys
import os
import argparse

def check_dependencies():
    """Check if required dependencies are installed"""
    missing_deps = []
    
    try:
        import scapy
    except ImportError:
        missing_deps.append('scapy')
    
    try:
        import psutil
    except ImportError:
        missing_deps.append('psutil')
    
    if missing_deps:
        print("❌ Missing required dependencies:")
        for dep in missing_deps:
            print(f"   - {dep}")
        print("\nPlease install missing dependencies with:")
        print(f"   pip install {' '.join(missing_deps)}")
        return False
    
    return True

def check_privileges():
    """Check if running with appropriate privileges"""
    try:
        if os.name == 'nt':  # Windows
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Linux/Unix
            is_admin = os.geteuid() == 0
        
        if not is_admin:
            print("⚠️  Warning: Not running with administrator privileges.")
            print("   Some features may not work properly.")
            print("   For full functionality, run as administrator/root.")
            
            response = input("Continue anyway? (y/N): ")
            if response.lower() != 'y':
                return False
    except Exception as e:
        print(f"⚠️  Could not check privileges: {e}")
    
    return True

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Personal Firewall - Advanced Network Protection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage Modes:
  GUI Mode (default): python main.py
  CLI Mode:          python main.py --cli [CLI_ARGS]

Examples:
  python main.py                                    # Launch GUI
  python main.py --cli status                      # Show status in CLI
  python main.py --cli monitor --interface eth0    # Monitor specific interface
  python main.py --cli rules list                  # List current rules
        """
    )
    
    parser.add_argument('--cli', action='store_true', 
                       help='Run in CLI mode instead of GUI')
    parser.add_argument('--no-check', action='store_true',
                       help='Skip dependency and privilege checks')
    
    # Parse known args to separate main args from CLI args
    args, remaining_args = parser.parse_known_args()
    
    # Print banner
    print("""
╔═════════════════════════════════════════════════════════════════╗
║                      Personal Firewall v1.0                    ║
║                  Advanced Network Protection                    ║
║                                                                 ║
║  Features:                                                      ║
║  • Real-time packet monitoring with Scapy                      ║
║  • Rule-based traffic filtering                                ║
║  • Suspicious activity detection                               ║
║  • IPTables integration (Linux)                                ║
║  • Comprehensive logging and audit                             ║
║  • Modern GUI with Tkinter                                     ║
║  • Full CLI interface                                          ║
╚═════════════════════════════════════════════════════════════════╝
    """)
    
    # Perform checks unless skipped
    if not args.no_check:
        print("🔍 Checking system requirements...")
        
        if not check_dependencies():
            sys.exit(1)
        
        if not check_privileges():
            sys.exit(1)
        
        print("✅ System requirements satisfied.")
    
    try:
        if args.cli:
            # CLI Mode
            print("🖥️  Starting in CLI mode...")
            
            # Import and run CLI with remaining arguments
            sys.argv = ['firewall_cli.py'] + remaining_args
            from firewall_cli import main as cli_main
            cli_main()
        else:
            # GUI Mode (default)
            print("🖼️  Starting in GUI mode...")
            
            try:
                from firewall_gui import FirewallGUI
                app = FirewallGUI()
                print("✅ GUI initialized successfully.")
                app.run()
            except ImportError as e:
                print(f"❌ Error importing GUI components: {e}")
                print("Falling back to CLI mode...")
                from firewall_cli import FirewallCLI
                cli = FirewallCLI()
                cli.show_status()
    
    except KeyboardInterrupt:
        print("\n\n👋 Application terminated by user.")
    except Exception as e:
        print(f"\n❌ Unexpected error occurred: {e}")
        print("Please check your installation and try again.")
        sys.exit(1)

if __name__ == "__main__":
    main()
