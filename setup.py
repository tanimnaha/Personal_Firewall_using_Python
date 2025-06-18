#!/usr/bin/env python3
"""
Setup script for Personal Firewall
Installs dependencies and sets up the application
"""

import subprocess
import sys
import os
import platform

def run_command(command, description):
    """Run a command and handle errors"""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, 
                              capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed: {e}")
        if e.stdout:
            print(f"Output: {e.stdout}")
        if e.stderr:
            print(f"Error: {e.stderr}")
        return False

def check_python_version():
    """Check if Python version is adequate"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 7):
        print(f"❌ Python 3.7+ required, but you have {version.major}.{version.minor}")
        return False
    print(f"✅ Python {version.major}.{version.minor}.{version.micro} is adequate")
    return True

def check_privileges():
    """Check if running with appropriate privileges"""
    try:
        if os.name == 'nt':  # Windows
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Linux/Unix
            is_admin = os.geteuid() == 0
        
        if is_admin:
            print("✅ Running with administrator privileges")
        else:
            print("⚠️  Not running with administrator privileges")
            print("   Some features may not work properly during runtime")
        
        return True
    except Exception as e:
        print(f"⚠️  Could not check privileges: {e}")
        return True

def install_python_dependencies():
    """Install Python dependencies"""
    dependencies = [
        "scapy==2.5.0",
        "psutil==5.9.6", 
        "requests==2.31.0"
    ]
    
    for dep in dependencies:
        if not run_command(f"{sys.executable} -m pip install {dep}", f"Installing {dep}"):
            return False
    
    return True

def install_system_dependencies():
    """Install system-specific dependencies"""
    system = platform.system().lower()
    
    if system == "windows":
        print("📋 Windows system detected")
        print("⚠️  Please manually install Npcap from https://npcap.org/")
        print("   This is required for packet capture functionality")
        
    elif system == "linux":
        print("🐧 Linux system detected")
        
        # Try to detect distribution
        try:
            with open('/etc/os-release', 'r') as f:
                os_info = f.read().lower()
                
            if 'ubuntu' in os_info or 'debian' in os_info:
                commands = [
                    "apt update",
                    "apt install -y python3-dev libpcap-dev python3-tk"
                ]
            elif 'centos' in os_info or 'rhel' in os_info or 'fedora' in os_info:
                commands = [
                    "yum update -y",
                    "yum install -y python3-devel libpcap-devel tkinter"
                ]
            else:
                print("⚠️  Unknown Linux distribution")
                print("   Please manually install: python3-dev, libpcap-dev, python3-tk")
                return True
            
            for cmd in commands:
                if not run_command(f"sudo {cmd}", f"Running: {cmd}"):
                    print("⚠️  Some system packages may not have been installed")
                    print("   You may need to install them manually")
                    break
                    
        except Exception as e:
            print(f"⚠️  Could not detect Linux distribution: {e}")
            print("   Please manually install: python3-dev, libpcap-dev, python3-tk")
    
    elif system == "darwin":  # macOS
        print("🍎 macOS system detected")
        print("⚠️  Please ensure you have:")
        print("   - Xcode Command Line Tools: xcode-select --install")
        print("   - Homebrew: brew install libpcap")
    
    return True

def create_startup_scripts():
    """Create convenient startup scripts"""
    
    # Create GUI launcher
    gui_script = """#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from main import main

if __name__ == "__main__":
    main()
"""
    
    # Create CLI launcher
    cli_script = """#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Pass CLI flag and all arguments
sys.argv = [sys.argv[0], '--cli'] + sys.argv[1:]
from main import main

if __name__ == "__main__":
    main()
"""
    
    try:
        with open('run_gui.py', 'w') as f:
            f.write(gui_script)
        
        with open('run_cli.py', 'w') as f:
            f.write(cli_script)
        
        # Make executable on Unix systems
        if os.name != 'nt':
            os.chmod('run_gui.py', 0o755)
            os.chmod('run_cli.py', 0o755)
        
        print("✅ Created startup scripts: run_gui.py, run_cli.py")
        return True
        
    except Exception as e:
        print(f"⚠️  Could not create startup scripts: {e}")
        return False

def create_desktop_shortcut():
    """Create desktop shortcut (Windows only)"""
    if os.name == 'nt':
        try:
            import winshell
            from win32com.client import Dispatch
            
            desktop = winshell.desktop()
            path = os.path.join(desktop, "Personal Firewall.lnk")
            target = os.path.join(os.getcwd(), "run_gui.py")
            
            shell = Dispatch('WScript.Shell')
            shortcut = shell.CreateShortCut(path)
            shortcut.Targetpath = sys.executable
            shortcut.Arguments = f'"{target}"'
            shortcut.WorkingDirectory = os.getcwd()
            shortcut.IconLocation = sys.executable
            shortcut.save()
            
            print("✅ Created desktop shortcut")
            
        except ImportError:
            print("⚠️  Could not create desktop shortcut (winshell not available)")
        except Exception as e:
            print(f"⚠️  Could not create desktop shortcut: {e}")

def run_tests():
    """Run basic functionality tests"""
    print("🧪 Running basic tests...")
    
    try:
        # Test imports
        print("  Testing imports...")
        import scapy
        import psutil
        print("  ✅ All imports successful")
        
        # Test rule manager
        print("  Testing rule manager...")
        from rule_manager import RuleManager
        rm = RuleManager()
        print("  ✅ Rule manager working")
        
        # Test logger
        print("  Testing logger...")
        from logger import Logger
        logger = Logger()
        print("  ✅ Logger working")
        
        print("✅ All basic tests passed")
        return True
        
    except Exception as e:
        print(f"❌ Tests failed: {e}")
        return False

def main():
    """Main setup function"""
    print("""
╔═══════════════════════════════════════════════════════════════╗
║                Personal Firewall Setup                       ║
║              Advanced Network Protection                     ║
╚═══════════════════════════════════════════════════════════════╝
    """)
    
    print("🚀 Starting setup process...")
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Check privileges
    check_privileges()
    
    # Install Python dependencies
    if not install_python_dependencies():
        print("❌ Failed to install Python dependencies")
        sys.exit(1)
    
    # Install system dependencies
    install_system_dependencies()
    
    # Create startup scripts
    create_startup_scripts()
    
    # Create desktop shortcut (Windows)
    create_desktop_shortcut()
    
    # Run tests
    if not run_tests():
        print("⚠️  Some tests failed, but setup may still work")
    
    print("""
✅ Setup completed successfully!

🚀 You can now run the Personal Firewall:

GUI Mode:
  python main.py
  python run_gui.py

CLI Mode:
  python main.py --cli status
  python run_cli.py status

📖 See README.md for detailed usage instructions.

⚠️  Remember to run with administrator privileges for full functionality!
    """)

if __name__ == "__main__":
    main()
