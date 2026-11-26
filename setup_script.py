import os
import shutil
import subprocess
import sys
import time

def check_root():
    if os.geteuid() != 0: #0 is root user
        print("Program must be run as root, use sudo.")
        sys.exit(1) #1 means an error occured

def suricata_installed():
    return shutil.which("suricata") is not None #searches path for suricata, returns bool

def install_suricata():
    print("Installing Suricata...")
    subprocess.run(["apt-get", "update"], check = True) #runs cmds (check=true makes it stop if an error occurs)
    subprocess.run(["apt-get", "install", "-y", "suricata"], check = True)

    if not suricata_installed():
        print("Install failed.")
        sys.exit(1)

def get_interface():
    result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True)
    parsed = result.stdout.split()

    if "dev" not in parsed: #normally after dev would show the network interface
        print("Could not detect a network interface.")
        sys.exit(1)

    return parsed[parsed.index("dev") + 1] #finds dev and returns the value of the next word (which is the net int)

def suricata_running():
    result = subprocess.run(["pgrep", "-f", "suricata -c"], capture_output=True) #capturing so we don't get spammed with the output
    return result.returncode == 0 #0 means pgrep found the process

def start_suricata(interface):
    subprocess.run(["systemctl", "stop", "suricata"], capture_output=True)

    if suricata_running():
        print("Suricata is already running.")
        return
    
    print("Starting Suricata on ", interface)
    subprocess.Popen(["suricata", "-c", "/etc/suricata/suricata.yaml", "-i", interface]) #popen starts a command and moves on so it doesn't freeze (run would freeze)

def wait_for_eve():
    print("Waiting for eve.json")
    for i in range(30):
        if os.path.exists("/var/log/suricata/eve.json"):
            return
        time.sleep(1)

    print("eve.json never loaded")
    sys.exit(1)

def start_logger(script, user=None):
    check = subprocess.run(["pgrep", "-f", script], capture_output=True)
    if check.returncode == 0:
        print(script, " is already running.")
        return

    print("Starting", script)
    process = subprocess.Popen([sys.executable, script], user=user) #normally I would put the full command python3 scriptname whatever, but sys just uses whatever python is running this script

    time.sleep(2)
    if process.poll() is not None: #poll returns none if the process is still running, otherwise it prints to run it manually
        print(script, " failed to start. Run " + script + " manually to see the error.")

def ensure_auth_log_script():
    if not os.path.exists("/var/log/auth.log"):
        subprocess.run(["apt-get", "install", "-y", "rsyslog"], check=True)
        subprocess.run(["systemctl", "enable", "--now", "rsyslog"], check=True)
    
    subprocess.run(["logger", "-p", "auth.info", "Janus setup"]) #gets auth.log up and moving if it aint already with a custom msg (is handy for testing on kali)
    time.sleep(1)

def install_gui_dependencies():
    try:
        import customtkinter
        return
    except ImportError:
        pass

    print("Installing GUI dependencies...")
    subprocess.run(["apt-get", "install", "-y", "python3-tk", "python3-pip"], check=True)
    subprocess.run([sys.executable, "-m", "pip", "install", "--break-system-packages", "customtkinter"], check=True) #breaksystempackages lets newer debian systems run pip install

def main():
    if sys.version_info < (3, 10):
        print("Python 3.10 or higher is required.")
        sys.exit(1)

    os.chdir(os.path.dirname(os.path.abspath(__file__))) #changes working directory to the script's directory so it can find the other scripts
    check_root()

    if suricata_installed():
        print("Suricata is already installed, checking interface...")
    else:
        install_suricata()
        print("Suricata installed, checking interface...")

    interface = get_interface()
    print("Detected", interface)

    start_suricata(interface)

    wait_for_eve()

    ensure_auth_log_script()
    install_gui_dependencies()

    start_logger("auth_log_script.py")
    start_logger("eve_log_script.py")
    start_logger("traffic_monitor.py")
    start_logger("dashboard.py", user=os.environ.get("SUDO_USER")) #gets the user that ran sudo

if __name__ == "__main__":
    main()