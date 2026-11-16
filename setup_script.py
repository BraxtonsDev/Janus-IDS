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

def start_logger(script):
    check = subprocess.run(["pgrep", "-f", script], capture_output=True)
    if check.returncode == 0:
        print(script, " is already running.")
        return

    print("Starting ", script)
    subprocess.Popen([sys.executable, script]) #normally I would put the full command python3 scriptname whatever, but sys just uses whatever python is running this script

def main():
    check_root()

    if suricata_installed():
        print("Suricata is already installed, checking interface...")
    else:
        install_suricata()
        print("Suricata installed, checking interface...")

    interface = get_interface()
    print("Detected ", interface)

    start_suricata(interface)

    wait_for_eve()

    start_logger("auth_log_script.py")
    start_logger("eve_log_script.py")

main()

#For now until GUI is done we'll just tail the
#network logs in a different terminal 
#tail -f auth_alerts.jsonl
#tail -f network_alerts.jsonl