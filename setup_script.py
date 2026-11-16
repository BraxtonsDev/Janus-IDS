import os
import shutil
import subprocess
import sys

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

def main():
    check_root()

    if suricata_installed():
        print("Suricata is already installed, checking interface...")
    else:
        install_suricata()
        print("Suricata installed, checking interface...")

    interface = get_interface()
    print("Detected ", interface)

main()