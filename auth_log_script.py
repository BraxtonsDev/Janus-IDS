from collections import defaultdict, deque
import json
import time
import re

# Open auth.log and move to the end
with open("/var/log/auth.log", "r") as file:

    file.seek(0, 2)

    # track attempts separately for each IP, per service
    ssh_attempts = defaultdict(deque)
    failed_attempts = defaultdict(deque)
    ftp_attempts = defaultdict(deque)

    # track which IPs have already triggered alerts, per service
    ssh_alerted = set() #ssh brute force
    login_alerted = set() #general failed logins
    ftp_alerted = set() #ftp brute force

    open("auth_alerts.jsonl", "a").close() # Ensure the output file exists

    while True:
        line = file.readline()

        if not line:
            time.sleep(1)
            continue

        srcIP = None
        alrType = None
        svrType = None
        msg = None

        #check for repeated general failed logins
        login_ip = None

        if "failed" in line.lower() or "authentication failure" in line.lower():
            login_ip = re.search(r"from (\S+)", line) or re.search(r"rhost=(\S+)", line)

        if login_ip:
            srcIP = login_ip.group(1)
            now = time.time()

            failed_attempts[srcIP].append(now)

            #remove failed login attempts older than 60 seconds
            while failed_attempts[srcIP] and now - failed_attempts[srcIP][0] > 60:
                failed_attempts[srcIP].popleft()

            if len(failed_attempts[srcIP]) >= 5 and srcIP not in login_alerted:
                alrType = "Repeated Failed Logins"
                svrType = "Medium"
                msg = "5 or more failed authentication attempts from this IP in 60 seconds"
                login_alerted.add(srcIP)

            if len(failed_attempts[srcIP]) < 5:
                login_alerted.discard(srcIP)

        #check for SSH brute force
        ssh_ip = None

        if "sshd" in line.lower() and ("failed" in line.lower() or "authentication failure" in line.lower()):
            ssh_ip = re.search(r"from (\S+)", line)

        if ssh_ip:
            srcIP = ssh_ip.group(1)
            now = time.time()

            ssh_attempts[srcIP].append(now)

            #remove SSH attempts older than 60 seconds
            while ssh_attempts[srcIP] and now - ssh_attempts[srcIP][0] > 60:
                ssh_attempts[srcIP].popleft()

            if len(ssh_attempts[srcIP]) >= 15 and srcIP not in ssh_alerted:
                alrType = "SSH Brute Force"
                svrType = "High"
                msg = "15 or more failed SSH attempts in 60 seconds"
                ssh_alerted.add(srcIP)

            if len(ssh_attempts[srcIP]) < 15:
                ssh_alerted.discard(srcIP)

        #check for FTP brute force
        ftp_ip = None
        if "vsftpd" in line.lower() and ("failed" in line.lower() or "failure" in line.lower()):
            ftp_ip = re.search(r"rhost=(\S+)", line)

        if ftp_ip:
            srcIP = ftp_ip.group(1)
            now = time.time()

            ftp_attempts[srcIP].append(now)

            #remove FTP attempts older than 60 seconds
            while ftp_attempts[srcIP] and now - ftp_attempts[srcIP][0] > 60:
                ftp_attempts[srcIP].popleft()

            if len(ftp_attempts[srcIP]) >= 15 and srcIP not in ftp_alerted:
                alrType = "FTP Brute Force"
                svrType = "High"
                msg = "15 or more failed FTP attempts in 60 seconds"
                ftp_alerted.add(srcIP)

            if len(ftp_attempts[srcIP]) < 15:
                ftp_alerted.discard(srcIP)

        #export alert if one was generated
        if alrType is not None:

            alert = {
                "source": "auth.log",
                "source_ip": srcIP,
                "alert_type": alrType,
                "severity": svrType,
                "message": msg,
                "raw_log": line.strip(),
                "time": int(time.time())
            }

            #save each alert to the JSONL file
            with open("auth_alerts.jsonl", "a") as output:
                output.write(json.dumps(alert) + "\n")


            