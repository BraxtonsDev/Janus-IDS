from collections import defaultdict, deque
import json
import time
import re

# Open auth.log and move to the end
with open("/var/log/auth.log", "r") as file:

    file.seek(0, 2)

    #track attempts separately for each IP
    ssh_attempts = defaultdict(deque)
    failed_attempts = defaultdict(deque)

    #track which IPs have already triggered alerts
    alerted_ips = set()
    repeated_alert_sent = set()

    while True:
        line = file.readline()

        if not line:
            time.sleep(1)
            continue

        # get ip
        ip = re.search(r"from (\S+)", line)

        if ip:
            srcIP = ip.group(1)
        else:
            srcIP = None

        alrType = None
        svrType = None
        msg = None

        if "Failed" in line or "authentication failure" in line:

            now = time.time()

            alrType = "Failed authentication"
            svrType = "Low"
            msg = "Failed login attempt detected"

            #only track attempts when an IP is available
            if srcIP:

                #track all failed authentication attempts for this IP
                failed_attempts[srcIP].append(now)

                #remove attempts older than 60 seconds
                while failed_attempts[srcIP] and now - failed_attempts[srcIP][0] > 60:
                    failed_attempts[srcIP].popleft()

                #check for repeated failed logins
                if len(failed_attempts[srcIP]) > 5 and srcIP not in repeated_alert_sent:
                    alrType = "Repeated Failed Logins"
                    svrType = "Medium"
                    msg = "More than 5 failed authentication attempts from this IP in 60 seconds"
                    repeated_alert_sent.add(srcIP)

                #check for SSH brute force
                if "ssh" in line.lower():

                    ssh_attempts[srcIP].append(now)

                    #remove SSH attempts older than 60 seconds
                    while ssh_attempts[srcIP] and now - ssh_attempts[srcIP][0] > 60:
                        ssh_attempts[srcIP].popleft()

                    if len(ssh_attempts[srcIP]) > 15 and srcIP not in alerted_ips:
                        alrType = "SSH Brute Force"
                        svrType = "High"
                        msg = "More than 15 failed SSH attempts in last minute"
                        alerted_ips.add(srcIP)

                #reset alert flags once the count drops below the threshold
                if len(failed_attempts[srcIP]) <= 5:
                    repeated_alert_sent.discard(srcIP)

                if len(ssh_attempts[srcIP]) <= 15:
                    alerted_ips.discard(srcIP)

        elif "sshd" in line:
            alrType = "SSH event"
            svrType = "Low"
            msg = "SSH activity detected"

        elif "sudo" in line:
            alrType = "Sudo event"
            svrType = "Low"
            msg = "Sudo activity detected"

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


            