from collections import defaultdict, deque
import json
import time
import re

# Open auth.log and move to the end
with open("/var/log/auth.log", "r") as file:

    file.seek(0, 2)

    ssh_attempts = defaultdict(deque) #maintain active ssh attempts
    failed_attempts = 0  # failed counter
    alerted_ips = set() #set to track ip's
    repeated_alert_sent = False
    

    while True:
        line = file.readline()  # read line

        if not line: # if no line, try again in 1
            time.sleep(1)
            continue

        ip = re.search(r"from (\S+)", line) # search for # after "from"
        
        if ip: # if exists, assign to srcIP
            srcIP = ip.group(1)
        else: # else null, some alerts wont state ip
            srcIP = None

        alrType = None # alert type
        svrType = None  # severity type
        msg = None #msg

        if "Failed" in line or "authentication failure" in line:

            failed_attempts += 1

            # check now for brute force
            if "ssh" in line and srcIP:
                now = time.time() # pull time at detection
                ssh_attempts[srcIP].append(now) # append to deque

                #remove old ssh attempts > 60 sec
                while ssh_attempts[srcIP] and now - ssh_attempts[srcIP][0] > 60: # pop ones that are > 60 sec old
                    ssh_attempts[srcIP].popleft()

                if len(ssh_attempts[srcIP]) > 15 and srcIP not in alerted_ips: # check if more than 15 attempts
                    alrType = "SSH Brute Force"
                    svrType = "High"
                    msg = "More than 15 failed SSH attempts in last minute"
                    alerted_ips.add(srcIP)
            
            elif failed_attempts > 5 and not repeated_alert_sent:
                alrType = "Repeated Failed Logins"
                svrType = "Medium"
                msg = "More than 5 failed auth attempts"
                repeated_alert_sent = True


        if alrType is not None: # if alrType has been changed, just a final check

            alert = {
            "source": "auth.log",
            "source_ip": srcIP,
            "alert_type": alrType,
            "severity": svrType,
            "message": msg,
            "raw_log": line.strip(),
            "time": int(time.time())

            }

            # Save each alert to the JSON files
            with open("auth_alerts.jsonl", "a") as output:
                output.write(json.dumps(alert) + "\n")

            