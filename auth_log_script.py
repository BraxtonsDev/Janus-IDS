import json
import time

# Open auth.log and move to the end
with open("/var/log/auth.log", "r") as file:

    file.seek(0, 2)

    while True:
        line = file.readline()

        if not line:
            time.sleep(1)
            continue

        if "sshd" in line or "sudo" in line or "Failed" in line:

            alert = {
                "source": "auth.log",
                "alert_type": "Authentication Event",
                "severity": "Unknown",
                "message": "Authentication activity detected",
                "raw_log": line.strip()
            }

            # Save each alert to the JSON files
            with open("auth_alerts.jsonl", "a") as output:
                output.write(json.dumps(alert) + "\n")

            
