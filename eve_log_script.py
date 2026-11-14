import json
import time
from collections import defaultdict

eveLogPath = "/var/log/suricata/eve.json"

port_scan_tracker = defaultdict(dict)
already_flagged_scanners = set()

failed_conn_tracker = defaultdict(int)
already_flagged_probers = set()

BLOCKED_DOMAINS = {"malicious.com", "badsite.org", "crypto-miner.net"}
BLOCKED_IPS = {"192.0.2.99", "203.0.113.50"}
UNUSUAL_PORTS = {4444, 1337, 6667}

with open(eveLogPath, "r") as f, open("network_alerts.jsonl", "a") as output:
    f.seek(0, 2)  # Start at the end of the file

    while True:
        line = f.readline()

        if not line:
            time.sleep(0.5)
            continue

        try:
            data = json.loads(line)
        except json.decoder.JSONDecodeError:
            continue

        eventType = data.get("event_type")
        if eventType not in ("alert", "dns", "flow"):
            continue

        srcIP = data.get("src_ip", None)
        destIp = data.get("dest_ip", None)
        destPort = data.get("dest_port", None)
        if destPort is not None:
            destPort = int(destPort)

        alerts = []

        match eventType:
            case "alert":
                dataInfo = data.get("alert", {})
                alerts.append({
                    "alert_type": dataInfo.get("category", "Suricata Alert"),
                    "severity": dataInfo.get("severity", 1),
                    "message": dataInfo.get("signature", "unknown")
                })

            case "dns":
                dataInfo = data.get("dns",{})

                #Blocked Domain
                domain = dataInfo.get("rrname", "").lower().rstrip(".")

                if domain in BLOCKED_DOMAINS:
                    alerts.append({
                        "alert_type": "DNS Query to a blocked domain",
                        "severity": 1,
                        "message": f"Suspicious domain: {domain}"
                    })

            case "flow":
                flowInfo = data.get("flow", {})

                #Flagged IP
                if destIp in BLOCKED_IPS:
                    alerts.append({
                        "alert_type": "Suspicious outbound traffic",
                        "severity": 1,
                        "message": f"Connection to flagged IP: {destIp}"
                    })

                #Odd port use
                if destPort in UNUSUAL_PORTS:
                    alerts.append({
                        "alert_type": "Unused ports",
                        "severity": 2,
                        "message": f"Outbound connection on unusual port: {destPort}"
                    })
                
                # Scanning multiple ports
                if destPort is not None:
                    current_time = time.time()

                    port_scan_tracker[srcIP][destPort] = current_time

                    # Remove ports older than 60 seconds
                    port_scan_tracker[srcIP] = {
                        port: timestamp
                        for port, timestamp in port_scan_tracker[srcIP].items()
                        if current_time - timestamp <= 60
                    }

                    if len(port_scan_tracker[srcIP]) > 30 and srcIP not in already_flagged_scanners:
                        already_flagged_scanners.add(srcIP)
                        alerts.append({
                            "alert_type": "Port scanning",
                            "severity": 2,
                            "message": f"{len(port_scan_tracker[srcIP])} ports scanned by {srcIP}"
                        })

                #Repeated connection attempts
                if flowInfo.get("reason") == "timeout" and flowInfo.get("pkts_toclient") == 0:
                    failed_conn_tracker[srcIP] += 1

                    if failed_conn_tracker[srcIP] >= 20 and srcIP not in already_flagged_probers:
                        already_flagged_probers.add(srcIP)
                        alerts.append({
                            "alert_type": "Repeated connection attempts",
                            "severity": 2,
                            "message": f"Possible service probing: {failed_conn_tracker[srcIP]}"
                        })

        for alertInfo in alerts:
            alert = {
                "source": "eve.json",
                "source_ip": srcIP,
                "alert_type": alertInfo["alert_type"],
                "severity": alertInfo["severity"],
                "message": alertInfo["message"],
                "raw_log": line.strip(),
                "time": data.get("timestamp")
            }
            output.write(json.dumps(alert) + "\n")
            output.flush() #Update and write to file immediately