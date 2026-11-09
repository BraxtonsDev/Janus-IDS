import json
import time
from collections import defaultdict

eveLogPath = "/var/log/suricata/eve.json"

port_scan_tracker = defaultdict(set)
already_flagged_scanners = set()

failed_conn_tracker = defaultdict(int)
already_flagged_probers = set()

BLOCKED_DOMAINS = {"malicious.com", "badsite.org", "crypto-miner.net"}
BLOCKED_IPS = {"192.0.2.99", "203.0.113.50"}
UNUSUAL_PORTS = {4444, 1337, 6667}

with open(eveLogPath, "r") as f, open("auth_alerts.jsonl", "a") as output:
    for line in f:
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

        alrType = None
        svrType = None
        msg = None

        match eventType:
            # case "alert":
            #     dataInfo = data.get("alert", {})
            #     alrType = dataInfo.get("category", "Suricata Alert")
            #     svrType = dataInfo.get("severity", 1)
            #     msg = dataInfo.get("signature", "unknown")

            case "dns":
                dataInfo = data.get("dns",{})

                #Blocked Domain
                domain = dataInfo.get("rrname", "")
                if domain in BLOCKED_DOMAINS:
                    alrType = "DNS Query to a blocked domain"
                    svrType = 1
                    msg = "Suspicious domain"

            case "flow":
                flowInfo = data.get("flow", {})

                #Flagged IP
                if destIp in BLOCKED_IPS:
                    alrType = "Suspicious outbound traffic"
                    svrType = 1
                    msg = f"Connection to flagged IP: {destIp}"

                #Odd port use
                elif destPort in UNUSUAL_PORTS:
                    alrType = "Unused ports"
                    svrType = 2
                    msg = f"Outbound connection on unusual port: {destPort}"

                #Scanning multiple ports
                elif destPort is not None:
                    port_scan_tracker[srcIP].add(destPort)
                    if len(port_scan_tracker[srcIP]) > 30 and srcIP not in already_flagged_scanners:
                        already_flagged_scanners.add(srcIP)
                        alrType = "Port scanning"
                        svrType = 2
                        msg = f"{len(port_scan_tracker[srcIP])} ports scanned by {srcIP}"

                    #Repeated connection attempts
                    elif flowInfo.get("state") == "new":
                        failed_conn_tracker[srcIP] += 1
                        if failed_conn_tracker[srcIP] >= 20 and srcIP not in already_flagged_scanners:
                            alrType = "Repeated connection attempts"
                            svrType = 2
                            msg = f"Possible service probing: {failed_conn_tracker[srcIP]}"

        if alrType is not None:
            alert ={
                    "source": "eve.json",
                    "source_ip" : srcIP,
                    "alert_type": alrType,
                    "severity": svrType,
                    "message": msg,
                    "raw_log": line.strip(),
                    "time": data.get("timestamp")
            }
            output.write(json.dumps(alert) + "\n")