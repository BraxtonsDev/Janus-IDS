import json
import time
from collections import defaultdict

eveLogPath = "/var/log/suricata/eve.json"
port_scan_tracker = defaultdict(set)
already_flagged_scanners = set()

with open(eveLogPath, "r") as f, open("auth_alerts.jsonl", "a") as output:
    for line in f:
        try:
            data = json.loads(line)
        except json.decoder.JSONDecodeError:
            continue

        eventType = data.get("event_type")
        if eventType not in ("alert", "dns", "flow"):
            continue

        srcIP = data.get("src_ip", "unknown")
        destIp = data.get("dest_ip", "unknown")
        destPort = data.get("dest_port", "unknown")

        alrType = None
        svrType = None
        msg = None

        match eventType:
            case "alert":
                dataInfo = data.get("alert", {})
                alrType = dataInfo.get("category", "Suricata Alert")
                svrType = dataInfo.get("severity", 1)
                msg = dataInfo.get("signature", "unknown")

            case "dns":
                dataInfo = data.get("dns",{})
                domain = dataInfo.get("rrname", "")
                if domain in "/var/log/suricata/BLOCKED_DOMAINS":
                    alrType = "DNS Query to a blocked domain"
                    svrType = 1
                    msg = "Suspicious domain"

            case "flow":
                if destIp in "/var/log/suricata/BLOCKED_IP":
                    alrType = "Suspicious outbound traffic"
                    svrType = 1
                    msg = f"Connection to flagged IP: {destIp}"

                elif destPort in "/var/log/suricata/UNUSUAL_PORTS":
                    alrType = "Unused ports"
                    svrType = 2
                    msg = f"Connection to flagged IP: {destIp}"

                elif destPort is not None:
                    port_scan_tracker[srcIP].add(destPort)
                    if len(port_scan_tracker[srcIP]) > 30 and srcIP not in already_flagged_scanners:
                        already_flagged_scanners.add(srcIP)
                        alrType = "Port scanning"
                        svrType = 2
                        msg = f"{len(port_scan_tracker[srcIP])} ports scanned by {srcIP}"

        if alrType is not None:
            alert ={
                    "source": "eve.json",
                    "source_ip" : srcIP,
                    "alert_type": alrType,
                    "severity": svrType,
                    "message": msg,
                    "raw_log": line.strip()
            }
            output.write(json.dumps(alert) + "\n")