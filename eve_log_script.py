import json
import time
from collections import defaultdict, deque
eveLogPath = "/var/log/suricata/eve.json"

RECHECK_TIMEOUT_SECONDS = 300  # 5 minutes
ICMP_FLOOD_WINDOW_SECONDS = 10
ICMP_FLOOD_THRESHOLD = 100     # ICMP packets from one src_ip within the window

port_scan_tracker = defaultdict(dict)
flagged_scanners = {}  # src_ip -> timestamp of last port-scan alert

failed_conn_tracker = defaultdict(int)
flagged_probers = {}   # src_ip -> timestamp of last prober alert

icmp_flood_tracker = defaultdict(deque)  # src_ip -> deque of (timestamp, pkts_toserver)
flagged_icmp_flooders = {}               # src_ip -> timestamp of last ICMP flood alert

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
        if eventType not in ("dns", "flow"):
            continue

        srcIP = data.get("src_ip", None)
        destIp = data.get("dest_ip", None)
        destPort = data.get("dest_port", None)
        if destPort is not None:
            destPort = int(destPort)

        current_time = time.time()
        alerts = []

        match eventType:
            case "dns":
                dataInfo = data.get("dns", {})

                # Blocked Domain
                domain = dataInfo.get("rrname", "").lower().rstrip(".")

                if domain in BLOCKED_DOMAINS:
                    alerts.append({
                        "alert_type": "DNS Query to a blocked domain",
                        "severity": 1,
                        "message": f"Suspicious domain: {domain}"
                    })

            case "flow":
                flowInfo = data.get("flow", {})

                if destIp in BLOCKED_IPS:
                    alerts.append({
                        "alert_type": "Suspicious outbound traffic",
                        "severity": 1,
                        "message": f"Connection to flagged IP: {destIp}"
                    })

                if destPort in UNUSUAL_PORTS:
                    alerts.append({
                        "alert_type": "Unused ports",
                        "severity": 2,
                        "message": f"Outbound connection on unusual port: {destPort}"
                    })

                # Scanning multiple ports (recheck allowed every 5 minutes)
                if destPort is not None and srcIP is not None:
                    port_scan_tracker[srcIP][destPort] = current_time

                    # Remove ports older than 60 seconds
                    port_scan_tracker[srcIP] = {
                        port: timestamp
                        for port, timestamp in port_scan_tracker[srcIP].items()
                        if current_time - timestamp <= 60
                    }

                    last_scan_alert = flagged_scanners.get(srcIP)
                    can_alert_scan = (
                        last_scan_alert is None
                        or (current_time - last_scan_alert) >= RECHECK_TIMEOUT_SECONDS
                    )

                    if len(port_scan_tracker[srcIP]) > 30 and can_alert_scan:
                        flagged_scanners[srcIP] = current_time
                        alerts.append({
                            "alert_type": "Port scanning",
                            "severity": 2,
                            "message": f"{len(port_scan_tracker[srcIP])} ports scanned by {srcIP}"
                        })

                # Repeated connection attempts (recheck allowed every 5 minutes)
                if (
                    srcIP is not None
                    and flowInfo.get("reason") == "timeout"
                    and flowInfo.get("pkts_toclient") == 0
                ):
                    failed_conn_tracker[srcIP] += 1

                    last_probe_alert = flagged_probers.get(srcIP)
                    can_alert_probe = (
                        last_probe_alert is None
                        or (current_time - last_probe_alert) >= RECHECK_TIMEOUT_SECONDS
                    )

                    if failed_conn_tracker[srcIP] >= 20 and can_alert_probe:
                        flagged_probers[srcIP] = current_time
                        count_at_alert = failed_conn_tracker[srcIP]
                        failed_conn_tracker[srcIP] = 0  # Require 20 new timeouts for the next alert
                        alerts.append({
                            "alert_type": "Repeated connection attempts",
                            "severity": 2,
                            "message": f"Possible service probing: {count_at_alert}"
                        })

                # ICMP flood detection (recheck allowed every 5 minutes)
                proto = (data.get("proto") or "").upper()
                if proto in ("ICMP", "IPV6-ICMP") and srcIP is not None:
                    pkts = flowInfo.get("pkts_toserver")
                    if pkts is None:
                        pkts = 1
                    icmp_flood_tracker[srcIP].append((current_time, pkts))
                    # Drop entries older than the sliding window
                    while (
                        icmp_flood_tracker[srcIP]
                        and current_time - icmp_flood_tracker[srcIP][0][0] > ICMP_FLOOD_WINDOW_SECONDS
                    ):
                        icmp_flood_tracker[srcIP].popleft()
                    total_icmp_pkts = sum(count for _, count in icmp_flood_tracker[srcIP])
                    last_icmp_alert = flagged_icmp_flooders.get(srcIP)
                    can_alert_icmp = (
                        last_icmp_alert is None
                        or (current_time - last_icmp_alert) >= RECHECK_TIMEOUT_SECONDS
                    )
                    if total_icmp_pkts >= ICMP_FLOOD_THRESHOLD and can_alert_icmp:
                        flagged_icmp_flooders[srcIP] = current_time
                        alerts.append({
                            "alert_type": "ICMP flood",
                            "severity": 1,
                            "message": (
                                f"Possible ICMP flood from {srcIP}: "
                                f"{total_icmp_pkts} packets in {ICMP_FLOOD_WINDOW_SECONDS}s"
                            )
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
            output.flush()  # Update and write to file immediately