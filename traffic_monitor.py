import json
import os
import time
from collections import defaultdict
from datetime import datetime, timezone

TIME_WINDOW_MINUTES = 60
EVE_LOG_PATH = "/var/log/suricata/eve.json"
OUTPUT_FILE = "traffic_stats.json"
WINDOW_SECONDS = TIME_WINDOW_MINUTES * 60


def iso_time(epoch_seconds):
    # Format an epoch time as ISO 8601 in local time with UTC offset.
    return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).astimezone().isoformat(timespec="seconds")


def process_event(event, records, flows, now):
    if event.get("event_type") != "flow":
        return

    flow = event["flow"]
    current = (flow.get("bytes_toserver", 0), 
               flow.get("pkts_toserver", 0),
               flow.get("bytes_toclient", 0), 
               flow.get("pkts_toclient", 0))

    flow_id = event.get("flow_id")
    previous = (0, 0, 0, 0)
    if flow_id is not None:
        if flow_id in flows:
            previous = flows[flow_id][0]
        flows[flow_id] = (current, now)

    bytes_ts, pkts_ts, bytes_tc, pkts_tc = [max(c - p, 0) for c, p in zip(current, previous)]

    if bytes_ts or pkts_ts:
        records.append((now, event["src_ip"], bytes_ts, pkts_ts))
    if bytes_tc or pkts_tc:
        records.append((now, event["dest_ip"], bytes_tc, pkts_tc))


def build_snapshot(records, now):
    bytes_by_ip = defaultdict(int)
    packets_by_ip = defaultdict(int)
    for _, ip, byte_count, packet_count in records:
        bytes_by_ip[ip] += byte_count
        packets_by_ip[ip] += packet_count

    total_bytes = sum(bytes_by_ip.values())
    total_packets = sum(packets_by_ip.values())

    ip_stats = []
    for ip in bytes_by_ip:
        ip_bytes = bytes_by_ip[ip]
        ip_packets = packets_by_ip[ip]
        ip_stats.append({
            "source_ip": ip,
            "payload_bytes": ip_bytes,
            "packet_count": ip_packets,
            "payload_percentage": round(ip_bytes / total_bytes * 100, 2) if total_bytes else 0.0,
            "packet_percentage": round(ip_packets / total_packets * 100, 2) if total_packets else 0.0,
        })

    ip_stats.sort(key=lambda s: (s["payload_bytes"], s["packet_count"]), reverse=True) # Largest senders first.

    return {
        "generated_at": iso_time(now),
        "generated_at_epoch": round(now, 3),
        "time_window_minutes": TIME_WINDOW_MINUTES,
        "window_start": iso_time(now - WINDOW_SECONDS),
        "total_payload_bytes": total_bytes,
        "total_packet_count": total_packets,
        "ip_count": len(ip_stats),
        "ips": ip_stats,
    }


def write_stats(stats):
    # Write to a temp file, then swap it in.
    temp_path = OUTPUT_FILE + ".tmp"
    with open(temp_path, "w", encoding="utf-8") as temp_file:
        json.dump(stats, temp_file, indent=2)
    os.replace(temp_path, OUTPUT_FILE)


def open_log(seek_to_end):
    log_file = open(EVE_LOG_PATH, "r", encoding="utf-8", errors="replace")
    if seek_to_end:
        log_file.seek(0, os.SEEK_END)
    return log_file, os.fstat(log_file.fileno()).st_ino


def log_was_rotated(log_file, inode):
    # Detect log rotation (new file) or truncation (file shrank).
    try:
        stat = os.stat(EVE_LOG_PATH)
    except FileNotFoundError:
        return False  # Rotation in progress; keep reading the old handle.
    return stat.st_ino != inode or stat.st_size < log_file.tell()


def monitor():
    records = []  # (time, ip, bytes, packets), oldest first
    flows = {}    # flow_id -> (counters, last_seen)

    print(f"Monitoring {EVE_LOG_PATH}")
    print(f"Rolling window: {TIME_WINDOW_MINUTES} minute(s)")
    print(f"Writing statistics to {os.path.abspath(OUTPUT_FILE)}")

    log_file, inode = open_log(seek_to_end=True)

    # Write an initial (empty) snapshot so the GUI has a file immediately.
    write_stats(build_snapshot(records, time.time()))
    last_write = time.time()
    partial_line = ""

    try:
        while True:
            chunk = log_file.readline()

            if chunk:
                # A line without a \n is still being written; keep it until the rest arrives
                if not chunk.endswith("\n"):
                    partial_line += chunk
                    continue
                line = (partial_line + chunk).strip()
                partial_line = ""

                try:
                    process_event(json.loads(line), records, flows, time.time())
                except (ValueError, KeyError, TypeError, AttributeError):
                    pass  # Empty or malformed line/event: skip it.
            else:
                # No new data: check for rotation, then sleep briefly.
                if log_was_rotated(log_file, inode):
                    print("Log rotated or truncated, reopening")
                    log_file.close()
                    log_file, inode = open_log(seek_to_end=False)
                    partial_line = ""
                    continue
                time.sleep(1) # Seconds to sleep when there are no new log lines.

            # Drop expired data and rewrite the file on a fixed interval, even
            # without new events, so old traffic disappears from the GUI.
            now = time.time()
            if now - last_write >= 1: # Seconds between writes of the statistics file.
                cutoff = now - WINDOW_SECONDS
                records = [r for r in records if r[0] >= cutoff]
                flows = {fid: f for fid, f in flows.items() if f[1] >= cutoff}
                write_stats(build_snapshot(records, now))
                last_write = now
    finally:
        log_file.close()


if __name__ == "__main__":
    try:
        monitor()
    except FileNotFoundError:
        print(f"Log file not found: {EVE_LOG_PATH}")
    except PermissionError:
        print(f"Permission denied reading {EVE_LOG_PATH} (try sudo)")