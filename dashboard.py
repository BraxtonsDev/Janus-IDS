import argparse
import json
import os
import sys
import time
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import customtkinter as ctk

# ============================================================================
# CONFIGURATION
# ============================================================================

# Folder containing the monitoring scripts' output files. Defaults to the same folder as this script.
DATA_DIR = Path(__file__).resolve().parent

# Output files (relative to DATA_DIR unless absolute).
NETWORK_ALERTS_FILE = "network_alerts.jsonl"
AUTH_ALERTS_FILE = "auth_alerts.jsonl"
TRAFFIC_STATS_FILE = "traffic_stats.json"

# Refresh intervals (milliseconds).
ALERT_REFRESH_MS = 1000
TRAFFIC_REFRESH_MS = 2000

# Initial window size (pixels).
WINDOW_WIDTH = 1400
WINDOW_HEIGHT = 850

# Maximum number of alerts kept in (and loaded into) the notification feed.
MAX_DISPLAYED_ALERTS = 100

# Maximum number of IP rows shown in the traffic table.
MAX_TRAFFIC_ROWS = 100

# If traffic_stats.json has not been regenerated for this many seconds, the
# panel warns that the statistics may be out of date.
TRAFFIC_STALE_AFTER_SECONDS = 15

# How long (ms) newly arrived alerts keep a highlighted border.
NEW_ALERT_HIGHLIGHT_MS = 6000

# Safety limits for reading the JSONL files.
READ_BLOCK_SIZE = 64 * 1024            # block size when reading files backwards
MAX_BYTES_PER_POLL = 1024 * 1024       # max new bytes read per file per refresh
MAX_PARTIAL_LINE_BYTES = 1024 * 1024   # discard an unterminated line beyond this

# ============================================================================
# THEME
# ============================================================================

COLOR_BG = "#0f1115"
COLOR_PANEL = "#161a21"
COLOR_CARD = "#1d222b"
COLOR_CARD_HOVER = "#252b36"
COLOR_BORDER = "#2a303c"
COLOR_ROW_ALT = "#1a1f27"
COLOR_TEXT = "#e6e8eb"
COLOR_TEXT_SECONDARY = "#b4bac4"
COLOR_TEXT_MUTED = "#7f8794"
COLOR_ACCENT = "#3b82f6"
COLOR_OK = "#22c55e"
COLOR_WARN = "#f59e0b"
COLOR_ERROR = "#ef4444"

SEVERITY_STYLES = {
    "High":    {"color": "#ef4444", "text": "#ffffff"},
    "Medium":  {"color": "#f59e0b", "text": "#1a1205"},
    "Low":     {"color": "#3b82f6", "text": "#ffffff"},
    "Unknown": {"color": "#6b7280", "text": "#ffffff"},
}

STATUS_COLORS = {"ok": COLOR_OK, "warn": COLOR_WARN, "error": COLOR_ERROR}

if sys.platform.startswith("win"):
    MONO_FAMILY = "Consolas"
elif sys.platform == "darwin":
    MONO_FAMILY = "Menlo"
else:
    MONO_FAMILY = "DejaVu Sans Mono"

# Traffic table columns: (heading, minimum width in px, text anchor).
TRAFFIC_COLUMNS = [
    ("IP Address", 130, "w"),
    ("Traffic", 78, "e"),
    ("Traffic %", 72, "e"),
    ("Packets", 74, "e"),
    ("Packets %", 76, "e"),
]

TIME_DISPLAY_FORMAT = "%d %b %Y, %H:%M:%S"


# ============================================================================
# NORMALIZATION HELPERS
# ============================================================================

def normalize_severity(value):
    """Map the scripts' severity formats onto High / Medium / Low / Unknown.

    Numeric: 1 = High, 2 = Medium, 3 = Low.
    Text:    "High", "Medium", "Low" (case-insensitive).
    Anything else is reported as "Unknown" instead of raising an error.
    """
    if isinstance(value, bool):
        return "Unknown"
    if isinstance(value, str):
        text = value.strip().lower()
        named = {"high": "High", "medium": "Medium", "low": "Low"}
        if text in named:
            return named[text]
        try:
            value = float(text)
        except ValueError:
            return "Unknown"
    if isinstance(value, (int, float)):
        numeric = {1: "High", 2: "Medium", 3: "Low"}
        if value == int(value):
            return numeric.get(int(value), "Unknown")
    return "Unknown"


def _epoch_to_datetime(seconds):
    if seconds > 1e12:  # looks like milliseconds
        seconds /= 1000.0
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def normalize_timestamp(value):
    """Convert an ISO 8601 string or a Unix timestamp into an aware datetime.

    Returns None if the value is missing or cannot be understood.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return _epoch_to_datetime(float(value))
    if not isinstance(value, str):
        return None

    text = value.strip()
    if not text:
        return None

    # Unix timestamp stored as a string.
    try:
        return _epoch_to_datetime(float(text))
    except ValueError:
        pass

    # ISO 8601, e.g. Suricata's "2026-11-13T10:15:42.123456+0000".
    parsed = None
    iso_text = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(iso_text)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                    "%Y-%m-%d %H:%M:%S"):
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.astimezone()  # naive -> assume local time
    return parsed


def format_local_time(dt, fmt=TIME_DISPLAY_FORMAT):
    """Format an aware datetime in the user's local time zone."""
    if dt is None:
        return "Unknown time"
    try:
        return dt.astimezone().strftime(fmt)
    except (OverflowError, OSError, ValueError):
        return "Unknown time"


def format_bytes(value):
    """Human-readable byte count (B, KB, MB, GB, TB)."""
    size = float(value)
    for unit in ("B", "KB", "MB", "GB"):
        if abs(size) < 1024:
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def format_count(value):
    return f"{int(value):,}"


def format_percent(value):
    return f"{value:.1f}%"


def format_window(minutes):
    if minutes is None:
        return "Unknown"
    if minutes >= 60 and minutes % 60 == 0:
        hours = int(minutes // 60)
        return f"Last {hours} hour" + ("" if hours == 1 else "s")
    shown = int(minutes) if minutes == int(minutes) else minutes
    return f"Last {shown} min"


def format_age(seconds):
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    return f"{seconds // 3600}h ago"


def safe_number(value, default=None, minimum=None):
    """Return value as a number, or default if it is missing/invalid."""
    if isinstance(value, bool):
        return default
    if isinstance(value, str):
        try:
            value = float(value)
        except ValueError:
            return default
    if not isinstance(value, (int, float)) or value != value:  # NaN check
        return default
    if minimum is not None and value < minimum:
        return default
    return value


def blend(color_a, color_b, ratio):
    """Mix two #rrggbb colours (ratio 0 -> a, 1 -> b)."""
    ratio = max(0.0, min(1.0, ratio))
    a = [int(color_a[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(color_b[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x + (y - x) * ratio):02x}" for x, y in zip(a, b))


def resolve_path(name):
    path = Path(name)
    return path if path.is_absolute() else DATA_DIR / path


# ============================================================================
# ALERT MODEL
# ============================================================================

@dataclass
class Alert:
    key: str
    source_label: str
    alert_file: str
    log_source: str
    alert_type: str
    message: str
    severity: str
    severity_raw: object
    source_ip: str
    timestamp: object       # aware datetime or None
    time_raw: object
    raw_log: object
    sort_ts: float
    seq: int


def _text_field(value, default):
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def build_alert(record, line_text, source, fallback_ts, seq):
    """Turn one parsed JSONL record into an Alert, filling in safe defaults."""
    timestamp = normalize_timestamp(record.get("time"))
    sort_ts = timestamp.timestamp() if timestamp else fallback_ts
    return Alert(
        key=f"{source['file']}|{line_text}",
        source_label=source["label"],
        alert_file=source["file"],
        log_source=_text_field(record.get("source"), "Unknown"),
        alert_type=_text_field(record.get("alert_type"), "Unknown alert"),
        message=_text_field(record.get("message"), "No description provided."),
        severity=normalize_severity(record.get("severity")),
        severity_raw=record.get("severity"),
        source_ip=_text_field(record.get("source_ip"), "Unknown"),
        timestamp=timestamp,
        time_raw=record.get("time"),
        raw_log=record.get("raw_log"),
        sort_ts=sort_ts,
        seq=seq,
    )


# ============================================================================
# FILE READERS
# ============================================================================

def parse_jsonl_line(raw):
    """Return (record, text) for a valid JSON object line, else None."""
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        return None
    try:
        record = json.loads(text)
    except ValueError:
        return None  # malformed line: skip it
    if not isinstance(record, dict):
        return None
    return record, text


class JsonlAlertReader:
    """Follows one append-only JSONL file without re-reading old content.

    - The first read (and any read after truncation/replacement/deletion)
      loads only the newest `max_records` valid lines from the end of the file.
    - Afterwards only bytes appended since the last read are processed.
    - An unterminated last line is buffered until its newline arrives.
    """

    def __init__(self, path):
        self.path = Path(path)
        self.position = 0          # byte offset of data already consumed
        self.buffer = b""          # incomplete trailing line
        self.file_id = None        # (device, inode) of the file being followed
        self.needs_tail = True     # next read should load the file's tail
        self.status = ("warn", "Not checked yet")

    def _reset(self):
        self.position = 0
        self.buffer = b""
        self.file_id = None
        self.needs_tail = True

    def poll(self, max_records):
        """Return a list of (record, line_text) tuples that are new."""
        try:
            with open(self.path, "rb") as handle:
                info = os.fstat(handle.fileno())
                file_id = (info.st_dev, info.st_ino)
                note = ""
                if self.file_id is not None and file_id != self.file_id:
                    self._reset()
                    note = " (file was replaced, reloaded)"
                elif not self.needs_tail and info.st_size < self.position:
                    self._reset()
                    note = " (file was truncated, reloaded)"

                if self.needs_tail:
                    records = self._load_tail(handle, info.st_size, max_records)
                    self.needs_tail = False
                else:
                    records = self._read_appended(handle, info.st_size)
                self.file_id = file_id
        except FileNotFoundError:
            self._reset()
            self.status = ("warn", "Waiting for file (monitoring script not started yet?)")
            return []
        except PermissionError:
            self._reset()
            self.status = ("error", f"Permission denied: cannot read {self.path}")
            return []
        except OSError as exc:
            self._reset()
            self.status = ("error", f"Cannot read file: {exc.strerror or exc}")
            return []

        self.status = ("ok", "Connected" + note)
        return records

    def _load_tail(self, handle, size, max_records):
        complete_end = self._find_complete_end(handle, size)
        records = []
        pos = complete_end
        leftover = b""
        while pos > 0 and len(records) < max_records:
            step = min(READ_BLOCK_SIZE, pos)
            pos -= step
            handle.seek(pos)
            parts = (handle.read(step) + leftover).split(b"\n")
            leftover = parts[0]  # may be the tail end of an earlier line
            for raw in reversed(parts[1:]):
                parsed = parse_jsonl_line(raw)
                if parsed:
                    records.append(parsed)
                    if len(records) >= max_records:
                        break
        if pos == 0 and leftover and len(records) < max_records:
            parsed = parse_jsonl_line(leftover)
            if parsed:
                records.append(parsed)
        records.reverse()  # back to file order (oldest first)

        # Anything after the last newline is an incomplete line; it will be
        # picked up by _read_appended once it has been completed.
        self.position = complete_end
        self.buffer = b""
        return records

    @staticmethod
    def _find_complete_end(handle, size):
        """Byte offset just after the last newline in the file (0 if none)."""
        pos = size
        while pos > 0:
            step = min(READ_BLOCK_SIZE, pos)
            pos -= step
            handle.seek(pos)
            index = handle.read(step).rfind(b"\n")
            if index != -1:
                return pos + index + 1
        return 0

    def _read_appended(self, handle, size):
        if size <= self.position:
            return []
        handle.seek(self.position)
        data = handle.read(min(size - self.position, MAX_BYTES_PER_POLL))
        self.position += len(data)

        lines = (self.buffer + data).split(b"\n")
        self.buffer = lines.pop()
        if len(self.buffer) > MAX_PARTIAL_LINE_BYTES:
            self.buffer = b""  # a runaway line without newline; drop it
        return [parsed for parsed in map(parse_jsonl_line, lines) if parsed]


class TrafficStatsReader:
    """Reads the latest complete traffic_stats.json snapshot."""

    def __init__(self, path):
        self.path = Path(path)
        self.last_signature = None
        self.data = None  # last successfully parsed snapshot

    def read(self):
        """Return (status_level, status_text). Updates self.data when possible."""
        try:
            info = os.stat(self.path)
        except FileNotFoundError:
            self.data = None
            self.last_signature = None
            return "warn", "Waiting for traffic statistics (traffic_monitor.py not started yet?)"
        except PermissionError:
            return "error", f"Permission denied: cannot read {self.path}"
        except OSError as exc:
            return "error", f"Cannot access traffic statistics: {exc.strerror or exc}"

        signature = (info.st_ino, info.st_mtime_ns, info.st_size)
        if signature == self.last_signature and self.data is not None:
            return "ok", ""  # unchanged since last read

        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                raw = json.load(handle)
        except PermissionError:
            return "error", f"Permission denied: cannot read {self.path}"
        except (OSError, ValueError):
            # Temporary problem (e.g. mid-write); keep showing previous data.
            return "warn", "Traffic statistics temporarily unavailable, retrying..."

        if not isinstance(raw, dict):
            return "warn", "Traffic statistics file has an unexpected format"

        self.data = self._clean(raw)
        self.last_signature = signature
        return "ok", ""

    @staticmethod
    def _clean(raw):
        """Validate every field; missing/invalid values become None or 0."""
        generated = safe_number(raw.get("generated_at_epoch"), minimum=0)
        if generated is None:
            parsed = normalize_timestamp(raw.get("generated_at"))
            generated = parsed.timestamp() if parsed else None

        ips = []
        entries = raw.get("ips")
        for entry in entries if isinstance(entries, list) else []:
            if not isinstance(entry, dict):
                continue
            ip = _text_field(entry.get("source_ip"), None)
            if ip is None:
                continue
            ips.append({
                "ip": ip,
                "bytes": safe_number(entry.get("payload_bytes"), 0, minimum=0),
                "packets": safe_number(entry.get("packet_count"), 0, minimum=0),
                "bytes_pct": safe_number(entry.get("payload_percentage"), 0.0, minimum=0),
                "packets_pct": safe_number(entry.get("packet_percentage"), 0.0, minimum=0),
            })
        ips.sort(key=lambda e: (e["bytes"], e["packets"]), reverse=True)

        return {
            "generated_epoch": generated,
            "window_minutes": safe_number(raw.get("time_window_minutes"), minimum=0),
            "total_bytes": safe_number(raw.get("total_payload_bytes"), minimum=0),
            "total_packets": safe_number(raw.get("total_packet_count"), minimum=0),
            "ip_count": safe_number(raw.get("ip_count"), len(ips), minimum=0),
            "ips": ips,
        }


# ============================================================================
# WIDGETS: NOTIFICATION FEED
# ============================================================================

def rounded_rect(canvas, x1, y1, x2, y2, radius, **options):
    """Draw a rounded rectangle on a Tk canvas (smoothed polygon)."""
    r = max(0, min(radius, (x2 - x1) / 2, (y2 - y1) / 2))
    points = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
              x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return canvas.create_polygon(points, smooth=True, **options)


class AlertCard(tk.Canvas):
    """Compact, clickable notification card.

    The whole card is drawn on a single canvas (rounded background, severity
    stripe, badge and text). Building every card from separate widgets made a
    100-alert feed slow to appear, because Tk pays a fixed cost per widget.
    """

    PAD_X = 14
    TEXT_X = 30   # left edge of the text, right of the severity stripe

    def __init__(self, master, alert, fonts, width, on_click):
        super().__init__(master, bg=COLOR_PANEL, highlightthickness=0, borderwidth=0,
                         height=90, cursor="hand2")
        self.alert = alert
        self.fonts = fonts
        self._on_click = on_click
        self._drawn_width = None
        self._resize_job = None
        self._background = COLOR_CARD
        self._border = COLOR_BORDER
        self._meta_text = "   •   ".join([
            format_local_time(alert.timestamp),
            f"Source IP: {alert.source_ip}",
            alert.source_label,
        ])

        self.draw(width)
        self.bind("<Configure>", self._on_configure)
        self.bind("<Button-1>", lambda _e: self._on_click(self.alert))
        self.bind("<Enter>", lambda _e: self._set_background(COLOR_CARD_HOVER))
        self.bind("<Leave>", lambda _e: self._set_background(COLOR_CARD))

    def draw(self, width):
        """(Re)draw the card for the given pixel width and fit its height."""
        width = max(int(width), 320)
        self._drawn_width = width
        self.delete("all")
        style = SEVERITY_STYLES[self.alert.severity]
        fonts = self.fonts
        right = width - self.PAD_X

        # Severity badge (top right).
        badge_text = self.alert.severity.upper()
        badge_w = max(fonts["tk_badge"].measure(badge_text) + 22, 74)
        badge_h = fonts["tk_badge"].metrics("linespace") + 8
        rounded_rect(self, right - badge_w, 12, right, 12 + badge_h, 7,
                     fill=style["color"], outline="")
        self.create_text(right - badge_w / 2, 12 + badge_h / 2, text=badge_text,
                         fill=style["text"], font=fonts["tk_badge"])

        # Text lines: title, message, details.
        title = self.create_text(self.TEXT_X, 12, anchor="nw", text=self.alert.alert_type,
                                 fill=COLOR_TEXT, font=fonts["tk_card_title"],
                                 width=right - badge_w - 12 - self.TEXT_X)
        y = max(self.bbox(title)[3], 12 + badge_h) + 3
        message = self.create_text(self.TEXT_X, y, anchor="nw", text=self.alert.message,
                                   fill=COLOR_TEXT_SECONDARY, font=fonts["tk_body"],
                                   width=right - self.TEXT_X)
        y = self.bbox(message)[3] + 5
        meta = self.create_text(self.TEXT_X, y, anchor="nw", text=self._meta_text,
                                fill=COLOR_TEXT_MUTED, font=fonts["tk_small"],
                                width=right - self.TEXT_X)
        height = self.bbox(meta)[3] + 12

        # Background and stripe go underneath the text.
        rounded_rect(self, 1, 1, width - 1, height - 1, 12, tags="card",
                     fill=self._background, outline=self._border, width=1)
        rounded_rect(self, 14, 13, 18, height - 13, 2, fill=style["color"],
                     outline="", tags="stripe")
        self.tag_lower("stripe")
        self.tag_lower("card")
        self.configure(height=height)

    def _on_configure(self, event):
        if event.width == self._drawn_width:
            return
        # Debounce redraws while the window is being resized.
        if self._resize_job is not None:
            self.after_cancel(self._resize_job)
        self._resize_job = self.after(80, self._redraw)

    def _redraw(self):
        self._resize_job = None
        width = self.winfo_width()
        if width > 1 and width != self._drawn_width:
            self.draw(width)

    def _set_background(self, color):
        self._background = color
        self.itemconfigure("card", fill=color)

    def highlight(self, duration_ms):
        """Briefly outline a newly arrived alert in its severity colour."""
        self._border = SEVERITY_STYLES[self.alert.severity]["color"]
        self.itemconfigure("card", outline=self._border, width=2)
        self.after(duration_ms, self._unhighlight)

    def _unhighlight(self):
        if self.winfo_exists():
            self._border = COLOR_BORDER
            self.itemconfigure("card", outline=COLOR_BORDER, width=1)

class NotificationFeed(ctk.CTkFrame):
    """Central panel: heading plus a scrollable list of alert cards."""

    def __init__(self, master, fonts, on_alert_click):
        super().__init__(master, fg_color=COLOR_PANEL, corner_radius=14)
        self.fonts = fonts
        self.on_alert_click = on_alert_click
        self.cards = {}  # alert.key -> AlertCard

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        heading = ctk.CTkFrame(self, fg_color="transparent")
        heading.grid(row=0, column=0, sticky="ew", padx=20, pady=(18, 8))
        ctk.CTkLabel(heading, text="Recent Alerts", font=fonts["section"],
                     text_color=COLOR_TEXT).pack(side="left")
        self.subtitle = ctk.CTkLabel(heading, text="", font=fonts["small"],
                                     text_color=COLOR_TEXT_MUTED)
        self.subtitle.pack(side="right")

        self.scroll = ctk.CTkScrollableFrame(self, fg_color="transparent",
                                             corner_radius=0)
        self.scroll.grid(row=1, column=0, sticky="nsew", padx=(14, 6), pady=(0, 14))
        self.scroll.grid_columnconfigure(0, weight=1)

        self.empty_label = ctk.CTkLabel(
            self.scroll, font=fonts["body"], text_color=COLOR_TEXT_MUTED, justify="center",
            text="No alerts yet.\n\nNew notifications from the network and login "
                 "monitors will appear here automatically.")

    def show_alerts(self, alerts, new_keys=()):
        """Display `alerts` (already sorted newest first), reusing existing cards."""
        wanted = {alert.key for alert in alerts}
        for key in [k for k in self.cards if k not in wanted]:
            self.cards.pop(key).destroy()

        # Initial card width: current list width, or an estimate before the
        # window is first shown. Cards redraw themselves when resized.
        width = self.scroll.winfo_width() - 8
        if width < 100:
            width = WINDOW_WIDTH - 640
        for row, alert in enumerate(alerts):
            card = self.cards.get(alert.key)
            if card is None:
                card = AlertCard(self.scroll, alert, self.fonts, width,
                                 self.on_alert_click)
                self.cards[alert.key] = card
                if alert.key in new_keys:
                    card.highlight(NEW_ALERT_HIGHLIGHT_MS)
            card.grid(row=row, column=0, sticky="ew", padx=(0, 8), pady=4)

        if alerts:
            self.empty_label.grid_forget()
        else:
            self.empty_label.grid(row=0, column=0, pady=80)

        count = len(alerts)
        self.subtitle.configure(
            text=f"Showing {count} most recent" if count else "Monitoring for new alerts")


class AlertDetailWindow(ctk.CTkToplevel):
    """Pop-up showing every field of one alert, including the raw log."""

    def __init__(self, master, alert, fonts):
        super().__init__(master)
        self.title(f"Alert details - {alert.alert_type}")
        self.geometry("780x640")
        self.minsize(560, 460)
        self.configure(fg_color=COLOR_BG)
        style = SEVERITY_STYLES[alert.severity]

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # Header: severity badge + alert type.
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=22, pady=(20, 10))
        header.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(header, text=alert.severity.upper(), font=fonts["badge"],
                     fg_color=style["color"], text_color=style["text"],
                     corner_radius=6, height=24, width=80).grid(row=0, column=0, padx=(0, 12))
        ctk.CTkLabel(header, text=alert.alert_type, font=fonts["title"],
                     text_color=COLOR_TEXT, anchor="w", justify="left",
                     wraplength=620).grid(row=0, column=1, sticky="ew")

        # Detail fields.
        fields_frame = ctk.CTkFrame(self, fg_color=COLOR_PANEL, corner_radius=12)
        fields_frame.grid(row=1, column=0, sticky="ew", padx=22, pady=(0, 12))
        fields_frame.grid_columnconfigure(1, weight=1)

        severity_text = alert.severity
        if alert.severity_raw is not None and str(alert.severity_raw) != alert.severity:
            severity_text += f"   (reported as: {alert.severity_raw})"
        time_text = format_local_time(alert.timestamp)
        if alert.time_raw is not None:
            time_text += f"   (original: {alert.time_raw})"

        fields = [
            ("Alert type", alert.alert_type),
            ("Severity", severity_text),
            ("Source IP", alert.source_ip),
            ("Timestamp", time_text),
            ("Message", alert.message),
            ("Source log file", f"{alert.log_source}   (alerts file: {alert.alert_file})"),
            ("Reported by", alert.source_label),
        ]
        for row, (name, value) in enumerate(fields):
            top = 14 if row == 0 else 4
            bottom = 14 if row == len(fields) - 1 else 4
            ctk.CTkLabel(fields_frame, text=name, font=fonts["label"],
                         text_color=COLOR_TEXT_MUTED, anchor="nw", width=120
                         ).grid(row=row, column=0, sticky="nw", padx=(16, 8), pady=(top, bottom))
            ctk.CTkLabel(fields_frame, text=value, font=fonts["body"],
                         text_color=COLOR_TEXT, anchor="w", justify="left",
                         wraplength=560).grid(row=row, column=1, sticky="ew",
                                              padx=(0, 16), pady=(top, bottom))

        # Raw log entry.
        raw_frame = ctk.CTkFrame(self, fg_color=COLOR_PANEL, corner_radius=12)
        raw_frame.grid(row=2, column=0, sticky="nsew", padx=22, pady=(0, 12))
        raw_frame.grid_columnconfigure(0, weight=1)
        raw_frame.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(raw_frame, text="Raw log entry", font=fonts["label"],
                     text_color=COLOR_TEXT_MUTED, anchor="w"
                     ).grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 4))
        textbox = ctk.CTkTextbox(raw_frame, font=fonts["mono"], wrap="word",
                                 fg_color=COLOR_BG, text_color=COLOR_TEXT,
                                 border_width=1, border_color=COLOR_BORDER)
        textbox.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 14))
        textbox.insert("1.0", self._format_raw(alert.raw_log))
        textbox.configure(state="disabled")  # read-only, text remains selectable

        ctk.CTkButton(self, text="Close", width=110, command=self.destroy
                      ).grid(row=3, column=0, sticky="e", padx=22, pady=(0, 18))

        self.bind("<Escape>", lambda _e: self.destroy())
        # Bring the window to the front once it is mapped.
        self.after(120, self._bring_to_front)

    def _bring_to_front(self):
        if self.winfo_exists():
            self.lift()
            self.focus_force()

    @staticmethod
    def _format_raw(raw):
        """Pretty-print the raw log if it is JSON (e.g. Suricata), else show as is."""
        if raw is None:
            return "(no raw log entry recorded)"
        if isinstance(raw, (dict, list)):
            return json.dumps(raw, indent=2, ensure_ascii=False)
        text = str(raw)
        try:
            parsed = json.loads(text)
            if isinstance(parsed, (dict, list)):
                return json.dumps(parsed, indent=2, ensure_ascii=False)
        except ValueError:
            pass
        return text


# ============================================================================
# WIDGETS: TRAFFIC PANEL
# ============================================================================

class StatTile(ctk.CTkFrame):
    """Small summary figure: caption above a large value."""

    def __init__(self, master, caption, fonts):
        super().__init__(master, fg_color=COLOR_CARD, corner_radius=10)
        ctk.CTkLabel(self, text=caption, font=fonts["small"],
                     text_color=COLOR_TEXT_MUTED, anchor="w"
                     ).pack(fill="x", padx=14, pady=(10, 0))
        self.value = ctk.CTkLabel(self, text="—", font=fonts["stat"],
                                  text_color=COLOR_TEXT, anchor="w")
        self.value.pack(fill="x", padx=14, pady=(0, 10))

    def set(self, text):
        if self.value.cget("text") != text:
            self.value.configure(text=text)


class TrafficPanel(ctk.CTkFrame):
    """Right-hand panel: summary tiles and a scrollable per-IP table.

    The table is a ttk.Treeview (Tk's native table widget) styled to match
    the dark theme: it scrolls smoothly, keeps its header visible and stays
    fast no matter how many rows it holds.
    """

    def __init__(self, master, fonts):
        super().__init__(master, fg_color=COLOR_PANEL, corner_radius=14)
        self.fonts = fonts
        self.row_ids = []      # Treeview item ids, reused between refreshes
        self.row_values = []   # values currently shown in each row

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        ctk.CTkLabel(self, text="Network Traffic", font=fonts["section"],
                     text_color=COLOR_TEXT, anchor="w"
                     ).grid(row=0, column=0, sticky="ew", padx=20, pady=(18, 2))
        self.status_label = ctk.CTkLabel(self, text="", font=fonts["small"],
                                         text_color=COLOR_TEXT_MUTED, anchor="w",
                                         justify="left", wraplength=440)
        self.status_label.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 10))

        tiles = ctk.CTkFrame(self, fg_color="transparent")
        tiles.grid(row=2, column=0, sticky="ew", padx=14)
        tiles.grid_columnconfigure((0, 1), weight=1, uniform="tiles")
        self.tile_volume = StatTile(tiles, "Total traffic volume", fonts)
        self.tile_packets = StatTile(tiles, "Total packets", fonts)
        self.tile_window = StatTile(tiles, "Time window", fonts)
        self.tile_updated = StatTile(tiles, "Last updated", fonts)
        for index, tile in enumerate((self.tile_volume, self.tile_packets,
                                      self.tile_window, self.tile_updated)):
            tile.grid(row=index // 2, column=index % 2, sticky="ew", padx=6, pady=6)

        table_box = ctk.CTkFrame(self, fg_color=COLOR_CARD, corner_radius=10)
        table_box.grid(row=3, column=0, sticky="nsew", padx=20, pady=(12, 6))
        table_box.grid_columnconfigure(0, weight=1)
        table_box.grid_rowconfigure(0, weight=1)

        self._configure_table_style()
        columns = [name for name, _w, _a in TRAFFIC_COLUMNS]
        self.tree = ttk.Treeview(table_box, columns=columns, show="headings",
                                 style="Traffic.Treeview", selectmode="browse")
        for name, width, anchor in TRAFFIC_COLUMNS:
            self.tree.heading(name, text=name, anchor=anchor)
            self.tree.column(name, width=width, minwidth=width, anchor=anchor,
                             stretch=(name == "IP Address"))
        self.tree.tag_configure("odd", background=COLOR_ROW_ALT)
        self.tree.tag_configure("even", background=COLOR_CARD)

        scrollbar = ctk.CTkScrollbar(table_box, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.grid(row=0, column=0, sticky="nsew", padx=(8, 0), pady=8)
        scrollbar.grid(row=0, column=1, sticky="ns", padx=(2, 4), pady=8)

        self.table_message = ctk.CTkLabel(table_box, text="", font=fonts["body"],
                                          text_color=COLOR_TEXT_MUTED, justify="center",
                                          wraplength=380)

        self.footer = ctk.CTkLabel(self, text="", font=fonts["small"],
                                   text_color=COLOR_TEXT_MUTED, anchor="w")
        self.footer.grid(row=4, column=0, sticky="ew", padx=20, pady=(0, 12))

        self.update_stats(None, "warn", "Waiting for traffic statistics...")

    def _configure_table_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")  # the only built-in theme that honours colours
        row_height = self.fonts["tk_table"].metrics("linespace") + 12
        style.configure("Traffic.Treeview", background=COLOR_CARD,
                        fieldbackground=COLOR_CARD, foreground=COLOR_TEXT,
                        font=self.fonts["tk_table"], rowheight=row_height,
                        borderwidth=0, relief="flat")
        style.layout("Traffic.Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        style.map("Traffic.Treeview",
                  background=[("selected", blend(COLOR_CARD, COLOR_ACCENT, 0.45))],
                  foreground=[("selected", COLOR_TEXT)])
        style.configure("Traffic.Treeview.Heading", background=COLOR_CARD,
                        foreground=COLOR_TEXT_MUTED, font=self.fonts["tk_table_head"],
                        relief="flat", borderwidth=0, padding=(6, 6))
        style.map("Traffic.Treeview.Heading",
                  background=[("active", COLOR_CARD)], relief=[("active", "flat")])

    def update_stats(self, data, level, status_text):
        """Refresh the panel from a cleaned snapshot (or None if unavailable)."""
        if data is None:
            for tile in (self.tile_volume, self.tile_packets,
                         self.tile_window, self.tile_updated):
                tile.set("—")
            self._set_status(status_text, level)
            self._show_table_message(
                "Waiting for traffic statistics...\n\n"
                "Live data will appear once traffic_monitor.py is running.")
            self.footer.configure(text="")
            return

        self.tile_volume.set(format_bytes(data["total_bytes"])
                             if data["total_bytes"] is not None else "—")
        self.tile_packets.set(format_count(data["total_packets"])
                              if data["total_packets"] is not None else "—")
        self.tile_window.set(format_window(data["window_minutes"]))

        generated = data["generated_epoch"]
        if generated is None:
            self.tile_updated.set("Unknown")
            age = None
        else:
            age = time.time() - generated
            clock = format_local_time(datetime.fromtimestamp(generated, tz=timezone.utc),
                                      "%H:%M:%S")
            self.tile_updated.set(f"{clock}  ({format_age(age)})")

        if level != "ok":
            self._set_status(status_text + " Showing last known data.", level)
        elif age is not None and age > TRAFFIC_STALE_AFTER_SECONDS:
            self._set_status(f"No new statistics for {format_age(age)[:-4]}. "
                             "Is traffic_monitor.py still running?", "warn")
        else:
            self._set_status("● Live - updating automatically", "ok")

        self._fill_table(data["ips"])
        shown = min(len(data["ips"]), MAX_TRAFFIC_ROWS)
        total = int(data["ip_count"] or len(data["ips"]))
        self.footer.configure(
            text=f"{total:,} IP address{'es' if total != 1 else ''} in window"
                 + (f" (top {shown} shown)" if total > shown else ""))

    def _set_status(self, text, level):
        self.status_label.configure(text=text,
                                    text_color=STATUS_COLORS.get(level, COLOR_TEXT_MUTED))

    def _show_table_message(self, text):
        self.tree.grid_remove()
        self.table_message.configure(text=text)
        self.table_message.grid(row=0, column=0, padx=20, pady=60)

    def _fill_table(self, ips):
        if not ips:
            self._show_table_message("No traffic recorded in the current time window.")
            return
        self.table_message.grid_remove()
        self.tree.grid()

        visible = ips[:MAX_TRAFFIC_ROWS]
        for index, entry in enumerate(visible):
            values = (
                entry["ip"],
                format_bytes(entry["bytes"]),
                format_percent(entry["bytes_pct"]),
                format_count(entry["packets"]),
                format_percent(entry["packets_pct"]),
            )
            if index < len(self.row_ids):
                # Reuse the existing row; only touch it if something changed.
                if self.row_values[index] != values:
                    self.tree.item(self.row_ids[index], values=values)
                    self.row_values[index] = values
            else:
                tag = "odd" if index % 2 else "even"
                self.row_ids.append(self.tree.insert("", "end", values=values, tags=(tag,)))
                self.row_values.append(values)

        # Remove rows that are no longer needed.
        extra = self.row_ids[len(visible):]
        if extra:
            self.tree.delete(*extra)
            del self.row_ids[len(visible):]
            del self.row_values[len(visible):]


# ============================================================================
# MAIN APPLICATION
# ============================================================================

class Dashboard(ctk.CTk):

    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title("Network Monitoring Dashboard")
        self.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
        self.minsize(1100, 650)
        self.configure(fg_color=COLOR_BG)

        self.fonts = self._create_fonts()
        self.alert_sources = [
            {"file": NETWORK_ALERTS_FILE, "label": "Network monitor",
             "reader": JsonlAlertReader(resolve_path(NETWORK_ALERTS_FILE))},
            {"file": AUTH_ALERTS_FILE, "label": "Login monitor",
             "reader": JsonlAlertReader(resolve_path(AUTH_ALERTS_FILE))},
        ]
        self.traffic_reader = TrafficStatsReader(resolve_path(TRAFFIC_STATS_FILE))

        self.alerts = []        # current feed, newest first
        self._seq = 0           # tie-breaker preserving arrival order
        self._jobs = {}         # pending .after() jobs, cancelled on close

        self._build_layout()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Initial load, then start the periodic refresh loops.
        self.load_initial_alerts()
        self.refresh_traffic()
        self._jobs["alerts"] = self.after(ALERT_REFRESH_MS, self.poll_new_alerts)

    # ---------------------------------------------------------------- layout
    def _create_fonts(self):
        # Canvas text and the ttk table are not scaled automatically, so apply the same
        # DPI scaling CustomTkinter uses (negative size = pixels).
        scale = ctk.ScalingTracker.get_widget_scaling(self)
        family = ctk.CTkFont().cget("family")

        def tk_font(size, weight="normal"):
            return tkfont.Font(self, family=family, size=-round(size * scale),
                               weight=weight)

        return {
            "tk_card_title": tk_font(15, "bold"),
            "tk_body": tk_font(13),
            "tk_small": tk_font(12),
            "tk_badge": tk_font(11, "bold"),
            "tk_table": tk_font(12),
            "tk_table_head": tk_font(12, "bold"),
            "app_title": ctk.CTkFont(size=22, weight="bold"),
            "title": ctk.CTkFont(size=20, weight="bold"),
            "section": ctk.CTkFont(size=18, weight="bold"),
            "body": ctk.CTkFont(size=13),
            "label": ctk.CTkFont(size=12, weight="bold"),
            "small": ctk.CTkFont(size=12),
            "badge": ctk.CTkFont(size=11, weight="bold"),
            "stat": ctk.CTkFont(size=18, weight="bold"),
            "counter": ctk.CTkFont(size=20, weight="bold"),
            "mono": ctk.CTkFont(family=MONO_FAMILY, size=12),
        }

    def _build_layout(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._build_header()

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 6))
        body.grid_columnconfigure(0, weight=1)                 # feed grows
        body.grid_columnconfigure(1, weight=0, minsize=500)    # traffic panel
        body.grid_rowconfigure(0, weight=1)

        self.feed = NotificationFeed(body, self.fonts, self.open_alert_details)
        self.feed.grid(row=0, column=0, sticky="nsew", padx=(0, 9))

        self.traffic_panel = TrafficPanel(body, self.fonts)
        self.traffic_panel.grid(row=0, column=1, sticky="nsew", padx=(9, 0))

        self._build_status_bar()

    def _build_header(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=24, pady=(18, 14))
        header.grid_columnconfigure(1, weight=1)

        title_box = ctk.CTkFrame(header, fg_color="transparent")
        title_box.grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(title_box, text="Network Monitoring Dashboard",
                     font=self.fonts["app_title"], text_color=COLOR_TEXT
                     ).pack(anchor="w")
        status = ctk.CTkFrame(title_box, fg_color="transparent")
        status.pack(anchor="w", pady=(2, 0))
        ctk.CTkLabel(status, text="●", text_color=COLOR_OK,
                     font=self.fonts["small"]).pack(side="left")
        self.running_label = ctk.CTkLabel(status, text=" Running", font=self.fonts["small"],
                                          text_color=COLOR_TEXT_SECONDARY)
        self.running_label.pack(side="left")

        counters = ctk.CTkFrame(header, fg_color="transparent")
        counters.grid(row=0, column=2, sticky="e")
        self.counter_labels = {}
        for name, color in (("Total", COLOR_TEXT),
                            ("High", SEVERITY_STYLES["High"]["color"]),
                            ("Medium", SEVERITY_STYLES["Medium"]["color"])):
            box = ctk.CTkFrame(counters, fg_color=COLOR_PANEL, corner_radius=12)
            box.pack(side="left", padx=(10, 0))
            value = ctk.CTkLabel(box, text="0", font=self.fonts["counter"],
                                 text_color=color, width=40)
            value.pack(side="left", padx=(16, 6), pady=8)
            ctk.CTkLabel(box, text=f"{name}\nalerts", font=self.fonts["small"],
                         text_color=COLOR_TEXT_MUTED, justify="left"
                         ).pack(side="left", padx=(0, 16), pady=8)
            self.counter_labels[name] = value

    def _build_status_bar(self):
        bar = ctk.CTkFrame(self, fg_color="transparent")
        bar.grid(row=2, column=0, sticky="ew", padx=26, pady=(0, 10))
        self.source_status = {}
        for source in self.alert_sources:
            label = ctk.CTkLabel(bar, text="", font=self.fonts["small"],
                                 text_color=COLOR_TEXT_MUTED, anchor="w")
            label.pack(side="left", padx=(0, 28))
            self.source_status[source["file"]] = label

    # ---------------------------------------------------------------- alerts
    def _records_to_alerts(self, source, records, fallback_ts):
        alerts = []
        for record, line_text in records:
            self._seq += 1
            alerts.append(build_alert(record, line_text, source, fallback_ts, self._seq))
        return alerts

    def load_initial_alerts(self):
        """Load the newest alerts from both files and show them, newest first."""
        collected = []
        for source in self.alert_sources:
            records = source["reader"].poll(MAX_DISPLAYED_ALERTS)
            # Alerts without a usable timestamp sort to the bottom on startup.
            collected.extend(self._records_to_alerts(source, records, 0.0))
        self._merge_alerts(collected, highlight=False)
        self.update_source_status()

    def poll_new_alerts(self):
        """Periodic job: read only newly appended lines from both files."""
        try:
            collected = []
            now = time.time()
            for source in self.alert_sources:
                records = source["reader"].poll(MAX_DISPLAYED_ALERTS)
                # Live alerts without a timestamp use the time they arrived.
                collected.extend(self._records_to_alerts(source, records, now))
            if collected:
                self._merge_alerts(collected, highlight=True)
            self.update_source_status()
            self.running_label.configure(
                text=f" Running  •  last checked {datetime.now():%H:%M:%S}")
        except Exception as exc:  # never let one bad refresh stop the loop
            print(f"[dashboard] alert refresh error: {exc!r}", file=sys.stderr)
        finally:
            self._jobs["alerts"] = self.after(ALERT_REFRESH_MS, self.poll_new_alerts)

    def _merge_alerts(self, new_alerts, highlight):
        known = {alert.key for alert in self.alerts}
        added = [alert for alert in new_alerts if alert.key not in known]
        if not added and self.alerts:
            return
        self.alerts.extend(added)
        self.alerts.sort(key=lambda a: (a.sort_ts, a.seq), reverse=True)
        del self.alerts[MAX_DISPLAYED_ALERTS:]
        new_keys = {alert.key for alert in added} if highlight else set()
        self.feed.show_alerts(self.alerts, new_keys)
        self.update_counters()

    def update_counters(self):
        counts = {"Total": len(self.alerts), "High": 0, "Medium": 0}
        for alert in self.alerts:
            if alert.severity in counts:
                counts[alert.severity] += 1
        for name, label in self.counter_labels.items():
            label.configure(text=str(counts[name]))

    def update_source_status(self):
        for source in self.alert_sources:
            level, text = source["reader"].status
            symbol = "●" if level == "ok" else "▲"
            self.source_status[source["file"]].configure(
                text=f"{symbol} {source['file']}: {text}",
                text_color=COLOR_TEXT_MUTED if level == "ok" else STATUS_COLORS[level])

    def open_alert_details(self, alert):
        AlertDetailWindow(self, alert, self.fonts)

    # --------------------------------------------------------------- traffic
    def refresh_traffic(self):
        """Periodic job: show the latest traffic_stats.json snapshot."""
        try:
            level, text = self.traffic_reader.read()
            self.traffic_panel.update_stats(self.traffic_reader.data, level, text)
        except Exception as exc:
            print(f"[dashboard] traffic refresh error: {exc!r}", file=sys.stderr)
        finally:
            self._jobs["traffic"] = self.after(TRAFFIC_REFRESH_MS, self.refresh_traffic)

    # ------------------------------------------------------------- shutdown
    def _on_close(self):
        for job in self._jobs.values():
            try:
                self.after_cancel(job)
            except ValueError:
                pass
        self.destroy()


def main():
    global DATA_DIR
    parser = argparse.ArgumentParser(description="Network Monitoring Dashboard")
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR,
                        help="folder containing network_alerts.jsonl, auth_alerts.jsonl "
                             "and traffic_stats.json (default: this script's folder)")
    args = parser.parse_args()
    DATA_DIR = args.data_dir.expanduser().resolve()

    app = Dashboard()
    app.mainloop()


if __name__ == "__main__":
    main()
