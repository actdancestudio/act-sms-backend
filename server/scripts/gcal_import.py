#!/usr/bin/env python3
"""
gcal_import.py — ACT Lighthouse CRM: Google Calendar → Google Sheets sync
==========================================================================
Usage:
    python3 gcal_import.py <mcp_result_json_path>

Reads the MCP JSON output from google_calendar_search_events, reconciles
each event with the corresponding Events-MXX sheet tab in the CRM Google
Sheets spreadsheet, and logs import/update/skip/cancel counts.

The script writes a sync timestamp to the Audit sheet (column E) after a
successful run, serving as the sync_config.last_google_pull record.

Sheet column mapping (Events-MXX, columns A–X):
  A  Date            (YYYY-MM-DD)
  B  Name            (left blank; populated by sheet formula from col P)
  C  Teacher         (extracted from event summary or left blank)
  D  Start Time      (HH:MM)
  E  End Time        (HH:MM)
  F  Manual Title    (event summary)
  G  Location
  H  Notes           (event description, stripped of HTML)
  I  Type            (blank — not determinable from GCal alone)
  J–O               (blank — sheet formula columns)
  P  Tracking Number (blank — not in GCal event)
  Q–R               (blank — parsed by sheet)
  S  Program+Count   (blank)
  T–W               (blank)
  X  Program Code    (blank)

Reconciliation key: (sheet_tab, date_ymd, start_time, title)
  - If a matching row already exists → skip (no overwrite of manual data)
  - If the event is cancelled → mark as CANCELLED in Notes column
  - If no match → append as new row
"""

import json
import sys
import os
import re
import logging
from datetime import datetime, timezone
from html.parser import HTMLParser

# ── Logging setup ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("gcal_import")

# ── Config ───────────────────────────────────────────────────────────────────
BACKEND_URL = os.environ.get("ACT_BACKEND_URL", "https://act-sms-backend.onrender.com")
SPREADSHEET_ID = "1CMBs9PeR91ClApZ8nvmxhB7HqiFznX0AAH2IfonIjLo"

# Month 1 = September 2025 (matches server.mjs SHEETS_MONTH1)
MONTH1 = datetime(2025, 9, 1, tzinfo=timezone.utc)
TOTAL_MONTHS = 24

# Columns that are purely sheet-formula driven — we leave them blank on import
FORMULA_COLS = ["", "", "", "", "", ""]  # J..O (indices 9–14)

# ── HTML stripper ─────────────────────────────────────────────────────────────
class _HTMLStripper(HTMLParser):
    def __init__(self):
        super().__init__()
        self._parts = []

    def handle_data(self, data):
        self._parts.append(data)

    def get_text(self):
        return " ".join(self._parts).strip()


def strip_html(raw: str) -> str:
    if not raw:
        return ""
    s = _HTMLStripper()
    s.feed(raw)
    return s.get_text()


# ── Helpers ───────────────────────────────────────────────────────────────────
def month_tab_for(dt: datetime) -> str | None:
    """Return the Events-MXX tab name for a given datetime, or None if out of range."""
    offset = (dt.year - MONTH1.year) * 12 + (dt.month - MONTH1.month)
    m = offset + 1
    if m < 1 or m > TOTAL_MONTHS:
        return None
    return f"Events-M{str(m).zfill(2)}"


def parse_event_dt(event: dict) -> tuple[datetime | None, bool]:
    """
    Returns (datetime_utc_or_local, is_all_day).
    For all-day events the datetime has no time component (midnight UTC).
    """
    start = event.get("start", {})
    if "dateTime" in start:
        raw = start["dateTime"]
        # Parse ISO 8601 with offset
        dt = datetime.fromisoformat(raw)
        return dt, False
    elif "date" in start:
        raw = start["date"]  # YYYY-MM-DD
        dt = datetime.strptime(raw, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return dt, True
    return None, False


def parse_event_end_dt(event: dict) -> datetime | None:
    end = event.get("end", {})
    if "dateTime" in end:
        return datetime.fromisoformat(end["dateTime"])
    elif "date" in end:
        return datetime.strptime(end["date"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return None


def ymd(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d")


def hm(dt: datetime) -> str:
    return dt.strftime("%H:%M")


def read_sheet_rows(tab: str) -> list[list[str]]:
    """Read all data rows (row 2 onward) from a sheet tab via the backend API."""
    import urllib.request, urllib.parse
    range_param = urllib.parse.quote(f"{tab}!A2:X200")
    url = f"{BACKEND_URL}/api/sheets/read?range={range_param}"
    try:
        with urllib.request.urlopen(url, timeout=20) as resp:
            data = json.loads(resp.read())
        return data.get("values", [])
    except Exception as exc:
        log.warning("Could not read sheet %s: %s", tab, exc)
        return []


def append_sheet_row(tab: str, row: list) -> bool:
    """Append a single row to the given sheet tab via the backend API."""
    import urllib.request
    payload = json.dumps({
        "range": f"{tab}!A2:X2",
        "values": [row],
    }).encode()
    url = f"{BACKEND_URL}/api/sheets/append"
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            result = json.loads(resp.read())
        return result.get("ok", False)
    except Exception as exc:
        log.error("Failed to append row to %s: %s", tab, exc)
        return False


def write_last_pull_timestamp(ts: str) -> None:
    """
    Record the last successful pull timestamp in the Audit sheet (cell E1).
    This serves as sync_config.last_google_pull.
    """
    import urllib.request
    payload = json.dumps({
        "range": "Audit!E1:E1",
        "values": [[f"last_google_pull: {ts}"]],
    }).encode()
    url = f"{BACKEND_URL}/api/sheets/append"
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            pass
        log.info("sync_config.last_google_pull updated → %s", ts)
    except Exception as exc:
        log.warning("Could not write last_google_pull timestamp: %s", exc)


def build_row(event: dict, dt_start: datetime, dt_end: datetime | None, is_all_day: bool) -> list:
    """
    Build a 24-column row (A–X) for the Events-MXX sheet from a GCal event.
    """
    summary = event.get("summary", "").strip()
    location = event.get("location", "") or ""
    description = strip_html(event.get("description", "") or "")
    status = event.get("status", "confirmed")

    notes = description
    if status == "cancelled":
        notes = f"[CANCELLED] {notes}".strip()

    date_str = ymd(dt_start)
    start_time = "" if is_all_day else hm(dt_start)
    end_time = "" if is_all_day or dt_end is None else hm(dt_end)

    # 24 columns: A(0)..X(23)
    row = [
        date_str,    # A  Date
        "",          # B  Name (sheet formula)
        "",          # C  Teacher
        start_time,  # D  Start Time
        end_time,    # E  End Time
        summary,     # F  Manual Title (Override)
        location,    # G  Location
        notes,       # H  Notes
        "",          # I  Type
        "",          # J  Hours (formula)
        "",          # K  Back Department Lesson (formula)
        "",          # L  Ren/Ext Lessons (formula)
        "",          # M  Front Department Lesson (formula)
        "",          # N  TO Next Month (formula)
        "",          # O  Original/Extension/Renewal/No Sale (formula)
        "",          # P  Tracking Number
        "",          # Q  Program (parsed)
        "",          # R  Lesson Count (parsed)
        "",          # S  Program + Count (source)
        "",          # T  Title (Auto)
        "",          # U  Stage/Flow
        "",          # V  Payment
        "",          # W  Remaining
        "",          # X  Program Code
    ]
    return row


def make_key(row: list) -> tuple:
    """Derive a reconciliation key from an existing sheet row: (date, start_time, title)."""
    date = (row[0] if len(row) > 0 else "").strip()
    start = (row[3] if len(row) > 3 else "").strip()
    title = (row[5] if len(row) > 5 else "").strip()  # col F = Manual Title
    return (date, start, title)


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    if len(sys.argv) < 2:
        log.error("Usage: gcal_import.py <mcp_result_json_path>")
        sys.exit(1)

    result_path = sys.argv[1]
    if not os.path.exists(result_path):
        log.error("Result file not found: %s", result_path)
        sys.exit(1)

    with open(result_path, "r", encoding="utf-8") as f:
        mcp_data = json.load(f)

    if not mcp_data.get("success"):
        log.error("MCP result indicates failure: %s", mcp_data)
        sys.exit(1)

    events = mcp_data.get("result", [])
    log.info("Loaded %d events from MCP result: %s", len(events), result_path)

    # Counters
    imported = 0
    updated = 0   # reserved for future update logic
    cancelled = 0
    skipped = 0
    errors = 0

    # Cache of already-read sheet rows, keyed by tab name
    sheet_cache: dict[str, set[tuple]] = {}

    for event in events:
        event_id = event.get("id", "?")
        summary = event.get("summary", "(no title)")
        status = event.get("status", "confirmed")

        dt_start, is_all_day = parse_event_dt(event)
        if dt_start is None:
            log.warning("Skipping event with no start time: %s (%s)", summary, event_id)
            skipped += 1
            continue

        tab = month_tab_for(dt_start)
        if tab is None:
            log.info("Skipping out-of-range event: %s (%s) on %s", summary, event_id, ymd(dt_start))
            skipped += 1
            continue

        dt_end = parse_event_end_dt(event)

        # Build the row and its reconciliation key
        row = build_row(event, dt_start, dt_end, is_all_day)
        key = make_key(row)

        # Load existing rows for this tab (cached)
        if tab not in sheet_cache:
            existing_rows = read_sheet_rows(tab)
            sheet_cache[tab] = {make_key(r) for r in existing_rows if r}
            log.debug("Loaded %d existing rows from %s", len(sheet_cache[tab]), tab)

        if key in sheet_cache[tab]:
            log.debug("SKIP (already exists): [%s] %s @ %s", tab, summary, key[0])
            if status == "cancelled":
                cancelled += 1
            else:
                skipped += 1
            continue

        # Append new row
        ok = append_sheet_row(tab, row)
        if ok:
            sheet_cache[tab].add(key)
            if status == "cancelled":
                log.info("CANCELLED → appended: [%s] %s @ %s", tab, summary, key[0])
                cancelled += 1
            else:
                log.info("IMPORTED: [%s] %s @ %s %s", tab, summary, key[0], key[1])
                imported += 1
        else:
            log.error("FAILED to append: [%s] %s @ %s", tab, summary, key[0])
            errors += 1

    # Write last_google_pull timestamp
    now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    write_last_pull_timestamp(now_ts)

    # Summary
    log.info(
        "Sync complete — imported: %d | updated: %d | cancelled: %d | skipped: %d | errors: %d",
        imported, updated, cancelled, skipped, errors,
    )

    return {
        "imported": imported,
        "updated": updated,
        "cancelled": cancelled,
        "skipped": skipped,
        "errors": errors,
    }


if __name__ == "__main__":
    main()
