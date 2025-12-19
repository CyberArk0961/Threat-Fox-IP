#!/usr/bin/env python3
"""
ThreatFox IP:PORT IOC Crawler (POSITIONAL – FINAL)

Source:
https://threatfox.abuse.ch/export/csv/ip-port/recent/

IMPORTANT:
- This feed has NO HEADER ROW
- Rows are comma-separated
- Must be parsed positionally
"""

import requests
import csv
import os

# =====================
# CONFIG
# =====================
URL = "https://threatfox.abuse.ch/export/csv/ip-port/recent/"
OUTPUT_DIR = "output"
OUTPUT_FILE = "ThreatFox_IP_Port.csv"

HEADERS = {"User-Agent": "ThreatIntel-Crawler/1.0"}

FIELDNAMES = [
    "first_seen_utc",      # 0
    "ioc_id",              # 1
    "ioc_value",           # 2
    "ioc_type",            # 3
    "threat_type",         # 4
    "fk_malware",          # 5
    "malware_alias",       # 6
    "malware_printable",   # 7
    "last_seen_utc",       # 8
    "confidence_level",    # 9
    "reference",           # 10
    "tags",                # 11
    "anonymous",           # 12
    "reporter"             # 13
]

# =====================
# FETCH
# =====================
def fetch_csv():
    r = requests.get(URL, headers=HEADERS, timeout=60)
    r.raise_for_status()
    return r.text.lstrip("\ufeff")

# =====================
# PARSE (POSITIONAL)
# =====================
def parse_csv(raw):
    records = []
    seen_ids = set()

    reader = csv.reader(
        (line for line in raw.splitlines() if line and not line.startswith("#")),
        delimiter=",",
        quotechar='"'
    )

    for row in reader:
        if len(row) < 14:
            continue

        ioc_id = row[1].strip()
        if not ioc_id or ioc_id in seen_ids:
            continue
        seen_ids.add(ioc_id)

        record = dict(zip(FIELDNAMES, [c.strip() for c in row[:14]]))
        records.append(record)

    return records

# =====================
# SAVE
# =====================
def save_csv(data):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    path = os.path.join(OUTPUT_DIR, OUTPUT_FILE)

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=FIELDNAMES,
            quoting=csv.QUOTE_ALL
        )
        writer.writeheader()
        writer.writerows(data)

    print(f"[+] Saved {len(data)} records → {path}")

# =====================
# MAIN
# =====================
def main():
    print("[*] Fetching ThreatFox IP:PORT feed...")
    raw = fetch_csv()

    print("[*] Parsing CSV (positional)...")
    data = parse_csv(raw)

    if not data:
        raise RuntimeError("Parsed ZERO records – unexpected feed change")

    print("[*] Writing output...")
    save_csv(data)

if __name__ == "__main__":
    main()
