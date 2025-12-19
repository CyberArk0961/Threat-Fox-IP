#!/usr/bin/env python3
"""
ThreatFox IP:PORT IOC Crawler (AUTO-DETECT SCHEMA)

- Handles semicolon-delimited CSV
- Handles comments, BOM, quoted headers
- Dynamically maps ThreatFox columns
- Never outputs empty silently
"""

import requests
import csv
import os
import sys

THREATFOX_CSV_URL = "https://threatfox.abuse.ch/export/csv/ip-port/recent/"
OUTPUT_DIR = "output"
OUTPUT_FILE = "ThreatFox_IP_Port.csv"

HEADERS = {"User-Agent": "ThreatIntel-Crawler/1.0"}

EXPECTED_FIELDS = [
    "first_seen_utc",
    "ioc_id",
    "ioc_value",
    "ioc_type",
    "threat_type",
    "fk_malware",
    "malware_alias",
    "malware_printable",
    "last_seen_utc",
    "confidence_level",
    "reference",
    "tags",
    "anonymous",
    "reporter"
]

def fetch_csv():
    r = requests.get(THREATFOX_CSV_URL, headers=HEADERS, timeout=60)
    r.raise_for_status()
    return r.text.lstrip("\ufeff")

def parse_csv(raw_csv):
    lines = [
        l for l in raw_csv.splitlines()
        if l and not l.startswith("#")
    ]

    if not lines:
        print("[!] No CSV content after filtering")
        sys.exit(1)

    reader = csv.DictReader(lines, delimiter=";")

    print("[*] Detected ThreatFox columns:")
    print(reader.fieldnames)

    records = []
    seen = set()

    for row in reader:
        # Dynamically detect IOC ID field
        ioc_id = (
            row.get("ioc_id") or
            row.get("id") or
            row.get("iocid")
        )

        if not ioc_id:
            continue

        ioc_id = ioc_id.strip()
        if ioc_id in seen:
            continue
        seen.add(ioc_id)

        record = {}
        for field in EXPECTED_FIELDS:
            record[field] = row.get(field, "").strip()

        records.append(record)

    return records

def save_csv(data):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    path = os.path.join(OUTPUT_DIR, OUTPUT_FILE)

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=EXPECTED_FIELDS,
            quoting=csv.QUOTE_ALL
        )
        writer.writeheader()
        writer.writerows(data)

    print(f"[+] Saved {len(data)} records → {path}")

def main():
    print("[*] Fetching ThreatFox IP:PORT feed...")
    raw = fetch_csv()

    print("[*] Parsing CSV...")
    data = parse_csv(raw)

    if not data:
        print("[!] Parsed ZERO records — check printed headers above")
        sys.exit(1)

    print("[*] Writing output...")
    save_csv(data)

if __name__ == "__main__":
    main()
