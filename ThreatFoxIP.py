#!/usr/bin/env python3
"""
ThreatFox IP:PORT IOC Crawler (RAW SCHEMA – FINAL)

Source:
https://threatfox.abuse.ch/export/csv/ip-port/recent/

- Preserves original ThreatFox column names
- Handles semicolon-delimited CSV
- Handles BOM and comment lines (#)
- Deduplicates on ioc_id
- Produces Defender/SIEM-ready CSV
"""

import requests
import csv
import os

# =====================
# CONFIG
# =====================
THREATFOX_CSV_URL = "https://threatfox.abuse.ch/export/csv/ip-port/recent/"
OUTPUT_DIR = "output"
OUTPUT_FILE = "ThreatFox_IP_Port.csv"

HEADERS = {
    "User-Agent": "ThreatIntel-Crawler/1.0"
}

FIELDNAMES = [
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

# =====================
# FETCH CSV
# =====================
def fetch_threatfox_csv():
    response = requests.get(THREATFOX_CSV_URL, headers=HEADERS, timeout=60)
    response.raise_for_status()
    return response.text

# =====================
# PARSE CSV (ROBUST)
# =====================
def parse_csv(raw_csv):
    records = []
    seen_ids = set()

    # Remove BOM if present
    raw_csv = raw_csv.lstrip("\ufeff")

    lines = []
    for line in raw_csv.splitlines():
        if not line:
            continue
        if line.startswith("#"):
            continue
        lines.append(line)

    if not lines:
        return records

    reader = csv.DictReader(lines, delimiter=";")

    for row in reader:
        ioc_id = row.get("ioc_id")
        if not ioc_id:
            continue

        ioc_id = ioc_id.strip()
        if ioc_id in seen_ids:
            continue
        seen_ids.add(ioc_id)

        record = {field: row.get(field, "").strip() for field in FIELDNAMES}
        records.append(record)

    return records

# =====================
# SAVE CSV
# =====================
def save_csv(data):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, OUTPUT_FILE)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=FIELDNAMES,
            quoting=csv.QUOTE_ALL
        )
        writer.writeheader()
        writer.writerows(data)

    print(f"[+] Saved {len(data)} ThreatFox IP:PORT IOCs → {output_path}")

# =====================
# MAIN
# =====================
def main():
    print("[*] Fetching ThreatFox IP:PORT IOCs...")
    raw_csv = fetch_threatfox_csv()

    print("[*] Parsing CSV...")
    data = parse_csv(raw_csv)

    print("[*] Writing output CSV...")
    save_csv(data)

if __name__ == "__main__":
    main()
