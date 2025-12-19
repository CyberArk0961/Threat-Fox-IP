#!/usr/bin/env python3
"""
ThreatFox IP:PORT IOC Crawler (RAW SCHEMA)

Source:
https://threatfox.abuse.ch/export/csv/ip-port/recent/

- Fetches recent IP:PORT IOCs
- Preserves ThreatFox original schema
- Removes comment lines (#)
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
# PARSE CSV (RAW)
# =====================
def parse_csv(raw_csv):
    records = []
    seen_ids = set()

    reader = csv.DictReader(
        line for line in raw_csv.splitlines()
        if line and not line.startswith("#")
    )

    for row in reader:
        ioc_id = row.get("ioc_id", "").strip()
        if not ioc_id:
            continue

        # Deduplicate on IOC ID
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
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(data)

    print(f"[+] Saved {len(data)} ThreatFox IP:PORT IOCs → {output_path}")

# =====================
# MAIN
# =====================
def main():
    print("[*] Fetching ThreatFox IP:PORT IOCs...")
    raw_csv = fetch_threatfox_csv()

    print("[*] Parsing CSV (preserving raw schema)...")
    data = parse_csv(raw_csv)

    print("[*] Writing output CSV...")
    save_csv(data)

if __name__ == "__main__":
    main()
