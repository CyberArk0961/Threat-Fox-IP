#!/usr/bin/env python3
"""
ThreatFox IP:PORT IOC Crawler (CSV)

Source:
https://threatfox.abuse.ch/export/csv/ip-port/recent/

- Fetches recent IP:PORT IOCs
- Handles ThreatFox CSV comments
- Produces stable CSV output for automation
"""

import requests
import csv
import os
from datetime import datetime

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
    "ip",
    "port",
    "ioc",
    "ioc_type",
    "threat_type",
    "malware",
    "confidence_level",
    "reference",
    "first_seen",
    "last_seen",
    "source",
    "collection_date"
]

# =====================
# FETCH CSV
# =====================
def fetch_threatfox_csv():
    response = requests.get(THREATFOX_CSV_URL, headers=HEADERS, timeout=60)
    response.raise_for_status()
    return response.text

# =====================
# PARSE CSV
# =====================
def parse_csv(raw_csv):
    records = []
    seen_iocs = set()
    collection_time = datetime.utcnow().isoformat()

    reader = csv.reader(
        line for line in raw_csv.splitlines()
        if line and not line.startswith("#")
    )

    header = next(reader, None)
    if not header:
        return records

    for row in reader:
        # Expected format:
        # ip,port,ioc_type,threat_type,malware,confidence_level,reference,first_seen,last_seen
        if len(row) < 9:
            continue

        ip = row[0].strip()
        port = row[1].strip()
        ioc = f"{ip}:{port}"

        if not ip or not port:
            continue

        if ioc in seen_iocs:
            continue
        seen_iocs.add(ioc)

        records.append({
            "ip": ip,
            "port": port,
            "ioc": ioc,
            "ioc_type": row[2].strip(),
            "threat_type": row[3].strip(),
            "malware": row[4].strip(),
            "confidence_level": row[5].strip(),
            "reference": row[6].strip(),
            "first_seen": row[7].strip(),
            "last_seen": row[8].strip(),
            "source": "ThreatFox",
            "collection_date": collection_time
        })

    return records

# =====================
# SAVE CSV (ALWAYS)
# =====================
def save_csv(data):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, OUTPUT_FILE)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(data)

    print(f"[+] Saved {len(data)} IP:PORT IOCs → {output_path}")

# =====================
# MAIN
# =====================
def main():
    print("[*] Fetching ThreatFox IP:PORT IOCs (CSV)...")
    raw_csv = fetch_threatfox_csv()

    print("[*] Parsing IP:PORT IOCs...")
    iocs = parse_csv(raw_csv)

    print("[*] Writing output...")
    save_csv(iocs)

if __name__ == "__main__":
    main()
