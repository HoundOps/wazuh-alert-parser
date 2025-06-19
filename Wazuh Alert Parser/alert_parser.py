import json
import csv
import logging
import argparse
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter, defaultdict

def parse_args():
    parser = argparse.ArgumentParser(
        description="Parse and export Wazuh alerts based on filtered rules."
    )

    parser.add_argument(
        "--logpath",
        type=str,
        help="Path to Wazuh alerts.json file. Default: /var/ossec/logs/alerts/alerts.json"
    )

    parser.add_argument(
        "--jsonout", 
        type=str,
        help="Path to export filtered alerts as JSON. Default: alerts_output.json"
    )

    parser.add_argument(
        "--csvout", 
        type=str,
        help="Path to export filtered alerts as CSV. Default: alerts_output.csv"
    )

    parser.add_argument(
        "--rules", 
        nargs="+", 
        help="List of rule IDs to filter for (space-separated). Overrides default rules."
    )

    return parser.parse_args()

# === Fallback-friendly field extractor ===
def extract_field(data, keys):
    for key in keys:
        value = data
        for part in key.split("."):
            value = value.get(part) if isinstance(value, dict) else None
            if value is None:
                break
        if value is not None:
            return value
    return "N/A"
    
if __name__ == "__main__":
    # === File paths ===
    parse_time = datetime.now()
    parse_iso = parse_time.strftime("%Y-%m-%d_%H-%M-%S") # for filenames

    args = parse_args()
    log_path    = args.logpath or "/var/ossec/logs/alerts/alerts.json"
    json_output = args.jsonout or f"alerts_output_{parse_iso}.json"
    csv_output  = args.csvout  or f"alerts_output_{parse_iso}.csv"

    # summary filename now includes timestamp
    summary_file = f"summary_report_{parse_iso}.txt"
    

    # === Rule filtering ===
    FILTER_RULES = set(args.rules) if args.rules else {
        "60107", "60106", "61601", "61603", "67027", "530", "533", "18107"
    }

    # === MITRE mapping dictionary (expandable) ===
    mitre_mapping = {
        "T1059.001": "PowerShell",
        "T1047": "WMI",
        "T1021.001": "Remote Desktop Protocol (RDP)"
    }

    # === Configure Logging ===
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        
        handlers=[
            logging.FileHandler("alert_parser.log"),
            logging.StreamHandler()
        ]
    )

    # === Read, parse, and filter logs ===
    alerts = []
    with open(log_path, "r") as f:
        for line in f:
            try:
                alert = json.loads(line.strip())

                rule_id = extract_field(alert, ["rule.id"])
                if rule_id not in FILTER_RULES:
                    continue  # Skip alerts outside the target list

                timestamp = extract_field(alert, ["timestamp"])
                description = extract_field(alert, ["rule.description"])
                src_ip = extract_field(alert, ["data.srcip", "data.src_ip", "agent.ip"])
                process = extract_field(alert, ["data.win.eventdata.image", "data.win.system.process.name"])
                parent = extract_field(alert, ["data.win.eventdata.parentImage", "data.win.system.parent_process.name"])
                mitre_ids = extract_field(alert, ["rule.mitre.id"])
                mitre_desc = mitre_mapping.get(mitre_ids, mitre_ids)

                # Print to console
                # Print with color to terminal
                print(f"[{timestamp}] \033[93mRule {rule_id} – {description}\033[0m")

                # Log cleanly without ANSI codes
                logging.info(f"[{timestamp}] Rule {rule_id} – {description}")
                logging.info(f"   Source IP: {src_ip}")
                logging.info(f"   Process: {process} | Parent: {parent}")
                logging.info(f"   MITRE Technique: {mitre_desc}")
                logging.info("-" * 60)

                # Store for export
                alerts.append({
                    "timestamp": timestamp,
                    "rule_id": rule_id,
                    "description": description,
                    "source_ip": src_ip,
                    "process": process,
                    "parent_process": parent,
                    "mitre": mitre_desc
                })

            except json.JSONDecodeError:
                continue  # Skip malformed lines

     # Quick automated rule validation (you already have this)
    logging.info("\n=== Rule Validation Summary ===")
    matched_rules = set()
    with open(log_path, "r") as f_validate:
        for line in f_validate:
            try:
                alert_obj = json.loads(line.strip())
                rid = alert_obj.get("rule", {}).get("id", "")
                if str(rid) in FILTER_RULES:
                    matched_rules.add(str(rid))
            except json.JSONDecodeError:
                continue

    # === Build counters with descriptions ===
    rule_counter = defaultdict(lambda: {"description": "", "count": 0})
    mitre_counter = Counter(a["mitre"] for a in alerts)

    for a in alerts:
        rid = a["rule_id"]
        rule_counter[rid]["description"] = a["description"]
        rule_counter[rid]["count"] += 1

    # === Log the breakdown by Rule ID ===
    logging.info("\n=== Alert Rule Frequency Summary ===")
    for rid, info in sorted(rule_counter.items(), key=lambda x: int(x[0])):
        logging.info(f" Rule {rid} – {info['description']} ({info['count']} alerts)")

    # === MITRE Technique Summary ===
    logging.info("\n=== MITRE Technique Summary ===")
    for mitre, count in mitre_counter.items():
        logging.info(f" {mitre}: {count} alerts")

    # === Write summary to report file ===
    with open(summary_file, "w") as report:
        report.write(f"Parse Time: {parse_time.isoformat()}\n")
        report.write(f"Total Alerts Processed: {len(alerts)}\n\n")

        report.write("=== Alert Rule Frequency Summary ===\n")
        for rid, info in sorted(rule_counter.items(), key=lambda x: int(x[0])):
            report.write(f"Rule {rid} – {info['description']} ({info['count']} alerts)\n")

        report.write("\n=== MITRE Technique Summary ===\n")
        for mitre, count in mitre_counter.items():
            report.write(f"{mitre}: {count} alerts\n")

    logging.info(f"Wrote {summary_file}")

    # === Export to JSON ===
    if alerts:
        with open(json_output, "w", encoding="utf-8") as json_file:
            json.dump({
                "parse_time": parse_time.isoformat(),
                "total_alerts": len(alerts),
                "filtered_rules": list(FILTER_RULES),
                "alerts": alerts
            }, json_file, indent=2)
    else:
        logging.info("No matching alerts to export to JSON.")

    # === Export to CSV ===
    if alerts:
        # extend fieldnames with parse_time
        fieldnames = list(alerts[0].keys()) + ["parse_time"]
        with open(csv_output, "w", newline='', encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            for a in alerts:
                a["parse_time"] = parse_time.isoformat()
                writer.writerow(a)
    else:
        logging.info("No matching alerts to export.")

    logging.info(f"\n Exported {len(alerts)} alerts to {json_output} and {csv_output}")
