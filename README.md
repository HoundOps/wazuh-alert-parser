🔍 Wazuh Alert Parser & Exporter

# Wazuh Alert Parser & Exporter


A lightweight Python tool for SOC analysts to parse Wazuh’s  
`alerts.json`, filter by rule ID, enrich with MITRE ATT&CK mapping,  
and export clean, shareable data in JSON, CSV, and text-summary formats.

---

## Why I Built This
Manual alert review in Wazuh is slow when you're dealing with high-volume logs. This tool cuts triage time by filtering noise, mapping MITRE techniques automatically, and exporting clean data an analyst can actually work with.

---

### 🚀 Features

- **Rule ID filtering** (configurable via CLI)  
- **MITRE technique mapping** → human-readable names  
- **Source IP**, **Process** & **Parent Process** extraction  
- **Timestamped** export filenames for traceability  
- **CLI** + **ANSI-colored** terminal output  
- **Clean logging** to `alert_parser.log`  
- **Exports**:  
  - JSON (`alerts_output_<stamp>.json`)  
  - CSV (`alerts_output_<stamp>.csv`)  
  - Text summary (`summary_report_<stamp>.txt`)

---

🚀 How to Use
1. Requirements

- Python 3.7+
- No external packages required (only standard library)

2. Example Usage
python alert_parser.py [--logpath PATH] [--jsonout FILE] [--csvout FILE] [--rules ID [ID...]]

Examples
Default run (reads /var/ossec/logs/alerts/alerts.json):

python alert_parser.py
Custom inputs & outputs:

python alert_parser.py \
  --logpath ./test_alerts.json \
  --jsonout report.json \
  --csvout report.csv \
  --rules 60107 61601 530

🛠️ CLI Options
Flag	Description	Default
--logpath	| Path to the Wazuh alerts.json file |	/var/ossec/logs/alerts/alerts.json
--jsonout	| Output JSON filename (includes timestamp) |	alerts_output_<YYYYMMDD_HHMMSS>.json
--csvout	| Output CSV filename (includes timestamp) | alerts_output_<YYYYMMDD_HHMMSS>.csv
--rules	| Space-separated list of rule IDs to include; overrides default filter set |	60107 60106 61601 61603 67027 530 533 18107

📂 Output Files
alerts_output_<stamp>.json

alerts_output_<stamp>.csv
Columns: timestamp,rule_id,description,source_ip,process,parent_process,mitre,parse_time

summary_report_<stamp>.txt

text
Copy
Edit
Parse Time: 2025-06-19T14:30:09-04:00
Total Alerts Processed: 1234

=== Alert Rule Frequency Summary ===
Rule 60107 – Unauthorized PowerShell usage (432 alerts)
Rule 61601 – WMI Execution (310 alerts)
…

=== MITRE Technique Summary ===
PowerShell: 432 alerts
WMI:        310 alerts

🧠 MITRE Mapping
Some alerts include rule.mitre.id, which is mapped to friendly descriptions like:
MITRE ID
Description
T1059.001
PowerShell
T1047
WMI
T1021.001
Remote Desktop Protocol (RDP)
You can expand the built-in mapping dictionary in the script if needed.

🧪 Testing
To test the parser with sample data:
Create a file named test_alerts.json
Add valid Wazuh JSON entries (one per line)
Run: python alert_parser.py --logpath test_alerts.json

✅ Example Output
[2025-06-16T10:00:00Z] Rule 60107 – Unauthorized PowerShell usage
   Source IP: 192.168.1.100
   Process: powershell.exe | Parent: cmd.exe
   MITRE Technique: PowerShell

🛠 Author Notes
Built to solve a real triage problem, parsing and normalizing 10,000+ Wazuh alerts in under 5 seconds to reduce manual analyst review time.

📜 License
MIT — free to use, modify, and adapt.


