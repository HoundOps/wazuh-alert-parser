🔍 Wazuh Alert Parser & Exporter

A lightweight Python script that parses alerts.json files from a Wazuh server, filters by specific rule IDs, maps MITRE techniques, and exports selected alert data to both JSON and CSV.

Designed for SOC analysts, blue teamers, or cybersecurity learners who want clearer, cleaner access to relevant alert data.

⚙️ Features

✅ Rule ID filtering (customizable via CLI)
✅ MITRE ATT&CK technique mapping
✅ Source IP, process, and parent process extraction
✅ Terminal-friendly colored output
✅ Clean logging to alert_parser.log
✅ Export to JSON and CSV
✅ Optional command-line arguments
🚀 How to Use

Requirements
Python 3.7+
No external packages required (only standard library)
Example Usage python alert_parser.py This runs the script with default settings: Input file: /var/ossec/logs/alerts/alerts.json Output files: alerts_output.json and alerts_output.csv Rule IDs filtered: 60107, 60106, 61601, 61603, 67027, 530, 533, 18107

Custom Options python alert_parser.py
--logpath test_alerts.json
--jsonout output.json
--csvout output.csv
--rules 60107 61601

CLI Arguments Option Description Example --logpath Path to the alerts.json file /var/ossec/logs/alerts/alerts.json --jsonout Path to save the parsed JSON output alerts_output.json --csvout Path to save the parsed CSV output alerts_output.csv --rules Space-separated rule IDs to filter 60107 61601 533

📂 Output Colored terminal output: Only for matched rule alerts Log file: alert_parser.log Exports: alerts_output.json: Full filtered alerts alerts_output.csv: Tabular alert summary

🧠 MITRE Mapping Some alerts include rule.mitre.id, which is mapped to friendly descriptions like: MITRE ID Description T1059.001 PowerShell T1047 WMI T1021.001 Remote Desktop Protocol (RDP) You can expand the built-in mapping dictionary in the script if needed.

🧪 Testing To test the parser with sample data: Create a file named test_alerts.json Add valid Wazuh JSON entries (one per line) Run: python alert_parser.py --logpath test_alerts.json

✅ Example Output [2025-06-16T10:00:00Z] Rule 60107 – Unauthorized PowerShell usage Source IP: 192.168.1.100 Process: powershell.exe | Parent: cmd.exe MITRE Technique: PowerShell

🛠 Author Notes This script was built as a real-world SOC side project to demonstrate Python scripting, log analysis, and detection tuning.

📜 License MIT — free to use, modify, and adapt.
