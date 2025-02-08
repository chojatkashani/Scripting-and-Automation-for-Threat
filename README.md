

# Scripting and Automation for Threat Mitigation

## Project Overview
This project focuses on automating threat detection and response using Python scripts and security tools such as Suricata, Snort, and Google Chronicle. The goal is to automatically identify, log, and mitigate security threats in real time, reducing manual intervention and response time.

## Objectives
- Develop automation scripts for log analysis and threat detection
- Implement automatic mitigation actions (e.g., firewall rule updates, IP blocking)
- Integrate security alerts with a SIEM for real-time monitoring
- Deploy the script as a scheduled task for continuous protection

## Setup

### Prerequisites
- Python 3.x installed on a Linux-based system
- Security tools such as Suricata, Snort, or Google Chronicle configured
- API access to a firewall (e.g., iptables, pfSense, AWS Security Groups)
- SIEM platform (e.g., Splunk, Elastic Security, Chronicle) for alerting

### Installing Required Python Libraries
```bash
pip install requests pandas logging croniter
```

## Implementation

### Automating Threat Detection and Mitigation
The following Python script monitors logs for malicious activity and blocks the attacking IPs dynamically.

```python
import os
import json
import requests
import subprocess
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(filename="threat_mitigation.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Define log file path
SURICATA_LOG = "/var/log/suricata/eve.json"
BLOCKED_IPS = set()

# Function to parse logs and extract suspicious IPs
def parse_logs():
    try:
        with open(SURICATA_LOG, 'r') as log_file:
            for line in log_file.readlines():
                event = json.loads(line)
                if 'alert' in event and 'src_ip' in event:
                    ip = event['src_ip']
                    if ip not in BLOCKED_IPS:
                        block_ip(ip)
    except Exception as e:
        logging.error(f"Error reading log file: {e}")

# Function to block IPs dynamically using iptables
def block_ip(ip):
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        BLOCKED_IPS.add(ip)
        logging.info(f"Blocked IP: {ip}")
    except Exception as e:
        logging.error(f"Failed to block IP {ip}: {e}")

# Run log parsing
if __name__ == "__main__":
    parse_logs()
```

### Scheduling Automation with Cron
To ensure continuous threat monitoring, add the script as a scheduled cron job:
```bash
crontab -e
```
Add the following line to run the script every minute:
```bash
* * * * * /usr/bin/python3 /path/to/threat_mitigation.py
```

### Integrating with SIEM for Alerting
To send blocked IPs to a SIEM:
```python
def send_to_siem(ip):
    siem_url = "https://siem-instance/api/logs"
    payload = {"timestamp": datetime.utcnow().isoformat(), "blocked_ip": ip}
    headers = {"Authorization": "Bearer YOUR_SIEM_API_KEY"}
    requests.post(siem_url, json=payload, headers=headers)
    logging.info(f"Sent IP {ip} to SIEM")
```


This project successfully automates threat detection and response by analyzing logs, identifying malicious activity, and mitigating threats through automated IP blocking. Future improvements include integrating with a SOAR platform for full automation and implementing machine learning-based anomaly detection.
