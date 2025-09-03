# Blue-wix
Intrusion Detection System (IDS) in Python with CLI and PyQt GUI: real-time packet capture, signature and anomaly detection, web attack patterns (SQLi/XSS/LFI), logging, and optional email/WhatsApp alerts.


# Intrusion Detection System (IDS)
Real-time Python IDS with CLI and PyQt GUI. Captures packets (Scapy), detects attacks (signature + anomaly), flags web patterns (SQLi/XSS/LFI), logs events, and supports email/WhatsApp alerts.


## Screenshots
- GUI Dashboard & Alerts (add images in repo and reference here)
- Example: `![Dashboard](docs/dashboard.png)` `![Alerts](docs/alerts.png)`

## Features
- Packet capture (Scapy) with live analysis
- Signature detection: port-scan, SYN flood, suspicious ports, large packets
- Anomaly detection: size deviation
- Web attack patterns: SQLi, XSS, path traversal/LFI/RFI, command injection
- PyQt GUI (dark theme) and CLI tool
- Logging (`ids.log`) and optional email/WhatsApp alerts

## Quick Start
```bash
# Install deps (Kali/Ubuntu)
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-pyqt5 python3-scapy
pip3 install -r requirements.txt   # optional: pip install twilio

# CLI (loopback for localhost tests)
sudo ./blue-wix start --stats -i lo

# GUI
sudo python3 ids_gui.py
```

## Usage (CLI)
```bash
./blue-wix -h
./blue-wix start -i eth0 --stats
./blue-wix config
./blue-wix test
./blue-wix logs -n 50
./blue-wix notify-test -s HIGH
```

## Web Attack Detection
Inspected on ports 80/8080/8000/443; detects:
- SQLI: `union`, `select`, `'`/`%27`, `--`, etc.
- XSS: `<script>`, `onerror=`, `javascript:`, `document.cookie`
- Path traversal/LFI: `../`, `%2e%2e%2f`, `etc/passwd`
- RFI: external http(s) in params
- Command injection: `;`, `&&`, `||` with `bash/nc/ls/id/whoami`

Quick test:
```bash
python3 -m http.server 8080 &
curl "http://127.0.0.1:8080/test?q=1%27%20OR%201=1--"
curl "http://127.0.0.1:8080/?x=<script>alert(1)</script>"
curl "http://127.0.0.1:8080/../../etc/passwd"
tail -n 100 ids.log
```

## Configuration
`ids_config.json` (key snippets):
```json
{
  "interface": "any",
  "signature_rules": {
    "port_scan_threshold": 10,
    "syn_flood_threshold": 50,
    "large_packet_threshold": 1500,
    "suspicious_ports": [23,135,139,445,1433,3389]
  },
  "web_signatures": {
    "enabled": true,
    "inspect_ports": [80,8080,8000,443],
    "max_payload_len": 4096
  },
  "anomaly_detection": { "enabled": true, "packet_size_deviation": 2.0 },
  "logging": { "level": "INFO", "file": "ids.log" },
  "notifications": {
    "enabled": false,
    "min_severity": "HIGH",
    "email": {
      "enabled": false,
      "smtp_host": "smtp.gmail.com",
      "smtp_port": 587,
      "use_tls": true,
      "username": "your@gmail.com",
      "app_password": "app_password",
      "to": ["recipient@example.com"]
    },
    "whatsapp": {
      "enabled": false,
      "provider": "twilio",
      "account_sid": "ACxxxx",
      "auth_token": "xxxx",
      "from_number": "whatsapp:+14155238886",
      "to_numbers": ["whatsapp:+1234567890"]
    }
  }
}
```

## Notifications
- Email (Gmail): create an App Password; set username/app_password/to in config.
- WhatsApp (Twilio): enable sandbox or approved senders; set SID/token/from/to.
- Test:
```bash
./blue-wix notify-test -s HIGH
```

## Architecture
- Capture thread (Scapy) → analysis (signature + anomaly) → alert pipeline
- GUI runs on single main UI thread; worker thread handles heavy work
- Logging to `ids.log`, optional notifications

## Security Notes
- Run with root to capture packets
- Use only on authorized networks
- Web signatures are heuristic, not exhaustive

## Roadmap
- GUI dashboard charts (alerts over time/by type)
- Configurable rule editor in GUI
- PCAP import/offline analysis
- GeoIP/source enrichment

## Contributing
PRs welcome. Please open an issue first for major changes.

## License
MIT
