# 🛡️ Basic Packet Analyzer 
This project captures live network traffic and extracts:
- Source and destination IPs
- Protocols (TCP, UDP, ICMP)
- Raw payloads (data)

---
```
Algonive_Basic_Packet_Analyzer/
│
├── packet_analyzer.py          ← main script
├── packet_log.txt              ← output log (generated at runtime)
├── packet_log.csv              ← output log (generated at runtime)
├── README.md                   ← explanation & usage guide
└── requirements.txt            ← Python dependencies
```
---

### 📄 requirements.

scapy


---

# 🛡️ Basic Packet Analyzer — Algonive Internship Project

This project captures live network traffic and extracts:
- Source and destination IPs
- Protocols (TCP, UDP, ICMP)
- Raw payloads (data)

## 📦 Features
- Real-time packet sniffing
- Protocol detection
- Clean CSV logging for security analysis

## ▶️ Usage

### 1. Install Dependencies
bash
pip install -r requirements.txt


### 2. Run the Analyzer

bash
sudo python packet_analyzer.py


> Requires administrator privileges to sniff live traffic.

### 3. Output

* Console output of each captured packet
* Logs saved in packet_log.csv

## 📁 Sample Output (log.txt)

[2025-06-29 03:56:48] Protocol: TCP
 Source IP      : 142.250.77.195
 Destination IP : 192.168.1.14
 Payload (hex)  : 450000343a5000007b0667008efa4dc3c0a8010e0050b3424bb63fab9ca69fae8010041ad94e00000101080a32db9b3ca3ec0d93


## 📚 Built With

* Python 3
* [Scapy](https://scapy.readthedocs.io/)

## 👨‍💻 Author

\Kshitiz – Cybersecurity Intern @Algonive
