# 🛡️ SOC Threat Hunting & Investigation Portfolio

Welcome to my Security Operations Center (SOC) investigation and threat hunting portfolio.

This repository contains hands-on investigations performed using **real-world malware PCAP datasets**, analyzed with **Splunk SIEM and Wireshark**. Each project demonstrates practical detection, correlation, and attack-chain reconstruction skills aligned with SOC analyst responsibilities.

---

## 👨‍💻 About Me

**Name:** Rohit Aswal  
**Focus:** SOC Analyst | Threat Hunting | Network Security Monitoring  
**Primary Tools:** Splunk, Wireshark, Kali Linux  
**Methodology:** MITRE ATT&CK-aligned investigation and multi-layer traffic analysis  

---

# 🔍 Featured Investigation Series  
## PhantomStealer Malware – Multi-Layer Network Analysis

This 3-project series investigates a real malware infection from Malware Traffic Analysis and reconstructs the complete attack chain across DNS, HTTP, and TLS protocols.

---

## 📌 Project 1 – DNS Traffic Analysis  
**Title:** PhantomStealer DNS Beaconing Detection using Splunk  

### 🔎 Focus:
- DNS query analysis
- C2 domain identification
- Beaconing detection
- Field extraction using regex
- Compromised host identification

### 🧠 Key Findings:
- Suspicious repeated queries to:
  - `scxzswx.lovestoblog.com`
  - `exczx.com`
- Infected host identified: `10.1.30.101`
- DNS-based C2 beaconing confirmed

### 🛠 Skills Demonstrated:
- SPL queries
- Regex field extraction
- IOC development
- MITRE ATT&CK mapping (T1071.004)

➡️ [View Project 1 - DNS Analysis](./Project-01-DNS-Analysis)

---

## 📌 Project 2 – HTTP Traffic Analysis  
**Title:** PhantomStealer HTTP C2 Communication Investigation  

### 🔎 Focus:
- HTTP request analysis
- Payload/config file detection
- C2 IP correlation with DNS findings
- Attack timeline reconstruction

### 🧠 Key Findings:
- HTTP communication to `185.27.134.154`
- Timestamped config file downloads:
  - `/arquivo_20260129190545.txt`
  - `/arquivo_20260129190534.txt`
- Public IP discovery via icanhazip.com

### 🛠 Skills Demonstrated:
- Web protocol analysis
- Cross-protocol correlation
- Attack chain building
- MITRE ATT&CK mapping (T1071.001, T1105)

➡️ [View Project 2 - HTTP Analysis](./Project-02-HTTP-Analysis)

---

## 📌 Project 3 – TLS/SSL Encrypted Traffic Analysis  
**Title:** Encrypted C2 Channel Detection using SNI Extraction  

### 🔎 Focus:
- TLS handshake analysis
- Server Name Indication (SNI) extraction
- Encrypted C2 channel detection
- Multi-layer correlation (DNS → HTTP → TLS)

### 🧠 Key Findings:
- TLS connection to malicious domain `exczx.com`
- Encrypted Application Data exchanged
- 223 TLS events analyzed
- Multi-channel C2 infrastructure confirmed

### 🛠 Skills Demonstrated:
- Encrypted traffic investigation
- TLS protocol breakdown
- SNI-based detection
- MITRE ATT&CK mapping (T1573)

➡️ [View Project 3 - TLS Analysis](./Project-03-TLS-Analysis)

---

# 🎯 Complete Attack Chain Reconstruction

The investigation demonstrates how PhantomStealer used:

1. **DNS** → C2 domain resolution  
2. **HTTP** → Config file download  
3. **TLS (HTTPS)** → Encrypted C2 communication  

This shows multi-layered malware communication and detection methodology.

---

# 🛠 Tools & Technologies Used

- **Splunk Enterprise** – Log ingestion, SPL queries, correlation
- **Wireshark** – PCAP packet analysis
- **Kali Linux** – Isolated malware analysis environment
- **MITRE ATT&CK Framework** – Behavioral mapping
- **Malware Traffic Analysis** – Real-world dataset source

---

# 📊 Skills Demonstrated Across Portfolio

- Threat Hunting Methodology
- Network Traffic Analysis
- SIEM Query Development (SPL)
- IOC Extraction & Documentation
- C2 Infrastructure Identification
- Encrypted Traffic Analysis
- Attack Timeline Reconstruction
- MITRE ATT&CK Mapping
- Professional Security Documentation

---

# 🚀 Upcoming Projects

- Brute Force Detection in Splunk
- Windows Event Log Investigation
- PowerShell Threat Detection
- Lateral Movement Detection
- Active Directory Attack Analysis
- SOC Alert Triage Simulations

---

# 📌 Why This Portfolio Matters

This repository demonstrates:
- Practical SOC investigation skills
- Real-world malware traffic analysis
- Multi-protocol correlation
- Structured and professional reporting
- Analyst-level documentation

All investigations are performed in controlled lab environments using publicly available malware datasets.
