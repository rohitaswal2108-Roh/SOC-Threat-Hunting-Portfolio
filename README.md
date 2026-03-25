<div align="center">

```
███████╗ ██████╗  ██████╗    ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗
██╔════╝██╔═══██╗██╔════╝    ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝
███████╗██║   ██║██║            ██║   ███████║██████╔╝█████╗  ███████║   ██║   
╚════██║██║   ██║██║            ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   
███████║╚██████╔╝╚██████╗       ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   
╚══════╝ ╚═════╝  ╚═════╝       ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝  

H U N T I N G  —  D E T E C T I N G  —  R E S P O N D I N G
```

# 🛡️ SOC Threat Hunting & Investigation Portfolio

**Rohit Aswal · SOC Analyst | Threat Hunter | Network Security Monitoring**

[![Splunk](https://img.shields.io/badge/Tool-Splunk%20Enterprise-black?style=flat-square&logo=splunk&logoColor=green)](https://www.splunk.com/)
[![Wireshark](https://img.shields.io/badge/Tool-Wireshark-1679A7?style=flat-square&logo=wireshark)](https://www.wireshark.org/)
[![MITRE](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-orange?style=flat-square)](https://attack.mitre.org/)
[![Kali](https://img.shields.io/badge/OS-Kali%20Linux-557C94?style=flat-square&logo=kalilinux&logoColor=white)](https://www.kali.org/)
[![CEH](https://img.shields.io/badge/Certified-Ethical%20Hacker%20(CEH)-red?style=flat-square)](https://www.eccouncil.org/)

---

*Hands-on SOC investigations using real-world malware PCAP datasets — each case reconstructs a complete attack chain across DNS, HTTP, and TLS using Splunk SIEM and Wireshark.*

</div>

---

## 👨‍💻 About Me

| | |
|---|---|
| **Name** | Rohit Aswal |
| **Role Focus** | SOC Analyst · Threat Hunting · Network Security Monitoring |
| **Primary Tools** | Splunk Enterprise · Wireshark · Kali Linux |
| **Methodology** | MITRE ATT&CK-aligned multi-layer traffic analysis |
| **LinkedIn** | [![LinkedIn](https://img.shields.io/badge/-rohit--aswal08-0A66C2?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/rohit-aswal08) |
| **GitHub** | [![GitHub](https://img.shields.io/badge/-rohitaswal2108--Roh-181717?style=flat-square&logo=github)](https://github.com/rohitaswal2108-Roh) |

---

## 🔍 Featured Investigation Series

### PhantomStealer Malware — Multi-Layer Network Analysis

> A 3-project series investigating a real malware infection sourced from [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/), reconstructing the complete attack chain across DNS, HTTP, and TLS protocols using Splunk SIEM.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        PHANTOMSTEALER ATTACK CHAIN                          │
├─────────────────┬─────────────────┬─────────────────────────────────────────┤
│   PROJECT 1     │   PROJECT 2     │   PROJECT 3                             │
│   DNS Layer     │   HTTP Layer    │   TLS Layer                             │
│                 │                 │                                         │
│  C2 Beaconing   │  Config File    │  Encrypted C2                           │
│  Detection      │  Downloads      │  Channel Detection                      │
│                 │                 │                                         │
│  T1071.004      │  T1071.001      │  T1573                                  │
│                 │  T1105          │                                         │
└────────┬────────┴────────┬────────┴──────────┬──────────────────────────────┘
         │                 │                   │
         └────────>────────┴─────────>─────────┘
              DNS resolves    HTTP downloads      TLS encrypts
              C2 domain       config files        C2 traffic
```

---

## 📌 Project 1 — DNS Traffic Analysis

> **Title:** PhantomStealer DNS Beaconing Detection using Splunk

![DNS Analysis](https://img.shields.io/badge/Protocol-DNS-blue?style=for-the-badge)
![MITRE](https://img.shields.io/badge/MITRE-T1071.004-orange?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen?style=for-the-badge)

### 🔎 Focus Areas
- DNS query pattern analysis and C2 domain identification
- Beaconing detection via query frequency analysis
- Field extraction using Splunk regex (`rex`)
- Compromised host identification

### 🧠 Key Findings

| Finding | Detail | Severity |
|--------|--------|----------|
| C2 Domain (Primary) | `scxzswx.lovestoblog.com` → `185.27.134.154` | 🔴 Critical |
| C2 Domain (Secondary) | `exczx.com` → `185.38.151.11` | 🔴 Critical |
| Infected Host | `10.1.30.101` | 🔴 Critical |
| Recon Behaviour | `icanhazip.com` public IP lookup | 🟡 Suspicious |
| Beaconing Confirmed | 4 repeated queries to C2 domain | 🔴 Critical |

### 🛠️ Skills Demonstrated
`SPL Queries` · `Regex Field Extraction` · `IOC Development` · `MITRE ATT&CK Mapping` · `DNS Beaconing Detection`

➡️ **[View Full Project 1 — DNS Analysis](./Project-01-PhantomStealer-DNS-Analysis/)**

---

## 📌 Project 2 — HTTP Traffic Analysis

> **Title:** PhantomStealer HTTP C2 Communication Investigation

![HTTP Analysis](https://img.shields.io/badge/Protocol-HTTP-purple?style=for-the-badge)
![MITRE](https://img.shields.io/badge/MITRE-T1071.001%20%7C%20T1105-orange?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen?style=for-the-badge)

### 🔎 Focus Areas
- HTTP GET request analysis and payload detection
- Config file download identification (timestamped filenames)
- C2 IP correlation with DNS findings from Project 1
- Attack timeline reconstruction from HTTP session data

### 🧠 Key Findings

| Finding | Detail | Severity |
|--------|--------|----------|
| C2 Server | `185.27.134.154` (4 HTTP transactions) | 🔴 Critical |
| Config File 1 | `/arquivo_20260129190545.txt` downloaded | 🔴 Critical |
| Config File 2 | `/arquivo_20260129190534.txt` downloaded | 🔴 Critical |
| IP Recon | `icanhazip.com` (104.16.185.241) queried | 🟡 Suspicious |
| Activity Window | All traffic within 40-second burst | 🟡 Suspicious |

### 🛠️ Skills Demonstrated
`Web Protocol Analysis` · `Cross-Protocol Correlation` · `Attack Chain Building` · `Payload Detection` · `MITRE ATT&CK Mapping`

➡️ **[View Full Project 2 — HTTP Analysis](./Project-02-PhantomStealer-HTTP-Analysis/)**

---

## 📌 Project 3 — TLS/SSL Encrypted Traffic Analysis

> **Title:** Encrypted C2 Channel Detection using SNI Extraction

![TLS Analysis](https://img.shields.io/badge/Protocol-TLS%2FSSL-red?style=for-the-badge)
![MITRE](https://img.shields.io/badge/MITRE-T1573-orange?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen?style=for-the-badge)

### 🔎 Focus Areas
- TLS handshake phase analysis (Client Hello → Application Data)
- Server Name Indication (SNI) extraction for domain detection
- Encrypted C2 channel identification without decryption
- Multi-layer correlation: DNS → HTTP → TLS

### 🧠 Key Findings

| Finding | Detail | Severity |
|--------|--------|----------|
| Encrypted C2 | TLS connection to `exczx.com` via SNI | 🔴 Critical |
| TLS Events | 223 total events analysed | ℹ️ Info |
| Encrypted Payloads | Application Data exchanged post-handshake | 🔴 Critical |
| CDN Abuse | `res.cloudinary.com` TLS connections | 🟡 Suspicious |
| C2 Confirmed | Same infrastructure across DNS + HTTP + TLS | 🔴 Critical |

### 🛠️ Skills Demonstrated
`Encrypted Traffic Analysis` · `TLS Protocol Breakdown` · `SNI-Based Detection` · `Multi-Protocol Correlation` · `MITRE ATT&CK Mapping`

➡️ **[View Full Project 3 — TLS Analysis](./Project-03-PhantomStealer-TLS-Analysis/)**

---

## 🎯 Complete Attack Chain Reconstruction

```
PHASE 1 — RECONNAISSANCE
━━━━━━━━━━━━━━━━━━━━━━━━
Host: 10.1.30.101
Action: DNS query to icanhazip.com → discovers public IP
MITRE: T1016 (System Network Configuration Discovery)

         ↓

PHASE 2 — C2 DOMAIN RESOLUTION  [Project 1 — DNS]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Action: 4x DNS queries to scxzswx.lovestoblog.com → 185.27.134.154
        2x DNS queries to exczx.com → 185.38.151.11
MITRE: T1071.004 (Application Layer Protocol: DNS)

         ↓

PHASE 3 — UNENCRYPTED C2 CONTACT  [Project 2 — HTTP]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Action: HTTP GET → 185.27.134.154
        Downloads: arquivo_20260129190534.txt
                   arquivo_20260129190545.txt
MITRE: T1071.001 (Web Protocols), T1105 (Ingress Tool Transfer)

         ↓

PHASE 4 — ENCRYPTED C2 CHANNEL  [Project 3 — TLS]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Action: TLS HTTPS connection to exczx.com (detected via SNI)
        223 events — Client Hello → Application Data
MITRE: T1573 (Encrypted Channel)
```

---

## 🗺️ MITRE ATT&CK Coverage

| Technique ID | Technique Name | Tactic | Project |
|-------------|---------------|--------|---------|
| [T1016](https://attack.mitre.org/techniques/T1016/) | System Network Configuration Discovery | Discovery | 1, 2 |
| [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | Application Layer Protocol: DNS | Command & Control | 1 |
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Application Layer Protocol: Web | Command & Control | 2, 3 |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | Command & Control | 2 |
| [T1102](https://attack.mitre.org/techniques/T1102/) | Web Service | Command & Control | 2 |
| [T1573](https://attack.mitre.org/techniques/T1573/) | Encrypted Channel | Command & Control | 3 |

---

## 🛠️ Tools & Technologies

```
┌─────────────────────────────────────────────────────────────────┐
│                      SOC ANALYST TOOLKIT                        │
├──────────────────────┬──────────────────────┬───────────────────┤
│   SIEM               │   TRAFFIC ANALYSIS   │   ENVIRONMENT     │
│                      │                      │                   │
│  • Splunk Enterprise │  • Wireshark         │  • Kali Linux     │
│  • SPL (Search       │  • PCAP filtering    │  • Isolated VM    │
│    Processing Lang)  │  • DNS/HTTP/TLS      │                   │
│  • Custom Indexes    │    dissection        │                   │
│  • Correlation Rules │  • CSV export        │                   │
│                      │                      │                   │
├──────────────────────┴──────────────────────┴───────────────────┤
│   FRAMEWORKS & DATASETS                                         │
│  • MITRE ATT&CK Framework — Behavioral mapping                  │
│  • Malware Traffic Analysis — Real-world PCAP datasets          │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📊 Portfolio Skills Matrix

| Skill | Projects |
|-------|----------|
| Threat Hunting Methodology | 1, 2, 3 |
| Network Traffic Analysis | 1, 2, 3 |
| SIEM Query Development (SPL) | 1, 2, 3 |
| IOC Extraction & Documentation | 1, 2, 3 |
| C2 Infrastructure Identification | 1, 2, 3 |
| DNS Beaconing Detection | 1 |
| HTTP Payload Analysis | 2 |
| Encrypted Traffic Analysis (TLS/SNI) | 3 |
| Attack Timeline Reconstruction | 2, 3 |
| MITRE ATT&CK Mapping | 1, 2, 3 |
| Cross-Protocol Correlation | 2, 3 |
| Professional Security Documentation | 1, 2, 3 |

---

## 🔴 Indicators of Compromise (Master IOC List)

### Network IOCs

| Type | Value | Source |
|------|-------|--------|
| C2 Domain | `scxzswx.lovestoblog.com` | Project 1, 2 |
| C2 Domain | `exczx.com` | Project 1, 3 |
| C2 IP | `185.27.134.154` | Project 2 |
| C2 IP | `185.38.151.11` | Project 1, 3 |
| Recon IP | `104.16.185.241` (icanhazip.com) | Project 1, 2 |

### Host IOCs

| Type | Value | Source |
|------|-------|--------|
| Infected Host | `10.1.30.101` | Project 1, 2, 3 |
| Network Segment | `10.1.30.0/24` | Project 1 |

### File IOCs

| Type | Value | Source |
|------|-------|--------|
| Downloaded Config | `/arquivo_20260129190545.txt` | Project 2 |
| Downloaded Config | `/arquivo_20260129190534.txt` | Project 2 |

---

## 🚀 Upcoming Projects

| Project | Focus | Status |
|---------|-------|--------|
| Brute Force Detection | Splunk alert engineering | 🔜 Planned |
| Windows Event Log Investigation | Host-based threat hunting | 🔜 Planned |
| PowerShell Threat Detection | Script-based attack analysis | 🔜 Planned |
| Lateral Movement Detection | East-west traffic analysis | 🔜 Planned |
| Active Directory Attack Analysis | Identity-based attacks | 🔜 Planned |
| SOC Alert Triage Simulations | End-to-end SOC workflow | 🔜 Planned |

---

## ⚠️ Disclaimer

All investigations are performed in **controlled lab environments** using **publicly available malware datasets** from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/). No real systems were compromised. All findings are for educational and portfolio purposes only.

---

<div align="center">

**Rohit Aswal** · SOC Analyst · Threat Hunter
*🔐 Interests: SOC Analysis · Digital Forensics · Incident Response · Threat Hunting*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-rohit--aswal08-0A66C2?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/rohit-aswal08)
[![GitHub](https://img.shields.io/badge/GitHub-rohitaswal2108--Roh-181717?style=flat-square&logo=github)](https://github.com/rohitaswal2108-Roh)

</div>
