<div align="center">

```
██╗  ██╗████████╗████████╗██████╗
██║  ██║╚══██╔══╝╚══██╔══╝██╔══██╗
███████║   ██║      ██║   ██████╔╝
██╔══██║   ██║      ██║   ██╔═══╝
██║  ██║   ██║      ██║   ██║
╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝

H T T P   C 2   C O M M U N I C A T I O N   A N A L Y S I S
```

# 📌 Project 2 — HTTP Traffic Analysis
## PhantomStealer HTTP C2 Communication Investigation

[![Back to Portfolio](https://img.shields.io/badge/←%20Back-Main%20Portfolio-181717?style=flat-square&logo=github)](../README.md)
[![Protocol](https://img.shields.io/badge/Protocol-HTTP-purple?style=flat-square)]()
[![MITRE](https://img.shields.io/badge/MITRE-T1071.001%20%7C%20T1105-orange?style=flat-square)](https://attack.mitre.org/techniques/T1071/001/)
[![Tool](https://img.shields.io/badge/Tool-Splunk%20Enterprise-black?style=flat-square&logo=splunk&logoColor=green)]()
[![Status](https://img.shields.io/badge/Status-Complete-brightgreen?style=flat-square)]()

</div>

---

## 📋 Objective

Analyse HTTP traffic from the PhantomStealer infection to **identify C2 communication patterns**, **detect downloaded malware payloads**, and **correlate findings with the DNS analysis from Project 1** — building a cross-protocol picture of the attack chain.

---

## 🧰 Tools & Dataset

| Category | Detail |
|----------|--------|
| **SIEM** | Splunk Enterprise |
| **Capture Tool** | Wireshark (filter: `http`) |
| **Analysis OS** | Kali Linux (isolated VM) |
| **Dataset** | Same PCAP as Project 1 — `2026-01-30-PhantomStealer-infection.pcap` |
| **Events Analysed** | 6 HTTP transactions (complete HTTP communication) |
| **Splunk Index** | `phantom_http` |

---

## 🔗 Connection to Project 1

> **This project builds directly on DNS findings from Project 1.** The C2 IP `185.27.134.154` identified here resolves from `scxzswx.lovestoblog.com` — the primary beaconing domain found in DNS analysis. This cross-protocol link is the foundation of the full attack chain.

```
Project 1 (DNS):  scxzswx.lovestoblog.com  →  185.27.134.154  [resolved]
Project 2 (HTTP): 10.1.30.101              →  185.27.134.154  [HTTP contact confirmed]
                  ↳ DNS finding confirmed by HTTP evidence ✅
```

---

## 🔄 Investigation Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                     INVESTIGATION PIPELINE                      │
│                                                                 │
│  [1] Open PCAP  →  [2] Filter: http  →  [3] Export CSV        │
│                                               ↓                 │
│  [7] Correlate   ←  [6] IOC Extract  ←  [4] Ingest Splunk     │
│  with Project 1                           ↓                     │
│       ↓               [5] SPL Analysis → findings              │
│  [8] Attack chain rebuilt across DNS + HTTP                     │
└─────────────────────────────────────────────────────────────────┘
```

### Phase 1 — HTTP Traffic Extraction

Applied Wireshark display filter:
```
http
```

- Identified **6 HTTP transactions**
- Exported as CSV: `http_logs.csv`
- Transferred to Windows Splunk host

### Phase 2 — Splunk Ingestion

```
Settings → Indexes → New Index → Name: phantom_http
Settings → Add Data → Upload → http_logs.csv
Source Type: csv | Index: phantom_http
```

✅ **6 events successfully indexed**

---

## 🔬 Threat Hunting Analysis

### Step 1 — Traffic Overview

```spl
index=phantom_http 
| table Time Source Destination Info
```

**Findings:**
- All 6 transactions originated from `10.1.30.101` (same infected host from Project 1)
- Communications with two external IPs: `185.27.134.154` and `104.16.185.241`

---

### Step 2 — Source & Destination Analysis

```spl
index=phantom_http
| stats count by Source Destination
```

**Results:**

| Source | Destination | Count | Assessment |
|--------|-------------|-------|------------|
| `10.1.30.101` | `185.27.134.154` | 4 | 🔴 **C2 Communication** |
| `10.1.30.101` | `104.16.185.241` | 2 | 🟡 **IP Recon** (icanhazip.com) |

---

### Step 3 — Payload / Config File Detection

**Objective:** Identify files downloaded from C2 infrastructure.

```spl
index=phantom_http
| rex field=Info "GET (?<filename>/[^\s]+)"
| where isnotnull(filename)
| table Time Source Destination filename
```

**🚨 Critical Findings:**

| Filename | Timestamp Embedded | Assessment |
|----------|-------------------|------------|
| `/arquivo_20260129190545.txt` | 2026-01-29 19:05:45 | 🔴 Malware config file |
| `/arquivo_20260129190534.txt` | 2026-01-29 19:05:34 | 🔴 Malware config file |

> **Analysis:**
> - `arquivo` is Portuguese for "file" — suggests a Portuguese-speaking threat actor
> - Timestamps embedded in filenames indicate **automated, time-stamped config generation** on the C2 server
> - Both returned **HTTP 200 OK** — files successfully downloaded by the malware

---

### Step 4 — HTTP Method Distribution

```spl
index=phantom_http
| rex field=Info "^(?<http_method>GET|POST|HTTP)"
| stats count by http_method
```

**Findings:**
- Only `GET` requests observed — malware downloading commands/configs
- `HTTP` responses: all `200 OK` — successful transfers
- No `POST` requests — no outbound data exfiltration captured in this sample

---

### Step 5 — Attack Timeline

```spl
index=phantom_http
| timechart count
```

**Timeline:**

```
19:05:34 UTC  →  GET /arquivo_20260129190534.txt  (Config file #1 downloaded)
19:05:45 UTC  →  GET /arquivo_20260129190545.txt  (Config file #2 downloaded)

Total activity window: ~40 seconds
Pattern: Burst of activity = active C2 session receiving updated instructions
```

---

### Step 6 — C2 Communication Evidence

```spl
index=phantom_http
| eval C2_Server="185.27.134.154 (scxzswx.lovestoblog.com from DNS)"
| where Destination="185.27.134.154"
| table Time Source Destination Info C2_Server
```

**Evidence Chain:**

```
DNS (Project 1):   scxzswx.lovestoblog.com queried 4 times
DNS Resolution:    scxzswx.lovestoblog.com → 185.27.134.154
HTTP (Project 2):  GET requests to 185.27.134.154 ← CONFIRMED
Conclusion:        Complete DNS-to-HTTP C2 chain documented ✅
```

---

### Step 7 — Public IP Discovery

```spl
index=phantom_http
| where Destination="104.16.185.241"
| eval Service="icanhazip.com (Public IP Discovery)"
| table Time Source Destination Service Info
```

**Behaviour Analysis:**
- Malware queried `icanhazip.com` to discover the victim's public IP
- This occurs **before** C2 contact — classic reconnaissance behaviour
- Public IP is typically registered with the C2 server to track the infected host

---

## 🔍 Key Findings

### Full Attack Chain (DNS → HTTP)

```
STEP 1 — INFECTION
  Host 10.1.30.101 compromised with PhantomStealer

STEP 2 — RECONNAISSANCE (HTTP)
  GET http://icanhazip.com → 104.16.185.241
  Timestamp: 2026-01-29 19:05:xx UTC
  Purpose: Discover public IP, register with C2

STEP 3 — C2 RESOLUTION (DNS — Project 1)
  DNS: scxzswx.lovestoblog.com → 185.27.134.154
  DNS: exczx.com → 185.38.151.11

STEP 4 — CONFIG DOWNLOAD (HTTP — Project 2)
  GET 185.27.134.154/arquivo_20260129190534.txt  [HTTP 200 OK]
  GET 185.27.134.154/arquivo_20260129190545.txt  [HTTP 200 OK]
  Purpose: Malware receives updated C2 instructions/config

STEP 5 → Encrypted TLS channel established [Project 3]
```

---

### Indicators of Compromise (IOCs)

**🌐 Network IOCs:**
```
C2 IP:         185.27.134.154
C2 Domain:     scxzswx.lovestoblog.com (from Project 1)
Recon IP:      104.16.185.241 (icanhazip.com)
```

**📄 File IOCs:**
```
/arquivo_20260129190545.txt
/arquivo_20260129190534.txt
```

**🖥️ Host IOCs:**
```
Infected Host: 10.1.30.101
```

**🔁 Behavioural IOCs:**
- HTTP GET to timestamped config files
- Public IP lookup immediately before C2 contact
- All activity within 40-second burst window
- `arquivo` naming pattern (Portuguese-language C2 server)

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|----|----|
| Discovery | System Network Configuration Discovery | [T1016](https://attack.mitre.org/techniques/T1016/) | `icanhazip.com` HTTP request to discover public IP |
| Command & Control | Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | HTTP communication to C2 server `185.27.134.154` |
| Command & Control | Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | Config files downloaded via HTTP GET |
| Command & Control | Web Service | [T1102](https://attack.mitre.org/techniques/T1102/) | Abuse of standard web protocols for C2 |

---

## 🛡️ Recommendations

### Immediate Response

```
1. BLOCK     →  Outbound HTTP to 185.27.134.154
               DNS resolution of scxzswx.lovestoblog.com
               Internal access to icanhazip.com (recon indicator)

2. CONTAIN   →  Isolate 10.1.30.101 immediately
               Forensic analysis of downloaded config files
               Search for Portuguese-language file patterns on disk

3. HUNT      →  Search all hosts for GET requests matching:
               /arquivo_\d{14}\.txt pattern
               Queries to any IP lookup service
```

### Detection Rules

**Alert: HTTP Config File Download Pattern**
```spl
index=http_logs
| rex field=url "(?<pattern>\/arquivo_\d{14}\.txt)"
| where isnotnull(pattern)
| stats count by src_ip dest_ip url
```

**Alert: Public IP Discovery via HTTP**
```spl
index=http_logs
| where dest_domain IN ("icanhazip.com", "ipinfo.io", "api.ipify.org")
| stats count by src_ip dest_domain
```

**Alert: Repeated HTTP to Same External IP**
```spl
index=http_logs
| stats count by src_ip dest_ip
| where count > 3 AND NOT cidrmatch("10.0.0.0/8", dest_ip)
```

---

## 📊 Cross-Protocol Correlation Summary

| Layer | Project | Finding | IOC |
|-------|---------|---------|-----|
| **DNS** | Project 1 | Beaconing to `scxzswx.lovestoblog.com` | 4 repeated queries |
| **DNS** | Project 1 | Domain resolved to `185.27.134.154` | DNS A record |
| **HTTP** | Project 2 | HTTP GET to `185.27.134.154` | 4 transactions |
| **HTTP** | Project 2 | Config files downloaded | `arquivo_*.txt` files |

---

## 🔗 Related Projects

| Project | Focus | Link |
|---------|-------|------|
| **Project 1** | DNS Beaconing Detection | [→ DNS Analysis](../Project-01-PhantomStealer-DNS-Analysis/) |
| **Project 3** | TLS Encrypted C2 Channels | [→ TLS Analysis](../Project-03-PhantomStealer-TLS-Analysis/) |
| **All Queries** | Full SPL query reference | [→ Splunk Queries](./splunk-queries-http.md) |

---

## 📚 References

- [Project 1 — DNS Analysis](../Project-01-PhantomStealer-DNS-Analysis/)
- [MITRE ATT&CK — T1071.001](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK — T1105](https://attack.mitre.org/techniques/T1105/)
- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/)

---

<div align="center">

**Project Date:** February 2026 · **Platform:** Splunk Enterprise · **Part:** 2 of 3

[← Project 1: DNS](../Project-01-PhantomStealer-DNS-Analysis/) · [Back to Portfolio](../README.md) · [Project 3: TLS →](../Project-03-PhantomStealer-TLS-Analysis/)

</div>
