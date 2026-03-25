<div align="center">

```
██████╗ ███╗   ██╗███████╗
██╔══██╗████╗  ██║██╔════╝
██║  ██║██╔██╗ ██║███████╗
██║  ██║██║╚██╗██║╚════██║
██████╔╝██║ ╚████║███████║
╚═════╝ ╚═╝  ╚═══╝╚══════╝

D N S   B E A C O N I N G   D E T E C T I O N
```

# 📌 Project 1 — DNS Traffic Analysis
## PhantomStealer DNS Beaconing Detection using Splunk

[![Back to Portfolio](https://img.shields.io/badge/←%20Back-Main%20Portfolio-181717?style=flat-square&logo=github)](../README.md)
[![Protocol](https://img.shields.io/badge/Protocol-DNS-blue?style=flat-square)]()
[![MITRE](https://img.shields.io/badge/MITRE-T1071.004-orange?style=flat-square)](https://attack.mitre.org/techniques/T1071/004/)
[![Tool](https://img.shields.io/badge/Tool-Splunk%20Enterprise-black?style=flat-square&logo=splunk&logoColor=green)]()
[![Status](https://img.shields.io/badge/Status-Complete-brightgreen?style=flat-square)]()

</div>

---

## 📋 Objective

Analyse real-world DNS traffic from a PhantomStealer malware infection to **detect Command & Control (C2) communication**, **identify beaconing behaviour**, and **determine the compromised host** using Splunk SIEM and custom SPL queries.

---

## 🧰 Tools & Dataset

| Category | Detail |
|----------|--------|
| **SIEM** | Splunk Enterprise |
| **Capture Tool** | Wireshark (PCAP → CSV export) |
| **Analysis OS** | Kali Linux (isolated VM) |
| **Dataset Source** | [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/) |
| **Sample Date** | 2026-01-30 |
| **Malware Family** | PhantomStealer |
| **File** | `2026-01-30-PhantomStealer-infection.pcap.zip` |
| **Archive Password** | `infected_20260130` |
| **Events Analysed** | 10 DNS events (filtered from full PCAP) |

---

## 🔄 Investigation Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                     INVESTIGATION PIPELINE                      │
│                                                                 │
│  [1] Download PCAP  →  [2] Extract in VM  →  [3] Wireshark    │
│                                                    ↓            │
│  [7] MITRE Map   ←  [6] IOC Extract   ←  [4] Filter DNS       │
│       ↓                                       ↓                 │
│  [8] Report          [5] Export CSV  →  Splunk Ingest          │
└─────────────────────────────────────────────────────────────────┘
```

### Phase 1 — PCAP Acquisition & Extraction

1. Downloaded `2026-01-30-PhantomStealer-infection.pcap.zip` from Malware Traffic Analysis
2. Extracted safely inside **Kali Linux isolated VM** using password `infected_20260130`
3. Opened PCAP in Wireshark — observed mixed traffic: DNS, HTTP, TLS

> ⚠️ **Safety Note:** Always handle live malware PCAPs inside an isolated virtual machine with no network access to production systems.

### Phase 2 — DNS Traffic Extraction

Applied Wireshark display filter:
```
dns
```

Exported filtered results: **File → Export Packet Dissections → As CSV → `dns_logs.csv`**

Transferred CSV to Windows host running Splunk Enterprise.

### Phase 3 — Splunk Ingestion

```
Settings → Indexes → New Index → Name: phantom_dns
Settings → Add Data → Upload → dns_logs.csv
Source Type: csv | Index: phantom_dns
```

Verified ingestion:
```spl
index=phantom_dns
```
✅ **10 events successfully indexed**

### Phase 4 — Field Extraction

Splunk treated the CSV as a quoted string — manual regex extraction was required.

**Regex pattern used:**
```regex
"(?<No>[^"]+)","(?<Time>[^"]+)","(?<Source>[^"]+)","(?<Destination>[^"]+)","(?<Protocol>[^"]+)","(?<Length>[^"]+)","(?<Info>[^"]+)"
```

**Fields extracted:** `No` · `Time` · `Source` · `Destination` · `Protocol` · `Length` · `Info`

**Verification query:**
```spl
index=phantom_dns 
| table No Time Source Destination Protocol Length Info
```

---

## 🔬 Threat Hunting Analysis

### Step 1 — Domain Frequency Analysis

**Objective:** Identify which domains were queried most frequently — high frequency indicates C2 beaconing.

```spl
index=phantom_dns
| rex field=Info "A (?<domain>[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})"
| stats count by domain
| sort -count
```

**Results:**

| Domain | Query Count | Assessment |
|--------|-------------|------------|
| `scxzswx.lovestoblog.com` | 4 | 🔴 **CRITICAL** — Random subdomain, repeated queries, free hosting |
| `exczx.com` | 2 | 🔴 **SUSPICIOUS** — Short random-looking domain |
| `icanhazip.com` | 2 | 🟡 **SUSPICIOUS** — Legitimate service abused for IP discovery |
| `res.cloudinary.com` | 2 | 🟢 **LEGITIMATE** — CDN traffic |

> **Analysis:** `scxzswx.lovestoblog.com` exhibits hallmarks of malware C2: random subdomain pattern, hosted on a free blogging platform (disposable infrastructure), and the highest query frequency. This is consistent with Domain Generation Algorithm (DGA) or temporary callback domains.

---

### Step 2 — Beaconing Detection

**Objective:** Confirm repeated DNS queries indicating automated C2 callback behaviour.

```spl
index=phantom_dns
| rex field=Info "A (?<domain>[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})"
| stats count by domain
| where count > 1
```

**Finding:** `scxzswx.lovestoblog.com` with **4 queries** confirms active C2 beaconing.

**Beaconing Indicators:**
- ✅ Regular interval DNS lookups to same domain
- ✅ Pattern matches malware heartbeat/callback behaviour
- ✅ Queries originate from single internal host

---

### Step 3 — Compromised Host Identification

**Objective:** Determine which internal endpoint is infected.

```spl
index=phantom_dns "Standard query"
| rex field=Info "A (?<domain>[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})"
| stats count by Source domain
| sort -count
```

**🚨 Infected Host Identified: `10.1.30.101`**

| Host | Role | Behaviour |
|------|------|-----------|
| `10.1.30.101` | **Compromised endpoint** | Initiated all DNS queries to malicious domains |
| `10.1.30.1` | DNS server | Received and forwarded queries |

---

## 🔍 Key Findings

### Indicators of Compromise (IOCs)

**🌐 Network IOCs:**
```
C2 Domain:  scxzswx.lovestoblog.com  →  185.27.134.154
C2 Domain:  exczx.com               →  185.38.151.11
Recon:      icanhazip.com           →  104.16.185.241
```

**🖥️ Host IOCs:**
```
Infected Host:    10.1.30.101
Network Segment:  10.1.30.0/24
DNS Server:       10.1.30.1
```

**🔁 Behavioural IOCs:**
- DNS beaconing — 4 queries to C2 domain
- Public IP discovery via `icanhazip.com`
- Free hosting abuse for disposable C2 domains
- Algorithmically-generated subdomain pattern

---

### Attack Timeline

```
[T+0s]  Host 10.1.30.101 compromised — PhantomStealer deployed
         ↓
[T+1s]  DNS query: icanhazip.com → discovers public IP (reconnaissance)
         ↓
[T+2s]  DNS query #1: scxzswx.lovestoblog.com → C2 resolution attempt
         ↓
[T+3s]  DNS query #2: exczx.com → secondary C2 resolution
         ↓
[T+4s]  DNS query #3,#4: scxzswx.lovestoblog.com → beaconing confirmed
         ↓
[T+5s]  C2 channel established → proceeds to HTTP contact (Project 2)
```

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|----|----|
| Discovery | System Network Configuration Discovery | [T1016](https://attack.mitre.org/techniques/T1016/) | `icanhazip.com` public IP lookup |
| Command & Control | Application Layer Protocol: DNS | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | Repeated DNS queries confirming C2 beaconing |

---

## 🛡️ Recommendations

### Immediate Response

```
1. CONTAIN   →  Isolate 10.1.30.101 from network immediately
               Disable network adapters, preserve memory dump

2. BLOCK     →  Firewall: 185.27.134.154, 185.38.151.11
               DNS Sinkhole: scxzswx.lovestoblog.com, exczx.com
               Restrict internal access to icanhazip.com

3. HUNT      →  Check all hosts in 10.1.30.0/24 for similar DNS patterns
               Review authentication logs for credential abuse
               Search for lateral movement indicators
```

### Detection Rules

**Alert: DNS Beaconing (>3 queries to same domain)**
```spl
index=dns_logs earliest=-1h
| rex field=query "(?<domain>[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})"
| stats count by src_ip domain
| where count > 3
| eval alert_type="DNS_BEACONING"
| table _time src_ip domain count alert_type
```

**Alert: Public IP Discovery**
```spl
index=dns_logs
| where domain IN ("icanhazip.com", "ipinfo.io", "api.ipify.org", "checkip.amazonaws.com")
| stats count by src_ip domain
| eval alert_type="EXTERNAL_IP_LOOKUP"
```

**Alert: Suspicious TLD Queries**
```spl
index=dns_logs
| rex field=query "\.(?<tld>[a-z]{2,})$"
| where tld IN ("xyz", "top", "ru", "cn", "tk", "ml", "ga")
| stats count by src_ip query tld
```

---

## 📊 Skills Demonstrated

| Skill | Application |
|-------|-------------|
| SPL Query Development | Custom regex extraction, stats, field analysis |
| Regex Field Extraction | Manual parsing from raw Wireshark CSV |
| DNS Protocol Analysis | Beaconing pattern detection |
| IOC Development | C2 domains, IPs, behavioural indicators |
| MITRE ATT&CK Mapping | T1016, T1071.004 |
| Threat Hunting | Frequency analysis, beaconing detection |

---

## 🔗 Related Projects

| Project | Focus | Link |
|---------|-------|------|
| **Project 2** | HTTP C2 Communication | [→ HTTP Analysis](../Project-02-PhantomStealer-HTTP-Analysis/) |
| **Project 3** | TLS Encrypted C2 Channels | [→ TLS Analysis](../Project-03-PhantomStealer-TLS-Analysis/) |
| **All Queries** | Full SPL query reference | [→ Splunk Queries](./splunk-queries-dns.md) |

---

## 📚 References

- [Malware Traffic Analysis — PhantomStealer Exercise](https://www.malware-traffic-analysis.net/)
- [MITRE ATT&CK — T1071.004](https://attack.mitre.org/techniques/T1071/004/)
- [Splunk Documentation](https://docs.splunk.com/)
- [SANS DNS Tunneling Detection](https://www.sans.org/white-papers/)

---

<div align="center">

**Project Date:** February 2026 · **Platform:** Splunk Enterprise · **Part:** 1 of 3

[← Back to Portfolio](../README.md) · [Next: HTTP Analysis →](../Project-02-PhantomStealer-HTTP-Analysis/)

</div>
