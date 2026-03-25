<div align="center">

```
████████╗██╗     ███████╗
╚══██╔══╝██║     ██╔════╝
   ██║   ██║     ███████╗
   ██║   ██║     ╚════██║
   ██║   ███████╗███████║
   ╚═╝   ╚══════╝╚══════╝

E N C R Y P T E D   C 2   C H A N N E L   D E T E C T I O N
```

# 📌 Project 3 — TLS/SSL Traffic Analysis
## Encrypted C2 Channel Detection using SNI Extraction

[![Back to Portfolio](https://img.shields.io/badge/←%20Back-Main%20Portfolio-181717?style=flat-square&logo=github)](../README.md)
[![Protocol](https://img.shields.io/badge/Protocol-TLS%20%2F%20SSL-red?style=flat-square)]()
[![MITRE](https://img.shields.io/badge/MITRE-T1573-orange?style=flat-square)](https://attack.mitre.org/techniques/T1573/)
[![Tool](https://img.shields.io/badge/Tool-Splunk%20Enterprise-black?style=flat-square&logo=splunk&logoColor=green)]()
[![Events](https://img.shields.io/badge/Events%20Analysed-223-blue?style=flat-square)]()
[![Status](https://img.shields.io/badge/Status-Complete-brightgreen?style=flat-square)]()

</div>

---

## 📋 Objective

Analyse encrypted TLS/SSL traffic from the PhantomStealer infection to **identify encrypted C2 channels**, **extract Server Name Indication (SNI) data** for domain identification, and **complete the multi-layer investigation** — connecting DNS, HTTP, and TLS into a single unified attack chain.

---

## 🧰 Tools & Dataset

| Category | Detail |
|----------|--------|
| **SIEM** | Splunk Enterprise |
| **Capture Tool** | Wireshark (filter: `tls \|\| ssl`) |
| **Analysis OS** | Kali Linux (isolated VM) |
| **Dataset** | Same PCAP as Projects 1 & 2 — `2026-01-30-PhantomStealer-infection.pcap` |
| **Events Analysed** | **223 TLS events** |
| **Splunk Index** | `phantom_tls` |

---

## 🔗 Connection to Projects 1 & 2

> **This project completes the three-layer investigation.** The domain `exczx.com` — first detected in DNS queries (Project 1) and then via HTTP traffic to its resolved IP (Project 2) — is now confirmed to also have an encrypted HTTPS channel, detected via SNI extraction.

```
Project 1 (DNS):  exczx.com queried 2 times → resolved to 185.38.151.11
Project 2 (HTTP): HTTP GET requests to 185.38.151.11
Project 3 (TLS):  TLS Client Hello → SNI: exczx.com ← CONFIRMED ✅

Full C2 channel documented across all three protocol layers.
```

---

## 🔄 Investigation Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                     INVESTIGATION PIPELINE                      │
│                                                                 │
│  [1] Open PCAP  →  [2] Filter: tls||ssl  →  [3] Export CSV    │
│                                                    ↓            │
│  [7] Full chain  ←  [6] SNI Extract   ←  [4] Ingest Splunk    │
│  correlated           C2 confirmed        ↓                     │
│       ↓                              [5] TLS handshake         │
│  [8] MITRE map + IOCs + detection rules   analysis             │
└─────────────────────────────────────────────────────────────────┘
```

### Phase 1 — TLS Traffic Extraction

Applied Wireshark display filter:
```
tls || ssl
```

- Identified **223 TLS/SSL events**
- Exported as CSV: `tls_logs.csv`
- Transferred to Windows Splunk host

### Phase 2 — Splunk Ingestion

```
Settings → Indexes → New Index → Name: phantom_tls
Settings → Add Data → Upload → tls_logs.csv
Source Type: csv | Index: phantom_tls
```

✅ **223 events successfully indexed**

---

## 🔬 Threat Hunting Analysis

### Step 1 — TLS Traffic Overview

```spl
index=phantom_tls 
| table Time Source Destination Info
```

**Findings:**
- 223 TLS events from `10.1.30.101` (same infected host throughout all three projects)
- Multiple TLS handshakes to different destinations
- Significant volume of `Application Data` (encrypted payloads)

---

### Step 2 — TLS Handshake Phase Analysis

```spl
index=phantom_tls
| eval phase=case(
    match(Info, "Client Hello"), "Client Hello",
    match(Info, "Server Hello"), "Server Hello",
    match(Info, "Change Cipher Spec"), "Change Cipher Spec",
    match(Info, "Application Data"), "Application Data",
    1=1, "Other"
)
| stats count by phase
| sort -count
```

**TLS Session Breakdown:**

| Phase | Role | Significance |
|-------|------|-------------|
| `Client Hello` | Initiates connection, exposes SNI | 🔑 **Key for detection** — SNI visible here |
| `Server Hello` | Server responds with certificate | Certificate analysis possible |
| `Change Cipher Spec` | Encryption activated | Post-this: traffic is fully encrypted |
| `Application Data` | Encrypted payload exchange | C2 commands/exfiltration happen here |

> **Analyst Note:** Even without decrypting TLS, the `Client Hello` packet contains the **Server Name Indication (SNI)** field in plaintext — this is how we identify malicious domains in encrypted traffic.

---

### Step 3 — SNI Extraction 🔥

**Objective:** Extract domain names from TLS Client Hello packets — the critical technique for encrypted traffic investigation.

```spl
index=phantom_tls "Client Hello"
| rex field=Info "SNI=(?<domain>[^\)]+)"
| where isnotnull(domain)
| stats count by domain
| sort -count
```

**🚨 Critical Findings:**

| Domain (SNI) | Count | Assessment |
|-------------|-------|------------|
| `exczx.com` | multiple | 🔴 **MALICIOUS C2** — Confirmed across DNS + HTTP + TLS |
| `res.cloudinary.com` | multiple | 🟡 **INVESTIGATE** — CDN service potentially abused |

**`exczx.com` Three-Protocol Confirmation:**

```
DNS  (Project 1): 2 DNS queries detected → resolved to 185.38.151.11
HTTP (Project 2): HTTP GET requests to resolved IP
TLS  (Project 3): HTTPS Client Hello with SNI=exczx.com ← THIS QUERY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONCLUSION: exczx.com confirmed as C2 across all three protocol layers ✅
```

> **Why SNI Matters:** Encryption hides payload content but **not the destination hostname**. SNI extraction is a critical SOC technique — it allows analysts to identify malicious connections even when traffic is fully encrypted, with no decryption required.

---

### Step 4 — Source & Destination Analysis

```spl
index=phantom_tls
| stats count by Source Destination
| sort -count
```

**Findings:**
- All TLS traffic originates from `10.1.30.101` — consistent across all three projects
- Multiple destination IPs contacted via HTTPS, including C2 and CDN infrastructure

---

### Step 5 — Malicious Domain TLS Session

```spl
index=phantom_tls 
| search Info="*exczx.com*"
| table Time Source Destination Info
```

**Session Analysis:**

```
Client Hello     →  SNI=exczx.com exposed in plaintext
Server Hello     ←  Server certificate returned
Change Cipher    →  Encryption now active
Application Data ↔  Encrypted C2 commands and responses
                    ↳ Cannot inspect without key, but volume/timing reveals pattern
```

**Evasion Technique Identified:** PhantomStealer uses HTTPS to make C2 traffic blend with legitimate encrypted web traffic — standard network inspection would miss this without SNI analysis.

---

### Step 6 — CDN Traffic Analysis

```spl
index=phantom_tls
| search Info="*cloudinary*"
| table Time Source Destination Info
```

**Assessment:**
- TLS connections to `res.cloudinary.com` detected
- Cloudinary is a legitimate CDN — but malware commonly abuses CDNs to host payloads
- **Recommendation:** Correlate with HTTP logs to check for any payload downloads from Cloudinary domains
- Status: **Requires further investigation** — outside scope of this sample

---

### Step 7 — Encrypted Traffic Volume Analysis

```spl
index=phantom_tls "Application Data"
| stats count as encrypted_packets by Source Destination
| sort -encrypted_packets
```

```spl
index=phantom_tls
| stats sum(Length) as total_bytes count by Source Destination
| eval total_kb=round(total_bytes/1024,2)
| table Source Destination count total_kb
| sort -total_kb
```

**Interpretation Guide:**

| Packet Pattern | Likely Activity |
|---------------|----------------|
| Small, frequent packets | C2 heartbeat / commands received |
| Large single packets | Payload download or data exfiltration |
| Bursty with quiet periods | Active C2 sessions with idle intervals |

---

### Step 8 — Complete Attack Chain Query

```spl
index=phantom_tls "Client Hello"
| rex field=Info "SNI=(?<domain>[^\)]+)"
| where domain="exczx.com"
| eval Project_1_DNS="DNS queries to exczx.com (2 queries detected)"
| eval Project_2_HTTP="HTTP to 185.38.151.11 (exczx.com resolved IP)"
| eval Project_3_TLS="TLS encrypted connection to exczx.com (SNI confirmed)"
| eval Complete_Chain="DNS → HTTP → TLS — same C2 infrastructure"
| table Time Source Destination domain Project_1_DNS Project_2_HTTP Project_3_TLS Complete_Chain
```

---

## 🔍 Key Findings

### Multi-Protocol C2 Infrastructure — Complete Picture

| Protocol | Project | Detection Method | Evidence |
|----------|---------|----------------|---------|
| **DNS** | 1 | Query frequency analysis | 2 queries to `exczx.com` |
| **HTTP** | 2 | HTTP session analysis | GET requests to `185.38.151.11` |
| **TLS** | 3 | SNI extraction | Client Hello → `SNI=exczx.com` |

**Conclusion:** PhantomStealer operates **dual C2 channels** — unencrypted HTTP for config download and encrypted HTTPS for command execution — providing both functionality and stealth.

---

### Indicators of Compromise (IOCs)

**🌐 Network IOCs:**
```
C2 Domain:    exczx.com                  (confirmed: DNS + HTTP + TLS)
C2 IP:        185.38.151.11
CDN:          res.cloudinary.com         (investigate further)
```

**🖥️ Host IOCs:**
```
Infected Host: 10.1.30.101              (consistent across all 3 projects)
```

**🔐 Encrypted Channel IOCs:**
```
TLS Client Hello to exczx.com
SNI pattern: exczx.com in Client Hello
223 TLS events from compromised host
Application Data to C2 server
```

**🔁 Behavioural IOCs:**
- Multi-protocol C2 (DNS + HTTP + TLS) — redundant channels
- SNI-based domain evasion — blending with HTTPS traffic
- CDN service access (potential payload hosting)
- Consistent source host across all three investigation layers

---

### Complete 3-Project Attack Chain

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 1 — RECONNAISSANCE & C2 DISCOVERY    [Project 1 — DNS]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  DNS: icanhazip.com → public IP discovered
  DNS: scxzswx.lovestoblog.com (4 queries) → C2 beaconing
  DNS: exczx.com (2 queries) → secondary C2 resolution

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 2 — UNENCRYPTED C2 COMMUNICATION     [Project 2 — HTTP]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  HTTP GET: 185.27.134.154 → /arquivo_20260129190534.txt [200 OK]
  HTTP GET: 185.27.134.154 → /arquivo_20260129190545.txt [200 OK]
  Config files downloaded, malware receives updated instructions

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 3 — ENCRYPTED C2 CHANNEL             [Project 3 — TLS]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  TLS Client Hello → SNI=exczx.com
  TLS handshake completes → encryption active
  Application Data ↔ encrypted C2 commands and responses
  CDN connections → potential additional payload staging

RESULT: Multi-layered, redundant C2 using both HTTP and HTTPS
        Dual-channel design provides stealth AND reliability
```

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|----|----|
| Command & Control | Encrypted Channel | [T1573](https://attack.mitre.org/techniques/T1573/) | TLS HTTPS connection to `exczx.com` confirmed via SNI |
| Command & Control | Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | HTTPS used as C2 transport layer |

**Full Portfolio MITRE Coverage (all 3 projects combined):**

| ID | Technique | Project |
|----|-----------|---------|
| T1016 | System Network Configuration Discovery | 1, 2 |
| T1071.004 | App Layer Protocol: DNS | 1 |
| T1071.001 | App Layer Protocol: Web | 2, 3 |
| T1105 | Ingress Tool Transfer | 2 |
| T1102 | Web Service | 2 |
| T1573 | Encrypted Channel | 3 |

---

## 🛡️ Recommendations

### Immediate Response

```
1. BLOCK     →  All traffic to exczx.com (DNS, HTTP, HTTPS)
               Block IP 185.38.151.11 at perimeter firewall
               SNI-based filter for exczx.com in SSL inspection proxy

2. INSPECT   →  Deploy SSL/TLS inspection gateway
               Decrypt HTTPS traffic to unknown/untrusted domains
               Monitor all TLS Client Hello SNI fields

3. CONTAIN   →  Full forensic analysis of 10.1.30.101
               Review all TLS certificate stores on infected host
               Check for persistence mechanisms installed post-C2 contact
```

### Detection Rules

**Alert: SNI-Based C2 Detection**
```spl
index=tls_logs "Client Hello"
| rex field=sni "(?<domain>[a-zA-Z0-9\.-]+)"
| where domain IN ("exczx.com", "scxzswx.lovestoblog.com")
| stats count by src_ip domain
| where count > 0
```

**Alert: High-Volume Encrypted Traffic to Unknown Destinations**
```spl
index=tls_logs "Application Data"
| stats sum(bytes) as total_bytes by src_ip dest_ip
| where total_bytes > 100000
| eval alert="High volume encrypted traffic — investigate"
```

**Alert: TLS to Suspicious TLDs**
```spl
index=tls_logs "Client Hello"
| rex field=sni "\.(?<tld>[a-z]{2,})$"
| where tld IN ("xyz", "top", "tk", "ml", "ga")
| stats count by src_ip sni tld
```

### Long-Term Improvements

| Priority | Improvement | Benefit |
|----------|-------------|---------|
| 🔴 High | Deploy SSL/TLS inspection proxy | Decrypt and inspect HTTPS C2 channels |
| 🔴 High | SNI-based domain filtering at firewall | Block encrypted C2 without decryption |
| 🟡 Medium | Integrate TLS threat intelligence feeds | Automatic SNI reputation scoring |
| 🟡 Medium | Correlate DNS + HTTP + TLS logs automatically | Detect multi-protocol C2 infrastructure |
| 🟢 Standard | Baseline normal encrypted traffic volumes | Alert on deviations indicating C2 |

---

## 📊 Why This Analysis Matters

| Value | Detail |
|-------|--------|
| **Depth** | Not just surface detection — full investigation across DNS, HTTP, and TLS |
| **Correlation** | Same C2 infrastructure identified independently at three different protocol layers |
| **Real-World Technique** | SNI extraction is a production SOC skill — works without key material or decryption |
| **Completeness** | Three connected projects form a full incident response narrative |

---

## 🔗 Related Projects

| Project | Focus | Link |
|---------|-------|------|
| **Project 1** | DNS Beaconing Detection | [→ DNS Analysis](../Project-01-PhantomStealer-DNS-Analysis/) |
| **Project 2** | HTTP C2 Communication | [→ HTTP Analysis](../Project-02-PhantomStealer-HTTP-Analysis/) |
| **All Queries** | Full SPL query reference | [→ Splunk Queries](./splunk-queries-tls.md) |

---

## 📚 References

- [Project 1 — DNS Analysis](../Project-01-PhantomStealer-DNS-Analysis/)
- [Project 2 — HTTP Analysis](../Project-02-PhantomStealer-HTTP-Analysis/)
- [MITRE ATT&CK — T1573](https://attack.mitre.org/techniques/T1573/)
- [TLS 1.3 RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446)
- [Splunk TLS Analysis Guide](https://docs.splunk.com/)

---

<div align="center">

**Project Date:** February 2026 · **Platform:** Splunk Enterprise · **Part:** 3 of 3

[← Project 2: HTTP](../Project-02-PhantomStealer-HTTP-Analysis/) · [Back to Portfolio](../README.md)

*Investigation Complete — DNS → HTTP → TLS attack chain fully reconstructed* ✅

</div>
