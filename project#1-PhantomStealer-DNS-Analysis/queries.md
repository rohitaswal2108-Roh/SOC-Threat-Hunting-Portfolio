# Splunk Queries - PhantomStealer DNS Analysis

This document contains all SPL (Search Processing Language) queries used in the PhantomStealer DNS traffic analysis project.

---

## Table of Contents
1. [Data Verification Queries](#data-verification-queries)
2. [Field Extraction Queries](#field-extraction-queries)
3. [Threat Hunting Queries](#threat-hunting-queries)
4. [Detection & Analysis Queries](#detection--analysis-queries)
5. [Advanced Analysis Queries](#advanced-analysis-queries)

---

## Data Verification Queries

### 1. View All Ingested Data
**Purpose:** Verify data ingestion and view raw events
```spl
index=phantom_dns
```

**Expected Output:** All DNS events from the phantom_dns index

---

### 2. Count Total Events
**Purpose:** Get total number of DNS events analyzed
```spl
index=phantom_dns
| stats count
```

**Expected Output:** Total event count (e.g., 10 events)

---

### 3. Display Data in Table Format
**Purpose:** View parsed fields in structured table
```spl
index=phantom_dns 
| table No Time Source Destination Protocol Length Info
```

**Expected Output:** Clean table with separated columns

---

## Field Extraction Queries

### 4. Verify Field Extraction
**Purpose:** Check if fields are properly extracted
```spl
index=phantom_dns
| table _time Source Destination Info
```

**Expected Output:** Time, source IP, destination IP, and query info

---

### 5. List All Field Names
**Purpose:** Display all available fields
```spl
index=phantom_dns
| fieldsummary
| table field count
```

---

## Threat Hunting Queries

### 6. Domain Frequency Analysis
**Purpose:** Identify most queried domains (key query for C2 detection)
```spl
index=phantom_dns
| rex field=Info "A (?<domain>[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})"
| stats count by domain
| sort -count
```

**Expected Output:**
- scxzswx.lovestoblog.com: 4
- exczx.com: 2
- icanhazip.com: 2
- res.cloudinary.com: 2

**Analysis:** Highest count indicates potential C2 beaconing

---

### 7. Beaconing Detection
**Purpose:** Detect repeated DNS queries (C2 callback pattern)
```spl
index=phantom_dns
| rex field=Info "A (?<domain>[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})"
| stats count by domain
| where count > 1
```

**Expected Output:** Domains queried more than once

**Key Finding:** scxzswx.lovestoblog.com (4 queries) = beaconing behavior

---

### 8. Identify Infected Host
**Purpose:** Determine which internal IP is compromised
```spl
index=phantom_dns "Standard query"
| rex field=Info "A (?<domain>[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})"
| stats count by Source domain
| sort -count
```

**Expected Output:** 10.1.30.101 with highest query count

**Finding:** Internal host 10.1.30.101 = infected machine

---

### 9. Source IP Statistics
**Purpose:** Analyze DNS query patterns by source
```spl
index=phantom_dns 
| stats count by Source
| sort -count
```

**Expected Output:**
- 10.1.30.101: Higher count (infected host)
- 10.1.30.1: Lower count (DNS server responses)

---

## Detection & Analysis Queries

### 10. Top Level Domain (TLD) Analysis
**Purpose:** Identify suspicious TLDs (.xyz, .ru, .top, etc.)
```spl
index=phantom_dns
| rex field=Info "A (?<domain>[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})"
| eval tld=mvindex(split(domain,"."),-1)
| stats count by tld
| sort -count
```

**Red Flag TLDs:**
- .xyz
- .top
- .ru
- .cn
- .tk

---

### 11. Query Type Distribution
**Purpose:** Analyze types of DNS queries (A, AAAA, CNAME, etc.)
```spl
index=phantom_dns
| rex field=Info "query (?<query_type>0x[0-9a-f]+)"
| stats count by query_type
```

---

### 12. DNS Response Analysis
**Purpose:** Identify failed DNS queries (NXDOMAIN = non-existent domain)
```spl
index=phantom_dns "query response"
| rex field=Info "(?<response_code>NOERROR|NXDOMAIN|SERVFAIL)"
| stats count by response_code
```

**Suspicious:** High NXDOMAIN count = malware probing or DGA activity

---

### 13. Timeline of DNS Activity
**Purpose:** Visualize DNS traffic over time
```spl
index=phantom_dns
| timechart count by Protocol
```

**Use Case:** Identify spike patterns or regular intervals (beaconing)

---

### 14. Packet Size Analysis
**Purpose:** Detect DNS tunneling (unusually large DNS packets)
```spl
index=phantom_dns
| stats avg(Length) median(Length) max(Length) by Source
```

**Red Flag:** Packets > 512 bytes may indicate DNS tunneling

---

## Advanced Analysis Queries

### 15. Suspicious Domain Pattern Detection
**Purpose:** Find algorithmically-generated or random-looking domains
```spl
index=phantom_dns
| rex field=Info "A (?<domain>[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})"
| eval domain_length=len(domain)
| stats avg(domain_length) by domain
| sort -avg(domain_length)
```

**Indicator:** Very long or random character domains = DGA malware

---

### 16. External IP Discovery Detection
**Purpose:** Identify malware checking its public IP
```spl
index=phantom_dns
| rex field=Info "A (?<domain>[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})"
| where domain IN ("icanhazip.com", "ipinfo.io", "api.ipify.org", "checkip.amazonaws.com", "ifconfig.me")
| stats count by Source domain
```

**Finding:** 10.1.30.101 queried icanhazip.com = reconnaissance behavior

---

### 17. C2 Communication by Source-Destination Pair
**Purpose:** Map communication patterns between infected host and C2
```spl
index=phantom_dns
| rex field=Info "A (?<domain>[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})"
| stats count by Source Destination domain
| sort -count
```

---

### 18. Time-Based Beaconing Pattern
**Purpose:** Detect regular interval queries (heartbeat pattern)
```spl
index=phantom_dns
| rex field=Info "A (?<domain>[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})"
| where domain="scxzswx.lovestoblog.com"
| table _time Source domain
```

**Analysis:** Regular time intervals = automated malware beacon

---

### 19. Unique Domains by Source
**Purpose:** Count how many unique domains each host contacted
```spl
index=phantom_dns
| rex field=Info "A (?<domain>[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})"
| stats dc(domain) as unique_domains by Source
| sort -unique_domains
```

**Red Flag:** Single host contacting many random domains = scanning/DGA

---

### 20. Full Investigation Summary
**Purpose:** Combined query for comprehensive analysis
```spl
index=phantom_dns
| rex field=Info "A (?<domain>[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})"
| stats count dc(domain) as unique_domains by Source
| sort -count
| eval risk_score=if(count>3 AND unique_domains>2, "HIGH", if(count>2, "MEDIUM", "LOW"))
| table Source count unique_domains risk_score
```

---

## Detection Rules for Production

### Alert Rule 1: DNS Beaconing Detection
**Trigger:** More than 3 queries to same domain within 1 hour
```spl
index=dns_logs earliest=-1h
| rex field=query "(?<domain>[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})"
| stats count by src_ip domain
| where count > 3
| eval alert_type="DNS_BEACONING"
| table _time src_ip domain count alert_type
```

---

### Alert Rule 2: Public IP Lookup Detection
**Trigger:** Any internal host checking public IP
```spl
index=dns_logs
| rex field=query "(?<domain>[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})"
| where domain IN ("icanhazip.com", "ipinfo.io", "api.ipify.org", "checkip.amazonaws.com")
| stats count by src_ip domain
| eval alert_type="EXTERNAL_IP_LOOKUP"
| table _time src_ip domain count alert_type
```

---

### Alert Rule 3: Suspicious TLD Detection
**Trigger:** Queries to high-risk TLDs
```spl
index=dns_logs
| rex field=query "\.(?<tld>[a-z]{2,})$"
| where tld IN ("xyz", "top", "ru", "cn", "tk", "ml", "ga", "cf", "gq")
| stats count by src_ip query tld
| eval alert_type="SUSPICIOUS_TLD"
| table _time src_ip query tld count alert_type
```

---

## Notes

- All queries use the `phantom_dns` index
- Replace with your actual index name in production
- Regex patterns extract domains from the Info field
- Adjust thresholds based on your environment baseline
- Combine multiple queries for comprehensive threat hunting

---

**Last Updated:** February 2026  
**Analyst:** Rohit Aswal
