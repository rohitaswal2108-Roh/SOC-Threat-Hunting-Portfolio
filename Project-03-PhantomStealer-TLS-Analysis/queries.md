# Splunk Queries - TLS/SSL Traffic Analysis

All SPL queries used in PhantomStealer TLS/SSL encrypted traffic analysis.

---

## Data Verification

### 1. View All TLS Events
```spl
index=phantom_tls
```

### 2. TLS Traffic Overview
```spl
index=phantom_tls 
| table Time Source Destination Info
```

---

## TLS Analysis Queries

### 3. TLS Handshake Phase Distribution
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

### 4. Extract Server Names (SNI)
```spl
index=phantom_tls "Client Hello"
| rex field=Info "SNI=(?<domain>[^\)]+)"
| where isnotnull(domain)
| stats count by domain
| sort -count
```

### 5. Source & Destination Analysis
```spl
index=phantom_tls
| stats count by Source Destination
| sort -count
```

### 6. Malicious Domain TLS Activity
```spl
index=phantom_tls 
| search Info="*exczx.com*"
| table Time Source Destination Info
```

### 7. CDN Traffic Analysis
```spl
index=phantom_tls
| search Info="*cloudinary*"
| table Time Source Destination Info
```

### 8. Encrypted Traffic Volume
```spl
index=phantom_tls "Application Data"
| stats count as encrypted_packets by Source Destination
| sort -encrypted_packets
```

### 9. Data Volume Analysis
```spl
index=phantom_tls
| stats sum(Length) as total_bytes count by Source Destination
| eval total_kb=round(total_bytes/1024,2)
| table Source Destination count total_kb
| sort -total_kb
```

### 10. TLS Timeline
```spl
index=phantom_tls
| timechart count
```

### 11. Complete Attack Chain
```spl
index=phantom_tls "Client Hello"
| rex field=Info "SNI=(?<domain>[^\)]+)"
| where domain="exczx.com"
| eval Project_1_DNS="DNS queries to exczx.com"
| eval Project_2_HTTP="HTTP to 185.38.151.11"
| eval Project_3_TLS="TLS encrypted connection"
| table Time Source Destination domain Project_1_DNS Project_2_HTTP Project_3_TLS
```

---

## Detection Rules

### 12. SNI-Based C2 Detection
```spl
index=tls_logs "Client Hello"
| rex field=sni "(?<domain>[a-zA-Z0-9\.-]+)"
| where domain IN ("exczx.com", "scxzswx.lovestoblog.com")
| stats count by src_ip domain
```

### 13. High Volume Encrypted Traffic
```spl
index=tls_logs "Application Data"
| stats sum(bytes) as total_bytes by src_ip dest_ip
| where total_bytes > 100000
```

### 14. Suspicious TLD Detection
```spl
index=tls_logs "Client Hello"
| rex field=sni "\.(?<tld>[a-z]{2,})$"
| where tld IN ("xyz", "top", "tk", "ml")
| stats count by src_ip sni tld
```

---

**Analysis Date:** February 2026  
**Analyst:** Rohit Aswal

8. Commit message:
```
   Add TLS analysis screenshots
