# Splunk Queries - HTTP Traffic Analysis

All SPL queries used in PhantomStealer HTTP traffic analysis.

---

## Data Verification

### 1. View All HTTP Events
```spl
index=phantom_http
```

### 2. Table View
```spl
index=phantom_http 
| table Time Source Destination Info
```

---

## Analysis Queries

### 3. Source & Destination Analysis
```spl
index=phantom_http
| stats count by Source Destination
```

### 4. Extract Downloaded Files
```spl
index=phantom_http
| rex field=Info "GET (?<filename>/[^\s]+)"
| where isnotnull(filename)
| table Time Source Destination filename
```

### 5. HTTP Methods Distribution
```spl
index=phantom_http
| rex field=Info "^(?<http_method>GET|POST|HTTP)"
| stats count by http_method
```

### 6. Attack Timeline
```spl
index=phantom_http
| timechart count
```

### 7. Packet Size Analysis
```spl
index=phantom_http
| stats count avg(Length) max(Length) by Source Destination
| sort -count
```

### 8. C2 Communication Detection
```spl
index=phantom_http
| eval C2_Server="185.27.134.154 (scxzswx.lovestoblog.com)"
| where Destination="185.27.134.154"
| table Time Source Destination Info C2_Server
```

### 9. Public IP Discovery Detection
```spl
index=phantom_http
| where Destination="104.16.185.241"
| eval Service="icanhazip.com (Public IP Discovery)"
| table Time Source Destination Service Info
```

### 10. Correlate with DNS Analysis
```spl
index=phantom_http
| eval DNS_Finding="C2 Domain: scxzswx.lovestoblog.com (from Project 1)"
| table Time Source Destination Info DNS_Finding
```

---

**Analysis Date:** February 2026  
**Analyst:** Rohit Aswal
```
