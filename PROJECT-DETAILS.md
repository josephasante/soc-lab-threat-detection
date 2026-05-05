# SOC Lab – Threat Detection & Network Monitoring

A hands-on Security Operations Center (SOC) lab demonstrating real-world detection, analysis, and incident response workflows using network telemetry and packet analysis.

---

# 🔍 Overview
This project simulates realistic cyber attack scenarios in a controlled lab environment. It demonstrates how a SOC analyst detects, investigates, and responds to threats using industry tools.

### Core Skills Demonstrated
- Alert triage and investigation
- Network traffic analysis (PCAP)
- IOC extraction and validation
- Threat hunting using logs
- Detection engineering (custom rules)
- Incident documentation and reporting

---

# 🧱 Lab Architecture
```
            +---------------------------+
            |     Security Onion        |
            | SIEM / IDS / PCAP Engine  |
            +-------------+-------------+
                          |
        ----------------------------------------
        |                                      |
+---------------+                     +------------------+
|   Kali Linux  |                     | Metasploitable 2 |
|   Attacker    |                     |     Victim       |
+---------------+                     +------------------+
```

---

# 🧰 Tools Used
| Tool | Purpose |
|------|--------|
| Security Onion | SIEM, IDS/IPS, log analysis |
| Zeek | Network metadata analysis |
| Suricata | Signature-based detection |
| Wireshark | Packet-level investigation |
| NetworkMiner | File and artifact extraction |

---

# 🚨 Attack Scenarios

## 1. Reverse Shell (Command & Control)
- Outbound connection from victim to attacker
- Long-lived TCP sessions
- Uncommon ports (4444, 3632)

**Detection:**
- Suricata alerts
- Zeek `conn.log` (long duration + unusual ports)

---

## 2. HTTP Data Exfiltration
- Unauthorized file transfer via HTTP POST
- Large outbound payloads

**Detection:**
- Zeek `http.log`
- PCAP validation in Wireshark

---

## 3. DNS Tunneling
- High-entropy DNS queries
- Repeated subdomain patterns

**Detection:**
- Zeek `dns.log`
- Custom Suricata rules

---

# 🔄 Attack Workflow

1. **Reconnaissance**
   - Network scanning
   - Service discovery
   - Suricata scan alerts

2. **Exploitation**
   - Access vulnerable services
   - Abnormal SMB/FTP activity

3. **Command & Control**
   - Reverse shell callbacks
   - Persistent outbound connections

4. **Data Exfiltration**
   - HTTP POST transfers
   - DNS tunneling

---

# 🔍 Detection Methodology

## Reverse Shell Indicators
- Outbound traffic to uncommon ports
- Long session duration
- Minimal inbound response

## DNS Tunneling Indicators
- Long/random domain names
- High query volume
- Repeated patterns

## Exfiltration Indicators
- Large outbound data volume
- One-direction traffic dominance

---

# 🧪 PCAP Analysis Workflow (Wireshark)

1. Identify suspicious IPs
2. Filter traffic:
   ```
   ip.addr == <suspicious_ip>
   ```
3. Analyze packet size:
   - Large outbound packets → possible exfiltration
4. Follow TCP stream
5. Check timing patterns (beaconing)

---

# 📊 Threat Hunting Workflow

1. Start with alert (Suricata)
2. Pivot to Zeek logs
3. Identify abnormal patterns
4. Validate with PCAP
5. Extract IOCs
6. Document findings

---

# 🧾 Indicators of Compromise (IOCs)

| Type | Value |
|------|------|
| Attacker IP | 192.168.207.133 |
| Victim IP | 192.168.207.136 |
| Suspicious Ports | 4444, 3632, 8080 |

---

# 🛠️ Detection Engineering (Suricata)

### Reverse Shell Detection
```
alert tcp any any -> any 4444 (msg:"Reverse Shell Activity"; sid:1000001;)
```

### EXE Download Detection
```
alert http any any -> any any (msg:"EXE Download"; content:".exe"; http_uri; sid:1000002;)
```

### DNS Tunneling Detection
```
alert dns any any -> any any (msg:"Suspicious DNS Query"; pcre:"/[A-Za-z0-9]{20,}/"; sid:1000003;)
```

---

# 📌 MITRE ATT&CK Mapping

| Technique | Description |
|----------|------------|
| T1046 | Network Scanning |
| T1059 | Command Execution |
| T1071.001 | Web Protocol (HTTP) |
| T1071.004 | DNS Communication |
| T1041 | Data Exfiltration |
| T1105 | Tool Transfer |

---

# 🧠 SOC Analyst Workflow

```
Alert → Hunt → Log Analysis → PCAP → IOC → Report
```

---

# 🧾 Incident Report Summary (Example)

**Summary:**
Suspicious outbound traffic detected from internal host.

**Findings:**
- Reverse shell activity observed
- Persistent outbound connections
- Data exfiltration via HTTP

**IOCs:**
- IP addresses
- Ports
- Protocols

**Action Taken:**
- Traffic analyzed
- Host flagged
- Indicators documented

---

# 🚀 How to Reproduce

1. Install Security Onion (Standalone)
2. Deploy Kali Linux and Metasploitable
3. Configure same internal network
4. Generate attack traffic
5. Analyze using SOC tools

---

# 🎯 Key Takeaways

- Demonstrates real SOC workflows
- Shows practical detection and analysis skills
- Includes PCAP-level investigation
- Covers detection engineering and reporting

---

# 👤 Author
Joseph Asante

