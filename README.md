# SOC Lab – Threat Detection & Network Monitoring

## Overview
This project demonstrates hands-on SOC lab work focused on detecting malicious activity through network traffic analysis, IDS/IPS monitoring, and threat hunting.

The lab simulates real-world attacks in a controlled environment and documents the detection process using Security Onion, Zeek, Suricata,NetworkMiner and Wireshark.

## Lab Environment
- Security Onion (SIEM / IDS / IPS)
- Kali Linux (Attacker)
- Metasploitable 2 (Victim)

## Simulated Attack Scenarios
- Reverse shell exploitation
- HTTP data exfiltration
- DNS tunneling

## Attack Summary
### 1. Reconnaissance
- Performed network scanning to identify open ports and vulnerable services.

### 2. Exploitation
- Used Metasploit to exploit a vulnerable service on the target machine.

### 3. Command & Control
- Observed reverse shell activity through outbound connections to an attacker-controlled host.

### 4. Data Exfiltration
- Simulated file transfer over HTTP and suspicious DNS traffic to represent exfiltration techniques.

## Detection & Analysis
- Identified reverse shell behavior by analyzing unusual outbound connections and long-lived sessions.
- Detected suspicious DNS activity through Zeek logs and query patterns.
- Reviewed PCAP files in Wireshark to confirm attack behavior.
- Created custom Suricata rules to support detection.

## Indicators of Compromise (IOCs)
- Attacker IP: 192.168.207.133
- Victim IP: 192.168.207.136
- Suspicious Ports: 3632, 4444, 8080

## Project Artifacts
- [PCAP Files](pcaps/)
- [Detection Rules](detection-rules/suricata.rules)
- [Incident Report](reports/soc-incident-report.pdf)
- [Screenshots](screenshots/)
- [Threat Hunting Playbook](playbooks/threat-hunting-playbook.md)

## Skills Demonstrated
- Threat Hunting
- Network Traffic Analysis
- IDS/IPS Monitoring
- Log Correlation
- Incident Response
- PCAP Analysis
- Detection Rule Writing

## Tools Used
- Security Onion
- Zeek
- Suricata
- Wireshark
- NetworkMiner
- Kali Linux
- Metasploit
- Nmap

## Author
Joseph Asante

## SOC Lab – Threat Detection & Network Monitoring
- A hands‑on SOC project demonstrating real‑world detection, analysis, and incident response workflows.
- Overview
- This project showcases a fully built SOC lab designed to detect malicious activity through network traffic analysis, IDS/IPS monitoring, and threat hunting. The environment simulates realistic attack scenarios and documents how each activity is detected, analyzed, and validated using:
Security Onion (SIEM / IDS / IPS)
Zeek (Network metadata)
Suricata (Signature‑based detection)
Wireshark (Packet analysis)
NetworkMiner (Forensic extraction)
The goal is to demonstrate practical SOC analyst skills: alert triage, PCAP analysis, IOC extraction, detection engineering, and incident documentation.
Architecture Diagram
Code
                +---------------------------+
                 |      Security Onion       |
                 |  SIEM / IDS / IPS / PCAP  |
                 +-------------+-------------+
                               |
                               |
                ---------------------------------
                |                               |
        +-------+--------+              +--------+--------+
        |    Kali Linux  |              |  Metasploitable |
        |   (Attacker)   |              |    (Victim)     |
        +----------------+              +------------------+

Lab Environment
Component
Purpose
Security Onion
SIEM, IDS/IPS, log aggregation, alerting
Kali Linux
Generates controlled malicious traffic
Metasploitable 2
Vulnerable target for attack simulation
NetworkMiner
Forensic artifact extraction
Wireshark
Packet analysis and protocol inspection

Simulated Attack Scenarios
1. Reverse Shell Activity
Outbound callbacks from victim → attacker
Long‑lived TCP sessions
Unusual port usage (4444, 3632)
Detected via Suricata + Zeek conn.log
2. HTTP Data Exfiltration
Unauthorized file transfer via HTTP POST
Large outbound payloads
Confirmed via PCAP + Zeek http.log
3. DNS Tunneling
Encoded DNS queries
High‑entropy domain names
Detected via Zeek dns.log + custom Suricata rules
Attack Workflow Summary
1. Reconnaissance
Network scanning
Service enumeration
Suricata “SCAN” alerts triggered
2. Exploitation
Controlled exploitation of vulnerable services
Observed SMB/FTP anomalies in Zeek logs
3. Command & Control
Reverse shell callbacks
Outbound C2‑like traffic
Long‑duration TCP sessions
4. Data Exfiltration
HTTP POST exfiltration
DNS tunneling
Log correlation across Zeek, Suricata, and PCAPs
Detection & Analysis
Reverse Shell Detection
Outbound connections to uncommon ports
Long‑lived sessions
Suricata alerts + Zeek metadata correlation
DNS Tunneling Detection
High‑entropy queries
Abnormal query lengths
Repeated subdomain patterns
PCAP Analysis
Reconstructed sessions in Wireshark
Extracted files and artifacts using NetworkMiner
Mapped attacker behavior to MITRE ATT&CK
Custom Suricata Rules
Reverse shell detection
Suspicious DNS queries
Unusual outbound traffic patterns
MITRE ATT&CK Mapping
Technique
Description
Evidence in Lab
T1046 – Network Scanning
Reconnaissance
Nmap scans detected by Suricata
T1059 – Command Execution
Reverse shell activity
Outbound callbacks
T1071.001 – Web Protocols
HTTP exfiltration
Large POST requests
T1071.004 – DNS
DNS tunneling
High‑entropy DNS queries
T1041 – Exfiltration Over C2 Channel
Data exfiltration
HTTP + DNS exfiltration
T1105 – Ingress Tool Transfer
Payload transfer
Observed in PCAP metadata

Indicators of Compromise (IOCs)
Type
Value
Attacker IP
192.168.207.133
Victim IP
192.168.1.136
Suspicious Ports
3632, 4444, 8080

Project Artifacts
PCAP Files — Captured traffic from all attack scenarios
Detection Rules — Custom Suricata signatures
Incident Report — Full analysis of attack chain and detection workflow
Screenshots — SOC dashboards, alerts, and packet captures
Threat Hunting Playbook — Step‑by‑step investigation methodology
SOC Playbooks Included
Playbook 1 — Reverse Shell Detection
Identify unusual outbound ports
Correlate Zeek + Suricata
Validate session duration
Extract IOCs
Document findings
Playbook 2 — DNS Tunneling Investigation
Analyze query entropy
Review Zeek dns.log
Identify suspicious domains
Validate with PCAP
Document exfiltration patterns
Playbook 3 — HTTP Exfiltration Analysis
Inspect POST requests
Review payload size
Validate with Wireshark
Extract artifacts
Build incident timeline
Screenshot Gallery (Placeholder Section)
(Add your images here)
Security Onion dashboards
Suricata alerts
Zeek logs
Wireshark packet captures
NetworkMiner artifacts
How to Reproduce This Lab
1. Build the Environment
Install Security Onion (standalone mode)
Deploy Kali Linux
Deploy Metasploitable 2
Place all systems on the same isolated virtual network
2. Generate Traffic
Perform reconnaissance
Trigger controlled exploitation attempts
Generate reverse shell callbacks
Simulate HTTP and DNS exfiltration
3. Collect Evidence
Review Suricata alerts
Analyze Zeek logs
Capture PCAPs
Extract artifacts with NetworkMiner
4. Perform Analysis
Correlate logs across tools
Identify IOCs
Document findings
Map activity to MITRE ATT&CK
Future Improvements
Add ELK Stack integration
Add automated log enrichment
Expand DNS tunneling detection rules
Add machine learning anomaly detection
Add Windows endpoint telemetry (Sysmon)
Add Sigma rule conversions
Key Takeaways for Recruiters
Demonstrates real SOC workflows, not theory
Shows ability to detect, analyze, and document malicious activity
Includes custom detection engineering (Suricata rules)
Shows strong network forensics and PCAP analysis skills
Provides a complete incident response narrative
Proves hands‑on experience with Security Onion, Zeek, Suricata, Wireshark
Shows initiative in building a full lab environment
Author
Joseph Asante


