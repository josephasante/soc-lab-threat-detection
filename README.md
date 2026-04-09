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
- Attacker IP: 192.168.1.132
- Victim IP: 192.168.1.135
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
