# SOC Detection Lab

## Overview
This project demonstrates hands-on experience in detecting and analyzing cyber threats using real-world scenarios.

## Tools Used
- Security Onion
- Zeek
- Suricata
- Wireshark
- Elasticsearch / Kibana

## Lab Scenarios
- Brute Force Attack Detection
- Lateral Movement Detection
- Data Exfiltration Analysis

## Sample Detection Query
event.dataset:zeek.conn AND NOT tcp.state:"SF"
