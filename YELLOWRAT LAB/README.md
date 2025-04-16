# Yellow RAT Lab: Malware Analysis & Investigation

## Overview
This repository contains documentation and findings from a malware investigation conducted for GlobalTech Industries, where abnormal network traffic and search query redirections were detected across multiple workstations. The analysis focuses on the "Yellow Cockatoo" malware (also known as SolarMarker), a sophisticated remote access trojan.

## Incident Summary
During a routine IT security check at GlobalTech Industries, security analysts detected unusual network traffic patterns from several employee workstations. Further investigation revealed that search queries were being redirected to suspicious websites, indicating potential malware infection.

## Investigation Findings

### Malware Identification
- **Malware Sample:** `111bc461-1ca8-43c6-97ed-911e0e69fdf8.dll`
- **Classification:** Remote Access Trojan (RAT)
- **Family:** Yellow Cockatoo / SolarMarker

### Technical Details
- **Compilation Timestamp:** 2020-09-24 18:26
- **First Submission to VirusTotal:** 2020-10-15 02:47
- **Associated Files:** SolarMarker.dat (found in AppData folder)
- **Command & Control Server:** https://gogohid.com

### Attack Pattern
The malware:
1. Establishes persistence through DLL files in the system
2. Creates additional payload components like SolarMarker.dat
3. Communicates with C2 servers for remote control capabilities
4. Redirects user web searches to malicious domains

## Remediation Steps
- Isolate affected workstations
- Block communication to identified C2 servers
- Remove malicious DLL files and associated components
- Scan all systems for indicators of compromise
- Deploy updated endpoint protection definitions
- Review and strengthen network security controls

## Tools Used in Analysis
- VirusTotal for initial malware identification
- Dynamic analysis tools for behavior monitoring
- Network traffic analysis tools
- Threat intelligence sources (Red Canary report)

## References
- [Red Canary Threat Intelligence Report on Yellow Cockatoo](https://redcanary.com/blog/threat-intelligence/yellow-cockatoo/)
- VirusTotal analysis results

## Author
Prepared by: Manasseh Mutugi  
Position: SOC Analyst

## Note
This repository contains information about malicious software for educational and defensive purposes only. The code and indicators shared are intended for security professionals to better understand and defend against these threats.
