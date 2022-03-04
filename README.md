# SIEM_SOC
# Supporting SOC infrastructure - Combining offensive security, defensive security, and network analysis

[comment]: # (this is the syntax for a comment)

This project is organized into the following sections and subsections:
- **Network Topology:** Live network environment
    - Host machine
    - Attacking machine
    - Vulnerable Web Server
    - Wordpress Target
    - ELK Server
- **Offensive Security:** Security assessment of vulnerable VM and verification of working Kibana rules.
    - Critical Vulnerabilities
    - Exploits Used
    - Avoiding Detection
    - Maintaining Access   
- **Defensive Security:** Creating and implementing alerts and thresholds
    - Alerts Implemented
    - Hardening
    - Implementing Policies
- **Network Analysis:** Network forensics and analysis
    - Traffic Profile
    - Normal Activity
    - Malicious activity
___

In this activity SIEM engineers conduct offensive security, defensive security, and network analysis acivities to provide the SOC team with a comprehensive security report. Approaching potential cybersecurity threats from these three perspectives is likely to provide a more complete threat analysis resulting in more effective mitigation strategies. 

## Network Topology

In this environment the ELK server is monitoring the vulnerable and taregeted machines as they are being attacked by the Kali machine. 
![image](LINKTOIMAAGEINGITHUBREPOSITORY)

## Offensive Security

The objective of the offensive SIEM engineering team is to identify critical vulnerabilities in the system and exploit them. Documention of these vulnerabilities is reported to the SOC team. 

**Critical Vulnerabilities**

Our assessment uncovered the following critical vulnerabilities

    - Poorly secured ssh port
    - SQL enumeration
    - Weak user password
    - No file security

[SCREENSHOT SLIDE 5]

**Exploitation - Poorly Secured SSH Port**

    - What tool or technique did you use to exploit the vulnerability?

Nmap port scanning.

`nmap -O 192.168.1.0/24`

[SCREENSHOT SLIDE 7]

    - What did the exploit achieve?

Unauthorized access to the Target 1 machine was achieved by using the unsecured ssh port identified on the vulnerable machine.
Identification of vulnerable ports to potentially gain unauthorized access to the "Target 1" system.

`ssh Michael@192.168.1.110`

[SCREENSHOT SLIDE 8]

**Exploitation - WordPress Susceptible to Enumeration**

    - What tool or technique did you use to exploit the vulnerability?

    - What did the exploit achieve?

    - [SCREENSHOT]

**Exploitation - Weak User Password**

    - What tool or technique did you use to exploit the vulnerability?

    - What did the exploit achieve?

    - [SCREENSHOT]


**Exploitation - No File Security**

    - What tool or technique did you use to exploit the vulnerability?


    - What did the exploit achieve?


    - [SCREENSHOT]

## Defensive Security

The objective is to configure Kibana alerts and make sure they are working correctly. Here we ensure the latest exploits and vulnerabilities are accounted for.

## Network Analysis

The objective is to analyze network traffic to identify suspicious or malicious activity.
