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
![image](https://github.com/duffian/SIEM_SOC/blob/c5adcec83f0fa95bcf9e85064ce7755635b05f36/images/proj3_topology.png)

## Offensive Security

The objective of the offensive SIEM engineering team is to identify critical vulnerabilities in the system and exploit them. Documention of these vulnerabilities is reported to the SOC team. 

**Critical Vulnerabilities**

Our assessment uncovered the following critical vulnerabilities

    - Poorly secured ssh port
    - SQL enumeration
    - Weak user password
    - No file security

![image](https://github.com/duffian/SIEM_SOC/blob/b9bad2b5e48bc897300f255d3772730ce87673ee/images/adn5.png)

**Exploitation - Poorly Secured SSH Port**

    - What tool or technique did you use to exploit the vulnerability?

Nmap port scanning.

`nmap -O 192.168.1.0/24`

![image](https://github.com/duffian/SIEM_SOC/blob/ba1a85cafab83e375e0afd9a6100861d9ea0c7aa/images/linux_nmapcommand.png)
![image](https://github.com/duffian/SIEM_SOC/blob/a10b171bf63d285966e70f6b8a8195b9f5c65c7a/images/nmapscanreport.png)
![image](https://github.com/duffian/SIEM_SOC/blob/a10b171bf63d285966e70f6b8a8195b9f5c65c7a/images/7_ssh.png)


    - What did the exploit achieve?

Unauthorized access to the Target 1 machine was achieved by using the unsecured ssh port identified on the vulnerable machine.
Identification of vulnerable ports to potentially gain unauthorized access to the "Target 1" system.

`ssh Michael@192.168.1.110`

![image](https://github.com/duffian/SIEM_SOC/blob/b1ad487330827e1fdd4a7fa298a8a63e6a605ca5/images/8_sshmichael.png)

**Exploitation - WordPress Susceptible to Enumeration**

    - What tool or technique did you use to exploit the vulnerability?

WPScan enumeration

`wpscan --url 192.168.1.110/wordpress -e u`


![image](https://github.com/duffian/SIEM_SOC/blob/0ec4844e2ccdd26a87831fc1e3ef47458b2cb65f/images/9_enumeration.png) 

    - What did the exploit achieve?

Acquisition of usernames associated with IP addresses.



![image](https://github.com/duffian/SIEM_SOC/blob/0ec4844e2ccdd26a87831fc1e3ef47458b2cb65f/images/10_enum.png)

**Exploitation - Weak User Password**

    - What tool or technique did you use to exploit the vulnerability?

Brute forcing passwords using hydra

`$ hydra -l michael -t 4 -P /usr/share/wordlists/rockyou.txt 192.168.1.110 ssh`


    - What did the exploit achieve?

Discovered the login password for user “michael” allowing ssh access into Target 1 Machine

![image](https://github.com/duffian/SIEM_SOC/blob/a89a67f44005945181d2897d97e6466921eec59a/images/11_hydra.png) 


**Exploitation - No File Security**

    - What tool or technique did you use to exploit the vulnerability?

Simple directory exploration.
![image](https://github.com/duffian/SIEM_SOC/blob/a89a67f44005945181d2897d97e6466921eec59a/images/12_rootcreds.png)

    - What did the exploit achieve?

Privelege escalation: login data granted root access to Target 1 mysql data.

`michael@target1:/var/www/html/wp-config.php`
![image](https://github.com/duffian/SIEM_SOC/blob/a89a67f44005945181d2897d97e6466921eec59a/images/13_pe.png)


**Avoiding Detection**




Identifying monitoring data and understanding how these data points might be used in mitigation helps to maintain unauthorized access / malicious activity and avoid detection.

Monitoring - alerts, metrics, and thresholds 

Mitigation - How can you execute the same exploit without triggering the alert? Are there alternative exploits that may perform better? 
 
[SCREENSHOT 15]

**Stealth Exploitation of Poorly Secured SSH Port**

    - Monitoring Overview
        - Alerts that detect this exploit:
        - Metric = `WHEN        `
        - Threshold = 

    - Mitigation Detection
        - How can you execute the same exploit without triggering the alert? 

[SCREENSHOT 16-18]

**Stealth Exploitation of WordPress Susceptible to Enumeration**

    - Monitoring Overview
        - Alerts that detect this exploit:
        - Metric = `WHEN        `
        - Threshold = 

    - Mitigation Detection
        - How can you execute the same exploit without triggering the alert? 

[SCREENSHOT 19]

**Stealth Exploitation of Weak User Password**

    - Monitoring Overview
        - Alerts that detect this exploit:
        - Metric = `WHEN        `
        - Threshold = 

    - Mitigation Detection
        - How can you execute the same exploit without triggering the alert? 

[SCREENSHOT 20-21]

**Stealth Exploitation of No File Security**

    - Monitoring Overview
        - Alerts that detect this exploit:
        - Metric = `WHEN        `
        - Threshold = 

    - Mitigation Detection
        - How can you execute the same exploit without triggering the alert? 

[SCREENSHOT 22-23]

**Maintaining Access**

Python Script to Add User

[SCREENSHOT 24-25]
[s53-54]













## Defensive Security

The objective is to configure Kibana alerts and make sure they are working correctly. Here we ensure the latest exploits and vulnerabilities are accounted for.

**Alerts Overview**

Identify the metric the alert monitors and the threshold that metric fires at.
[S28]

**Alert: CPU Usage Monitor**

[S29]

**Alert: Excessive HTTP Errors**

[S30]

**Alert: HTTP Request Size Monitor**

[S31]


**Hardening**
Explain how to patch the target against the vulnerabilities. Explain why the patch works and how to install the patch.

**Hardening Against on Target 1**

[S35]

**Hardening Against on Target 1**

[S36]

**Hardening Against on Target 1**

[S37]














## Network Analysis

The objective is to analyze network traffic to identify suspicious or malicious activity.

**Traffic Profile and Behavioral Analysis**

[s39-40]

**Normal Activity - Web Traffic**

[s42-44]

**Normal Activity - DNS**

[s45-47]

**Malicious Activity**

    - Time Thieves

[s49]

    - Malicious File Download

[s50]

    - Vulnerable Windows Machines

[s51]

    - Illegal Downloads

[s52]











## Works Cited ##

[s56]
