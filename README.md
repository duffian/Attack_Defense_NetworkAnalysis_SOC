# SIEM_SOC
# Supporting SOC infrastructure - Combining offensive security, defensive security, and network analysis.

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

In this activity SIEM engineers conduct offensive, defensive, and network analysis acivities to provide the SOC team with a comprehensive security report. Approaching potential cybersecurity threats from multiple perspectives is likely to provide a more complete threat analysis. 

## Network Topology

In this environment the Kali Linux machine is the attacking machine. The ELK server is monitoring the vulnerable target machines as the attacking machine seeks to exploit the system.  
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

***Exploitation - Poorly Secured SSH Port***

What tool or technique did you use to exploit the vulnerability?
>nmap port scanning

`nmap -O 192.168.1.0/24`

![image](https://github.com/duffian/SIEM_SOC/blob/ba1a85cafab83e375e0afd9a6100861d9ea0c7aa/images/linux_nmapcommand.png)

![image](https://github.com/duffian/SIEM_SOC/blob/a10b171bf63d285966e70f6b8a8195b9f5c65c7a/images/nmapscanreport.png)

What did the exploit achieve?
>Unauthorized access to the Target 1 machine was achieved by using the unsecured ssh port identified on the vulnerable machine.
>Identification of vulnerable ports to potentially gain unauthorized access to the "Target 1" system.

`ssh Michael@192.168.1.110`

![image](https://github.com/duffian/SIEM_SOC/blob/b1ad487330827e1fdd4a7fa298a8a63e6a605ca5/images/8_sshmichael.png)

***Exploitation - WordPress Susceptible to Enumeration***

What tool or technique did you use to exploit the vulnerability?
>WPScan enumeration

`wpscan --url 192.168.1.110/wordpress -e u`

![image](https://github.com/duffian/SIEM_SOC/blob/0ec4844e2ccdd26a87831fc1e3ef47458b2cb65f/images/9_enumeration.png) 
What did the exploit achieve?
>Acquisition of usernames and their associated IP addresses.

![image](https://github.com/duffian/SIEM_SOC/blob/0ec4844e2ccdd26a87831fc1e3ef47458b2cb65f/images/10_enum.png)

***Exploitation - Weak User Password***

What tool or technique did you use to exploit the vulnerability?
>Brute forcing passwords using hydra

`$ hydra -l michael -t 4 -P /usr/share/wordlists/rockyou.txt 192.168.1.110 ssh`

What did the exploit achieve?
>Discovered the login password for user “michael” allowing ssh access into Target 1 Machine

![image](https://github.com/duffian/SIEM_SOC/blob/a89a67f44005945181d2897d97e6466921eec59a/images/11_hydra.png) 

***Exploitation - No File Security***

What tool or technique did you use to exploit the vulnerability?
>Simple directory exploration.

What did the exploit achieve?
>Privelege escalation - login data granted root access to Target 1 mysql data

`michael@target1:/var/www/html/wp-config.php`

![image](https://github.com/duffian/SIEM_SOC/blob/a89a67f44005945181d2897d97e6466921eec59a/images/12_rootcreds.png)
![image](https://github.com/duffian/SIEM_SOC/blob/a89a67f44005945181d2897d97e6466921eec59a/images/13_pe.png)






**Avoiding Detection**

Identifying the key data points and understanding how monitoring system alerts are generated helps the offensive SIEM engineer avoid detection. This expands the scope of potential system vulnerabilities. 

Monitoring - Identify alerts, metrics, and thresholds 

Mitigation - How can you execute the same exploit without triggering the alert? Are there alternative exploits that may perform better? 
 
![image](https://github.com/duffian/SIEM_SOC/blob/dcdcb2395afc40104128b2e63049f37ae94e1a84/images/15_introalerts.png) 

**Stealth Exploitation of Poorly Secured SSH Port**

    - Monitoring Overview
        - Alerts that detect this exploit:
		  - Port scanning traffic alerts
		  - Alerts monitoring for Unauthorized access through ssh port
        - Metric = `WHEN sum () of http.request.bytes OVER all documents`
        - Threshold = `IS ABOVE 3500 FOR THE LAST 1 minute`


    - Mitigation Detection
        - How can you execute the same exploit without triggering the alert? 
		  - Stealth scan
		  - Fast scan
		  - Limited-time scan
Stealth scan:
`nmap -sS`

![image](https://github.com/duffian/SIEM_SOC/blob/dcdcb2395afc40104128b2e63049f37ae94e1a84/images/16_nmap_stlth.png) 

Fast scan:
`nmap -F`
![image](https://github.com/duffian/SIEM_SOC/blob/dcdcb2395afc40104128b2e63049f37ae94e1a84/images/17_ssh_stlth.png)

**Stealth Exploitation of WordPress Susceptible to Enumeration**

    - Monitoring Overview
        - Alerts that detect this exploit:
		  - Alerts monitoring traffic from suspicious sources.
		  - Alerts monitoring traffic from non-white-listed IPs.
        - Metric = `WHEN count() GROUPED OVER top 5 ‘http.response.status_code`
        - Threshold = `IS ABOVE 400`

    - Mitigation Detection
        - How can you execute the same exploit without triggering the alert?
		  - Scan a WordPress site using random user agents and passive detection.
`wpscan --url 192.168.1.110/wordpress --stealthy -e u`
		

![image](images/adn19.png)
![image](https://github.com/duffian/SIEM_SOC/blob/dcdcb2395afc40104128b2e63049f37ae94e1a84/images/adn19.png)

**Stealth Exploitation of Weak User Password**

    - Monitoring Overview
        - Alerts that detect this exploit: CPU Usage Monitoring
		  - Alerts monitoring abnormal CPU usage according to time.
		  - Alerts monitoring abnormally high CPU usage.
        - Metric = `WHEN max() OF system.process.cpu.total pct OVER all documents`
        - Threshold = `IS ABOVE 0.5` (or norm for company)

    - Mitigation Detection
        - How can you execute the same exploit without triggering the alert? 
`$ hydra -l michael -t 4 P /usr/share/wordlists/rockyou.txt 192.168.1.110 ssh`
  - -t limits tasks per attempt
`$ hydra -l michael -w 5 P /usr/share/wordlists/rockyou.txt 192.168.1.110 ssh`
  - -w defines max wait time
  
![image](https://github.com/duffian/SIEM_SOC/blob/e65bdfaa5b51d75846e8a35e70dc7db5d75ab504/images/20_hydratasklimit.png) 
![image](https://github.com/duffian/SIEM_SOC/blob/e65bdfaa5b51d75846e8a35e70dc7db5d75ab504/images/21_hydrawaittimelimit.png)

**Stealth Exploitation of No File Security**

    - Monitoring Overview
        - Alerts that detect this exploit: Alerts monitoring traffic from;
		  - suspicious/malicious sources
		  - non-white-listed IPs
		  - unauthorized accounts
		  - root user logins
        - Metric = `user.name: root AND source.ip: 192.168.1.90 AND destination.ip: 192.168.1.110 OR event.action: ssh_login OR event.outcome: success`
        - Threshold = `IS ABOVE 1`

    - Mitigation Detection
        - How can you execute the same exploit without triggering the alert? 
		  - Remove evidence of instrusion/unauthorized access
		  - Mask source IP
		- Are there alternative exploits that may perform better? If attempts to elevate privileges to sudo are restricted and if root login data is secured with up-to-date password hashes, malicious actors will have a much more difficult time gaining root or elevated permissions.

![image](https://github.com/duffian/SIEM_SOC/blob/e65bdfaa5b51d75846e8a35e70dc7db5d75ab504/images/22_xtraalerts.png) 

**Maintaining Access**
Maintain access by writing a script to add an unauthorized user to the target system.



Python Script to Add User
`sudo python -c 'import.pty;pty.spawn("/bin/bash")'`
![image](https://github.com/duffian/SIEM_SOC/blob/1e64581adce910196643460e232d35489b2fee22/images/23_pythscrp_adduser.png) 


![image](https://github.com/duffian/SIEM_SOC/blob/1e64581adce910196643460e232d35489b2fee22/images/24_pythscrp_adduser.png) 
Could also write a script to install a backdoor shell listening for the attacker's instructions.












## Defensive Security

The objective is to configure Kibana alerts and make sure they are working correctly. Here we ensure the latest exploits and vulnerabilities are accounted for.

**Alerts Overview**

When generating alerts it can be helpful to identify
    - the metric that the alert monitors
    - the threshold that metric fires at
	
![image]() [S28]

**Alert: CPU Usage Monitor**

![image]() [S27_a]

**Alert: Excessive HTTP Errors**

![image]() [S30]

**Alert: HTTP Request Size Monitor**

![image]() [S31]


**Hardening**
Effective hardening methods should explain
    - how to patch a target against the vulnerabilities
    - why the patch works and how to install the patch

**Hardening Against on Target 1**

![image]() [S34]

**Hardening Against on Target 1**

![image]() [S35]

**Hardening Against on Target 1**

![image]()  [S36_c]

**Implementing Patches with Ansible**
Explain the vulnerability each task in the playbook addresses

## Network Analysis

The objective is to analyze network traffic to identify suspicious or malicious activity.

**Traffic Profile and Behavioral Analysis**

![image](https://github.com/duffian/SIEM_SOC/blob/2553f872a954fa8bff9c6686696817b625736453/images/adn35.png) 
![image](https://github.com/duffian/SIEM_SOC/blob/2553f872a954fa8bff9c6686696817b625736453/images/adn36.png)

**Normal Activity**
***Normal Activity - Web Traffic***

Kind of Traffic - Web traffic
Protocol - HTTP
Specific user action - Browsing "orbike.com"
Screenshots of packets justifying conclusions - 
![image](https://github.com/duffian/SIEM_SOC/blob/ed4be6a476dc61e1cf6e4346b88a2ef80275417c/images/42_normact_webtraf.png)

Description of any interesting files - 
![image](https://github.com/duffian/SIEM_SOC/blob/ed4be6a476dc61e1cf6e4346b88a2ef80275417c/images/43_normact_webtraf.png)


***Normal Activity - DNS***

Kind of Traffic - DNS query for "orbike.com"
Protocol - UDP over port 53;8.8.8.8
Specific user action - Querying Google DNS servers for "orbike.com" site data 
![image](https://github.com/duffian/SIEM_SOC/blob/ed4be6a476dc61e1cf6e4346b88a2ef80275417c/images/45_normact_dns.png) 
Packet data justifying conclusions - 
![image](https://github.com/duffian/SIEM_SOC/blob/ed4be6a476dc61e1cf6e4346b88a2ef80275417c/images/46_normact_dns.png) 

**Malicious Activity**
***Malicious Activity - Time Thieves*** 

Kind of Traffic - 
Protocol - 
Specific user action - 
Packet data justifying conclusions - 


Users created a web server to access YouTube
![image](https://github.com/duffian/SIEM_SOC/blob/2553f872a954fa8bff9c6686696817b625736453/images/adn45.png)
  - Filtered for traffic by IP address to correlate users and IP addresses.
![image](https://github.com/duffian/SIEM_SOC/blob/ed4be6a476dc61e1cf6e4346b88a2ef80275417c/images/48_malact_timethfa.png)
  - Discovered web server domain name "frank-n-ted.com"  and IP address 10.6.12.12
![image](https://github.com/duffian/SIEM_SOC/blob/ed4be6a476dc61e1cf6e4346b88a2ef80275417c/images/48_malact_timethfb.png)




***Malicious Activity - Malicious File Download*** 

Kind of Traffic - 
Protocol - 
Specific user action - 
Packet data justifying conclusions -    

![image](https://github.com/duffian/SIEM_SOC/blob/ed4be6a476dc61e1cf6e4346b88a2ef80275417c/images/49_malactmalfiledl_a.png) 
![image](https://github.com/duffian/SIEM_SOC/blob/ed4be6a476dc61e1cf6e4346b88a2ef80275417c/images/49_malactmalfiledl_b.png) 
The malicious file was downloaded on machine IP Address 10.6.12.203
`june11.dll`
![image](https://github.com/duffian/SIEM_SOC/blob/8d5e155b2dd84bba4138d95c32af683078cebda5/images/49_malfil_c.png)
"june11.dll" was scanned by anti-malware software "VirusTotal" and flagged as a possible Trojan
![image](https://github.com/duffian/SIEM_SOC/blob/8d5e155b2dd84bba4138d95c32af683078cebda5/images/49_malfil_d.png) 

***Malicious Activity - Vulnerable Windows Host Machines Infected***
Kind of Traffic - 
Protocol - 
Specific user action - 
Packet data justifying conclusions - 

Infected host machine on network
![image](https://github.com/duffian/SIEM_SOC/blob/8d5e155b2dd84bba4138d95c32af683078cebda5/images/50_malact_infect.png) 


***Malicious Activity - Illegal Downloads*** 
Kind of Traffic - 
Protocol - 
Specific user action - 
Packet data justifying conclusions - 

![image](https://github.com/duffian/SIEM_SOC/blob/8d5e155b2dd84bba4138d95c32af683078cebda5/images/51_malact_illdwnld.png) 











## Works Cited ##

![image](https://github.com/duffian/SIEM_SOC/blob/7c7a71069193d7edf6dd3c01aeaff6582064fbc8/images/adn52.png)






`THIS TEXT IS IN CODE FORMAT`
