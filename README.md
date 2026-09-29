# SOC Analyst Portfolio: Ransomware Investigation

**Name:** Yashwanth

This repository shows how I investigated a real-style security alert on the LetsDefend training platform. All computers, users and IP addresses are simulated.

\---

## SOC145: Ransomware Detected

**Event ID:** 92 | **Severity:** Critical | **Type:** Malware | **Verdict:** True Positive

### What happened

The security system raised a critical alert. A program called `ab.exe` was run on a computer named **MarkPRD** (IP address 172.16.17.88). I checked the file and found it was **ransomware**, a type of malware that locks (encrypts) your files. The antivirus/EDR tool did not stop it, so the file ran on the computer. I found no sign that it talked to an attacker's server. I quickly cut the computer off from the network so the damage could not spread. I closed the alert as a **True Positive** (a real attack, not a false alarm).

### Key details

|Item|Value|
|-|-|
|Computer name|MarkPRD|
|IP address|172.16.17.88|
|File name|ab.exe|
|File size|775.50 KB|
|File hash (MD5)|`0b486fe0503524cfe4726a4022fa6a68`|
|Did the security tool block it?|No, it was "Allowed"|

### What I did, step by step

1. **First thing i did: firstly i noted the host ip \[172.16.17.88] and file hash\[0b486fe0503524cfe4726a4022fa6a68]**
2. **Checking the reputation: Second process i did,checking the reputation of file hash in virus total,after checking its reputation in virus taotal it shows that 60/71 security vendors flagged this file as malicious.**
3. **Checked what the security tool did (Endpoint Security): It said that the file was allowed and ran in host machine \[markpkd].**
4. Contacting the attacker's sever: No it does not contacted the attacker's server.
5. **The containment : I contain the host markpkd to stop the further malware spead**.
6. **Closed the alert**: True Positive and wrote my notes.

### Indicators of Compromise (things to look for on other computers)

|Type|Value|
|-|-|
|File hash (MD5)|`0b486fe0503524cfe4726a4022fa6a68`|
|File name|ab.exe|
|Infected computer|MarkPRD / 172.16.17.88|
|Attacker server|None found|

### MITRE ATT\&CK (how the attack fits the standard attack list)

|Tactic|Technique|What I saw|
|-|-|-|
|Execution|T1204 User Execution|`ab.exe` was run on the computer|
|Impact|T1486 Data Encrypted for Impact|Files on the computer were encrypted|

### Why it was a True Positive

* The file hash is known ransomware.
* The security tool allowed it to run.
* Files on the computer were encrypted.
* Having no attacker server contact does not make it safe. This ransomware can lock files on its own.

### How to respond

* Done: isolated MarkPRD from the network.
* Next: block the file hash on all computers, search other computers for `ab.exe`, change passwords used on MarkPRD, and restore the files from backup.

### What I learned

* The security tool allowed a known bad file to run, so its blocking settings should be checked.
* Only allowing approved programs to run would stop unknown files like `ab.exe`.
* Regular backups make recovery from ransomware much easier.

\---

**Tools used:** LetsDefend Endpoint Security, Threat Intel, Log Management, MITRE ATT\&CK,Virus total

