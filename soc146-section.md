
---

## SOC146: Phishing Mail Detected - Excel 4.0 Macros
**Event ID:** 93 | **Severity:** High | **Type:** Exchange | **Verdict:** True Positive

### What happened
A phishing email with the subject **"RE: Meeting Notes"** was sent from `trenton@tritowncomputers.com` to `lars@letsdefend.io`. The email asked the recipient to open a password-protected attachment. LetsDefend's own note confirms this alert came from a real phishing attack.

I found that the attachment, `research-1646684671.xls`, is a malicious Excel 4.0 macro downloader — confirmed by 24 out of 62 security vendors on VirusTotal. When opened, the macro dropped two DLL files (`iroto.dll` and `iroto1.dll`) and executed them using `regsvr32.exe`, a legitimate Windows tool that attackers abuse to run malicious code while avoiding detection. This activity happened on the host **LarsPRD**, matching the exact time the phishing email was interacted with. I contained the host and deleted the phishing email from the mailbox. I closed the alert as a **True Positive**.

### Key details
| Item | Value |
|---|---|
| Event ID | 93 |
| Email subject | RE: Meeting Notes |
| Sender | trenton@tritowncomputers.com |
| Recipient | lars@letsdefend.io |
| Sender IP | 24.213.228.54 |
| Attachment | research-1646684671.xls (password: infected) |
| Affected host | LarsPRD (172.16.17.57) |

### What I did, step by step
1. **Read the alert.** Noted the sender, recipient, subject, and sender IP.

   ![Alert details showing sender, recipient, subject and SMTP address](images/01-alert-details.png)

2. **Opened the email in Email Security.** Found a short, generic message asking the recipient to open a password-protected attachment (`research-1646684671.xls`, password `infected`). A password-protected attachment is a red flag on its own, since it's a common trick to stop antivirus scanners from opening the file automatically.

   ![Email body showing the message and password-protected attachment](images/02-email-attachment.png)

3. **Downloaded and checked the attachment.** After unzipping it, I found the Excel file itself plus two DLL files it drops (`iroto.dll` and `iroto1.dll`). I checked the Excel file's hash in VirusTotal: 24 out of 62 vendors flagged it as malicious, labeled as an Excel 4.0 macro downloader (`downloader.x97m/downldrx`).

   ![VirusTotal result showing the Excel file flagged as malicious by 24/62 vendors](images/03-virustotal-xls-detection.png)

4. **Checked Endpoint Security's Terminal History for LarsPRD.** At the exact time of the alert, I found the commands `regsvr32.exe -s ../iroto.dll` and `regsvr32.exe -s ../iroto1.dll`. This proves the macro ran and used a legitimate Windows tool to register the malicious DLLs — a known evasion technique.

   ![Terminal history showing regsvr32.exe executing the dropped DLL files](images/04-terminal-regsvr32-execution.png)

5. **Contained the host.** I isolated LarsPRD from the network to stop further spread or command-and-control activity.

   ![Endpoint Security showing LarsPRD host contained](images/05-endpoint-containment.png)

6. **Deleted the phishing email** from the mailbox so it could not be opened again, and confirmed the deletion.

   ![Confirmation that the phishing email was deleted](images/06-email-deleted-confirmation.png)

7. **Closed the alert** as True Positive and wrote my analyst notes.

### Indicators of Compromise
| Type | Value |
|---|---|
| Sender address | trenton@tritowncomputers.com |
| Sender IP | 24.213.228.54 |
| Malicious attachment | research-1646684671.xls |
| Dropped file | iroto.dll |
| Dropped file | iroto1.dll |
| Affected host | LarsPRD / 172.16.17.57 |

### MITRE ATT&CK
| Tactic | Technique | What I saw |
|---|---|---|
| Initial Access | T1566.001 Spearphishing Attachment | Password-protected malicious attachment delivered by email |
| Execution | T1204.002 User Execution: Malicious File | Excel 4.0 macro executed after the file was opened |
| Defense Evasion | T1218.010 Signed Binary Proxy Execution: Regsvr32 | `regsvr32.exe` used to register the dropped DLLs and evade detection |

### Why it was a True Positive
- The attachment was confirmed malicious by multiple antivirus vendors.
- The macro's behavior (dropping and registering DLLs via `regsvr32`) matched a known attack pattern.
- The commands ran on LarsPRD at the exact time the email was received, proving execution, not just delivery.

### How to respond
- Done: isolated LarsPRD, deleted the phishing email.
- Next: block the sender address and IP, search other mailboxes for the same sender, scan LarsPRD for further compromise, and reset any credentials used on that host.

### What I learned
- Excel 4.0 macros are an old feature still actively abused by attackers, and mail filtering should flag or block them.
- Password-protected attachments are a common way to bypass automated email scanning and deserve extra scrutiny.
- `regsvr32.exe` is a legitimate tool that's frequently abused for defense evasion — its use with unusual DLL paths is worth alerting on.

---
**Tools used:** LetsDefend Email Security, Endpoint Security, VirusTotal, MITRE ATT&CK
