# Windows-MITRE_ATT-CK-Wazuh-Rules

This is a set of rules that i was developing for wazuh HIDS based on MITRE ATT&CK Framework to complement the windows base ruleset.
I add rules as i develop them for my own needs. Notice that i'm working with events for windows above 2003.
Use under your own risk.


The idea is to work with two files:

1. The first one **rules_regular_events.txt** consist on rules that one can obtain just with regular windows events 

### Notice that in many cases you must enable specific event gathering in wazuh agent config
>  <localfile>
>    <location>Security</location>
>    <log_format>eventchannel</log_format>
>    <query>Event/System[EventID != 5145 and EventID != 5156 and EventID != 5447 and
>      EventID != 4656 and EventID != 4658 and EventID != 4663 and EventID != 4660 and
>      EventID != 4670 and EventID != 4690 and EventID != 4703 and EventID != 4907]</query>
>  </localfile>


2. The second one **rules_sysmon_events.txt** consist on rules based on sysmon events, to use them you must first install and configure sysmon.


--------------------

Before each rule category it's a commented block with events in order to test each rule with **ossec-logtest**.

---------------------


`Initial access` |	`Execution` |	`Persistence` |	`Privilege Escalation` |	`Defense Evasion` |	`Credential Access` |	`Discovery` |	`Lateral Movement` |	`Collection` |	`Command and Control` |	`Exfiltration` |	`Impact`
---- |	---- |	---- |	---- |	---- |	---- |	---- |	---- |	---- |	---- |	---- |	----
Drive-by Compromise |	CMSTP |	Accessibility Features |	Access Token Manipulation |	Access Token Manipulation |	Account Manipulation |	Account Discovery |	Application Deployment Software |	Audio Capture |	Commonly Used Port |	Automated Exfiltration |	Account Access Removal
Exploit Public-Facing Application |	Command-Line Interface |	Account Manipulation |	Accessibility Features |	Binary Padding |	Brute Force |	Application Window Discovery |	Component Object Model and Distributed COM |	Automated Collection |	Communication Through Removable Media |	Data Compressed |	Data Destruction
External Remote Services |	Compiled HTML File |	AppCert DLLs |	AppCert DLLs |	BITS Jobs |	Credential Dumping |	Browser Bookmark Discovery |	Exploitation of Remote Services |	Clipboard Data |	Connection Proxy |	Data Encrypted |	Data Encrypted for Impact
Hardware Additions | Component Object Model and Distributed COM | AppInit DLLs | AppInit DLLs | Bypass User Account Control | Credentials from Web Browsers | Domain Trust Discovery | Internal Spearphishing | Data from Information Repositories | Custom Command and Control Protocol | Data Transfer Size Limits | Defacement
Replication Through Removable Media | Control Panel Items | Application Shimming | Application Shimming | CMSTP | Credentials in Files | File and Directory Discovery | Logon Scripts | Data from Local System | Custom Cryptographic Protocol | Exfiltration Over Alternative Protocol | Disk Content Wipe
Spearphishing Attachment | Dynamic Data Exchange | Authentication Package | Bypass User Account Control | Code Signing | Credentials in Registry | Network Service Scanning | Pass the Hash | Data from Network Shared Drive | Data Encoding | Exfiltration Over Command and Control Channel | Disk Structure Wipe
Spearphishing Link | Execution through API | BITS Jobs | DLL Search Order Hijacking | Compile After Delivery | Exploitation for Credential Access | Network Share Discovery | Pass the Ticket | Data from Removable Media | Data Obfuscation | Exfiltration Over Other Network Medium | Endpoint Denial of Service
Spearphishing via Service | Execution through Module Load | Bootkit | Exploitation for Privilege Escalation | Compiled HTML File | Forced Authentication | Network Sniffing | Remote Desktop Protocol | Data Staged | Domain Fronting | Exfiltration Over Physical Medium | Firmware Corruption
Supply Chain Compromise | Exploitation for Client Execution | Browser Extensions | Extra Window Memory Injection | Component Firmware | Hooking | Password Policy Discovery | Remote File Copy | Email Collection | Domain Generation Algorithms | Scheduled Transfer | Inhibit System Recovery
Trusted Relationship | Graphical User Interface | Change Default File Association | File System Permissions Weakness | Component Object Model Hijacking | Input Capture | Peripheral Device Discovery | Remote Services | Input Capture | Fallback Channels | | Network Denial of Service
Valid Accounts | InstallUtil | Component Firmware | Hooking | Connection Proxy | Input Prompt | Permission Groups Discovery | Replication Through Removable Media | Man in the Browser | Multi-hop Proxy | | Resource Hijacking
