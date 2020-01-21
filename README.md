# Windows-MITRE&ATT-CK-Wazuh-Rules


1. [Regular rule files](#Regular-rule-files)
2. [Independent file list](#Independent-file-list)
3. [ATT&CK Matrix with tactics covered by the rules](#ATT_CK-Matrix-with-tactics-covered-by-the-rules)






## Regular rule files



This is a set of rules that i was developing for wazuh HIDS based on MITRE ATT&CK Framework to complement the windows base ruleset.
I add rules as i develop them for my own needs. Notice that i'm working with events for windows above 2003.
Use under your own risk.

The idea is to work with two main files:

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


In the two main files before each rule category it's a commented block with events in order to test each rule with **ossec-logtest**.

-----------------------------------------------------








## Independent file list:

Due to the complexity of the task i try to follow the way wazuh categorizes rules and so if audit new log sources needed (other than security and system, both enabled by default) i will create new independent files.


### - powershell_rules.xml
-------------------------------
This config must be enabled in the agent configuration:

```
<localfile>
<location>Microsoft-Windows-PowerShell/Operational</location>
<log_format>eventchannel</log_format>
</localfile>

```

> PowerShell module logging can be configured to record all activities of each PowerShell module, covering single PowerShell commands, imported modules, and remote management. The module logging function can be enabled by configuring GPO settings.
> Alternately, setting the following registry values will have the same effect:
>   - HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging → EnableModuleLogging = 1
>   - HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging \ModuleNames → * = *
   
------------------------------
### - rdp_rules.xml

This config must be enabled in agent configuration:

```
<localfile>
<location>Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational</location>
<log_format>eventchannel</log_format>
</localfile>

```

--------------------------------








## ATT_CK Matrix with tactics covered by the rules



`Initial access` |	`Execution` |	`Persistence` |	`Privilege Escalation` |	`Defense Evasion` |	`Credential Access` |	`Discovery` |	`Lateral Movement` |	`Collection` |	`Command and Control` |	`Exfiltration` |	`Impact`
---- |	---- |	---- |	---- |	---- |	---- |	---- |	---- |	---- |	---- |	---- |	----
Drive-by Compromise |	CMSTP |	Accessibility Features |	Access Token Manipulation |	Access Token Manipulation |	* **Account Manipulation** |	Account Discovery |	Application Deployment Software |	Audio Capture |	Commonly Used Port |	Automated Exfiltration |	Account Access Removal
Exploit Public-Facing Application |	Command-Line Interface |	Account Manipulation |	Accessibility Features |	Binary Padding |	* **Brute Force** |	Application Window Discovery |	Component Object Model and Distributed COM |	Automated Collection |	Communication Through Removable Media |	Data Compressed |	Data Destruction
External Remote Services |	Compiled HTML File |	AppCert DLLs |	AppCert DLLs |	BITS Jobs |	* **Credential Dumping** |	Browser Bookmark Discovery |	Exploitation of Remote Services |	Clipboard Data |	Connection Proxy |	Data Encrypted |	Data Encrypted for Impact
Hardware Additions | Component Object Model and Distributed COM | AppInit DLLs | AppInit DLLs | Bypass User Account Control | * **Credentials from Web Browsers** | Domain Trust Discovery | Internal Spearphishing | Data from Information Repositories | Custom Command and Control Protocol | Data Transfer Size Limits | Defacement
Replication Through Removable Media | Control Panel Items | Application Shimming | Application Shimming | CMSTP | Credentials in Files | File and Directory Discovery | Logon Scripts | Data from Local System | Custom Cryptographic Protocol | Exfiltration Over Alternative Protocol | Disk Content Wipe
Spearphishing Attachment | Dynamic Data Exchange | Authentication Package | Bypass User Account Control | Code Signing | Credentials in Registry | Network Service Scanning | Pass the Hash | Data from Network Shared Drive | Data Encoding | Exfiltration Over Command and Control Channel | Disk Structure Wipe
Spearphishing Link | Execution through API | BITS Jobs | DLL Search Order Hijacking | Compile After Delivery | Exploitation for Credential Access | Network Share Discovery | Pass the Ticket | Data from Removable Media | Data Obfuscation | Exfiltration Over Other Network Medium | Endpoint Denial of Service
Spearphishing via Service | Execution through Module Load | Bootkit | Exploitation for Privilege Escalation | Compiled HTML File | Forced Authentication | Network Sniffing | Remote Desktop Protocol | Data Staged | Domain Fronting | Exfiltration Over Physical Medium | Firmware Corruption
Supply Chain Compromise | Exploitation for Client Execution | Browser Extensions | Extra Window Memory Injection | Component Firmware | Hooking | Password Policy Discovery | Remote File Copy | Email Collection | Domain Generation Algorithms | Scheduled Transfer | Inhibit System Recovery
Trusted Relationship | Graphical User Interface | Change Default File Association | File System Permissions Weakness | Component Object Model Hijacking | Input Capture | Peripheral Device Discovery | Remote Services | Input Capture | Fallback Channels | | Network Denial of Service
Valid Accounts | InstallUtil | Component Firmware | Hooking | Connection Proxy | Input Prompt | Permission Groups Discovery | Replication Through Removable Media | Man in the Browser | Multi-hop Proxy | | Resource Hijacking
| | LSASS Driver | Component Object Model Hijacking | Image File Execution Options Injection | Control Panel Items | * **Kerberoasting** | Process Discovery | Shared Webroot | Screen Capture | Multi-Stage Channels | | Runtime Data Manipulation
| | Mshta | * **Create Account** | New Service | * **DCShadow** | LLMNR/NBT-NS Poisoning and Relay | Query Registry | Taint Shared Content | Video Capture | Multiband Communication | | Service Stop
| | * **PowerShell** | DLL Search Order Hijacking | Parent PID Spoofing | Deobfuscate/Decode Files or Information | Network Sniffing | Remote System Discovery | Third-party Software | |	Multilayer Encryption | | Stored Data Manipulation
| |	Regsvcs/Regasm | External Remote Services | Path Interception | Disabling Security Tools | Password Filter DLL | Security Software Discovery | Windows Admin Shares | |	Remote Access Tools | |	System Shutdown/Reboot
| |	Regsvr32 | File System Permissions Weakness | Port Monitors | DLL Search Order Hijacking | Private Keys | Software Discovery | Windows Remote Management | | Remote File Copy | | Transmitted Data Manipulation 
| |	Regsvcs/Regasm | External Remote Services | Path Interception | Disabling Security Tools | Password Filter DLL | Security Software Discovery | Windows Admin Shares | |	Remote Access Tools | |	System Shutdown/Reboot
| | Rundll32 | Hidden Files and Directories | PowerShell Profile | DLL Side-Loading | Steal Web Session Cookie | System Information Discovery | | |	Standard Application Layer Protocol | | |	
| | * **Scheduled Task** | Hooking | Process Injection | Execution Guardrails | Two-Factor Authentication Interception | System Network Configuration Discovery | | |	Standard Cryptographic Protocol | | | 
| | Scripting | Hypervisor | Scheduled Task | Exploitation for Defense Evasion | | System Network Connections Discovery | | | Standard Non-Application Layer Protocol | | | | 
| | Service Execution | Image File Execution Options Injection | Service Registry Permissions Weakness | Extra Window Memory Injection | | System Owner/User Discovery | | | Uncommonly Used Port | | | | 
| | Signed Binary Proxy Execution | Logon Scripts | SID-History Injection | * **File and Directory Permissions Modification** | | System Service Discovery | | | Web Service | | |
| | Signed Script Proxy Execution | LSASS Driver | Valid Accounts | File Deletion | | System Time Discovery | | | | |				
| |	Third-party Software | Modify Existing Service | Web Shell | File System Logical Offsets | | Virtualization/Sandbox Evasion | | | | |
| | Trusted Developer Utilities | Netsh Helper DLL | | Group Policy Modification | | | | | | | 				
| | User Execution | * **New Service** | | Hidden Files and Directories | | | | | | |		
| | Windows Management Instrumentation | Office Application Startup | | Hidden Window | | | | | | | 						
| | Windows Remote Management | Path Interception | | Image File Execution Options Injection | | | | | | | 						
| | XSL Script Processing | Port Monitors | | Indicator Blocking | | | | | | |
| | | PowerShell Profile | | Indicator Removal from Tools | | | | | | | |  							
| | | Redundant Access | | Indicator Removal on Host | | | | | | | |						
| | | Registry Run Keys / Startup Folder | | Indirect Command Execution | | | | | | | |							
| | | Scheduled Task | | Install Root Certificate | | | | | | | |
| | | Screensaver | | InstallUtil | | | | | | | |
| | | Security Support Provider | | Masquerading | | | | | | | | 							
| | | Server Software Component | | Modify Registry | | | | | | | |				
| | | Service Registry Permissions Weakness | | Mshta | | | | | | | |			
| | | Shortcut Modification | | Network Share Connection Removal | | | | | | | |						
| | | SIP and Trust Provider Hijacking | | NTFS File Attributes | | | | | | | |		
| | | System Firmware | | Obfuscated Files or Information | | | | | | | |		
| | | * **Time Providers** | | Parent PID Spoofing | | | | | | | |
| | | * **Valid Accounts** | | Process Doppelgänging | | | | | | | |			
| | | Web Shell | | Process Hollowing | | | | | | | |	
| | | Windows Management Instrumentation Event Subscription | | Process Injection | | | | | | | |
| | | Winlogon Helper DLL | | Redundant Access | | | | | | | |
| | | | | Regsvcs/Regasm | | | | | | | |
| | | | | Regsvr32 | | | | | | | |						
| | | | | * **Rootkit** | | | | | | | |			
| | | | | Rundll32 | | | | | | | |			
| | | | | Scripting | | | | | | | |			
| | | | | Signed Binary Proxy Execution | | | | | | | | 							
| | | | | Signed Script Proxy Execution | | | | | | | |			
| | | | | SIP and Trust Provider Hijacking | | | | | | | |				
| | | | | Software Packing | | | | | | | |
| | | | | Template Injection | | | | | | | |			
| | | | | Timestomp | | | | | | | |
| | | | | Trusted Developer Utilities | | | | | | | | 							
| | | | | Valid Accounts | | | | | | | |
| | | | | Virtualization/Sandbox Evasion | | | | | | | | 							
| | | | | Web Service | | | | | | | |
| | | | | XSL Script Processing | | | | | | | |
