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


Initial Access |	Execution |	Persistence |	Privilege Escalation |	Defense Evasion |	Credential Access |	Discovery |	Lateral Movement |	Collection |	Command and Control |	Exfiltration |	Impact
---- |	---- |	---- |	---- |	---- |	---- |	---- |	---- |	---- |	---- |	---- |	----
Drive-by Compromise |	CMSTP |	Accessibility Features |	Access Token Manipulation |	Access Token Manipulation |	Account Manipulation |	Account Discovery |	Application Deployment Software |	Audio Capture |	Commonly Used Port |	Automated Exfiltration |	Account Access Removal
Exploit Public-Facing Application |	Command-Line Interface |	Account Manipulation |	Accessibility Features |	Binary Padding |	Brute Force |	Application Window Discovery |	Component Object Model and Distributed COM |	Automated Collection |	Communication Through Removable Media |	Data Compressed |	Data Destruction
