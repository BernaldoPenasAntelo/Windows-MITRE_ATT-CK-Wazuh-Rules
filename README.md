# Windows-MITRE_ATT-CK-Wazuh-Rules

This is a set of rules that i was developing for wazuh HIDS based on MITRE ATT&CK Framework to complement the windows base ruleset.
I add rules as i develop them for my own needs.
Use under your own risk.


The idea is to work with two files:

1. The first one **rules_regular_events.txt** consist on rules that one can obtain just with regular windows events 

### Note that in many cases you must enable the event in wazuh agent config
>  <localfile>
>    <location>Security</location>
>    <log_format>eventchannel</log_format>
>    <query>Event/System[EventID != 5145 and EventID != 5156 and EventID != 5447 and
>      EventID != 4656 and EventID != 4658 and EventID != 4663 and EventID != 4660 and
>      EventID != 4670 and EventID != 4690 and EventID != 4703 and EventID != 4907]</query>
>  </localfile>


2. The second one **rules_sysmon_events.txt** consist on rules based on sysmon events, to use them you must first install and configure sysmon.

