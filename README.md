# SOC Home Lab: Windows Monitoring with Splunk

I built a Windows SOC lab to practise collecting and investigating endpoint activity using Splunk and Sysmon. The aim was to understand how common attacker techniques appear in Windows event logs and develop searches to identify them.

I used Atomic Red Team to simulate several techniques, investigated the resulting events in Splunk and saved five detection queries along with screenshots of the findings.

## Setup

| Component | Tools |
|---|---|
| SIEM | Splunk Enterprise |
| Endpoint | Windows 11 VM |
| Virtualisation | Oracle VirtualBox |
| Log forwarding | Splunk Universal Forwarder |
| Data sources | Windows Security, System and Sysmon |
| Simulations | Atomic Red Team and PowerShell |

Splunk Enterprise runs on the host machine, while the Windows VM sends logs through a host-only network connection on TCP port 9997. Events are collected in the `windows` index.

Setting up the logging pipeline took some troubleshooting. I encountered issues with the host-only network adapter, Windows Firewall and permissions for accessing Sysmon logs. Security and System events were reaching Splunk before Sysmon was, so I had to investigate the forwarding configuration and service permissions separately.

Once all three log sources were working, I moved on to the simulations.

## Detection testing

### 1. Local account creation

**MITRE ATT&CK:** T1136.001  
**Event ID:** 4720  
**Atomic test:** T1136.001-4

The test created a local Windows account named `T1136.001_CMD`. I located the corresponding event in Splunk, which showed the account that had been created and the user responsible.

This type of event is useful when investigating unexpected account creation, but it would need to be checked against legitimate administration. I'd also want to look for subsequent activity involving the new account, particularly changes to group membership.

[View evidence](screenshots/01-local-account-creation.png)

### 2. Scheduled task creation

**MITRE ATT&CK:** T1053.005  
**Event ID:** 4698  
**Atomic test:** T1053.005-2

I created a scheduled task called `spawn` using Atomic Red Team. The task was configured to launch `cmd.exe`.

The event in Splunk included the task name and its XML configuration, allowing me to inspect what had been registered.

Scheduled tasks are frequently created by legitimate programs, so I'd need to look at the task's executable, creator and schedule before deciding whether it was suspicious.

[View evidence](screenshots/02-scheduled-task-creation.png)

### 3. Registry Run key persistence

**MITRE ATT&CK:** T1547.001  
**Event ID:** 13 (Sysmon)  
**Atomic test:** T1547.001-1

This simulation added a registry value named `Atomic Red Team` under:

`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

The value pointed to `C:\Path\AtomicRedTeam.exe`, which was a placeholder path used by the test.

Sysmon logged the modification and identified `reg.exe` as the process responsible.

The search I used included the test value name to locate the event. For more general detection coverage, I'd remove that dependency and monitor changes to relevant startup registry locations instead.

[View evidence](screenshots/03-registry-run-key.png)

### 4. Windows event log clearing

**MITRE ATT&CK:** T1685.005  
**Event ID:** 104 (System)

I initially inspected an Atomic Red Team test for log clearing, but it would have removed events from several existing Windows logs.

Instead, I created a separate log named `SOC-Lab-Test`, wrote a test event into it and cleared that log using PowerShell.

Splunk recorded Event ID 104, confirming that the test log had been cleared.

This allowed me to investigate log-clearing activity without removing the Security and Sysmon events from the earlier simulations.

[View evidence](screenshots/04-event-log-clearing.png)

### 5. Failed logon attempts

**MITRE ATT&CK:** T1110 (related technique)  
**Event ID:** 4625

I generated failed network authentication attempts against a nonexistent account called `SOC_Test_InvalidUser`.

Three failed logons were recorded. The events included the targeted account, authentication method and logon type.

For this test, I used SPL to group failures into ten-minute intervals and count the number of attempts. All three events appeared in the same interval.

I set the threshold to two failures for testing because the dataset was small. This would be too sensitive for most real environments. A better approach would be to group failures by account and source address, then determine an appropriate threshold based on normal login activity.

[Event details](screenshots/05-failed-logon-evidence.png) | [Detection results](screenshots/05-failed-logon-detection.png)

## SPL queries

The five searches are available in the [detections folder](detections/).

Most of the searches identify specific event types. The failed-logon detection also uses time-based aggregation to identify repeated authentication failures.

These queries were tested against events generated in my lab. They have not been tuned or evaluated against production data.

## Further improvements

There are several things I'd like to build on.

The first is improving the detection logic. Individual event IDs can indicate activity worth investigating, but they often lack enough context to determine whether something is malicious. I'd like to correlate account creation with privilege changes, scheduled-task creation with process execution, and registry changes with the programs being configured to run.

I'd also like to improve the failed-authentication detection by accounting for source IP addresses, targeted accounts and normal login patterns.

Another area is alerting. So far, I've focused on generating events, confirming they're collected correctly and testing searches manually. The next stage would be converting selected searches into scheduled alerts and testing their reliability.

## Notes

All simulations were carried out in a controlled Windows VM. The screenshots show activity generated for testing, not genuine security incidents.

All simulations were carried out in a controlled Windows VM. The screenshots show activity generated for testing, not genuine security incidents.
