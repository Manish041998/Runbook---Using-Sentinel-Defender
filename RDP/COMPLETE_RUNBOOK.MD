# RDP Lateral Movement Investigation Guide

I'll break this down into a clear investigation workflow with corresponding KQL queries you can use in Microsoft Sentinel, Defender for Endpoint, or Log Analytics.

---

## Investigation Flow Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 1: Initial Detection (Anomaly Spotted)                       │
│  → Unusual RDP connections, weird times, strange source/dest pairs  │
└───────────────────────────┬─────────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 2: Validate the Connection                                   │
│  → Check Event 1149 (attempt) + 4624 (success) + Session logs       │
└───────────────────────────┬─────────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 3: Investigate Source Machine                                │
│  → mstsc.exe execution, Registry MRU, Bitmap Cache                  │
└───────────────────────────┬─────────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 4: Investigate Target Machine                                │
│  → tstheme.exe/rdpclip.exe in Prefetch, post-exploitation activity  │
└───────────────────────────┬─────────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 5: Map the Full Attack Path                                  │
│  → Timeline all RDP hops, identify credential theft, find patient 0 │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Initial Detection — Find Anomalous RDP Activity

### What to look for
- RDP at unusual hours (nights, weekends)
- RDP between systems that shouldn't communicate
- Sudden spike in RDP connections
- RDP from non-admin workstations to servers

### KQL: Detect RDP Logins at Unusual Hours

```kql
SecurityEvent
| where EventID == 4624
| where LogonType in (10, 7)  // 10 = new RDP, 7 = reconnect
| extend HourOfDay = datetime_part("hour", TimeGenerated)
| where HourOfDay < 6 or HourOfDay > 22  // Outside 6 AM - 10 PM
| project 
    TimeGenerated,
    Computer,
    TargetAccount = TargetUserName,
    SourceIP = IpAddress,
    SourceWorkstation = WorkstationName,
    LogonType,
    HourOfDay
| order by TimeGenerated desc
```

### KQL: Detect RDP Between Unusual Machine Pairs

```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| summarize 
    ConnectionCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP = IpAddress, TargetMachine = Computer, Account = TargetUserName
| where ConnectionCount == 1  // First-time connection = suspicious
| order by LastSeen desc
```

### KQL: Detect RDP Brute Force Attempts

```kql
SecurityEvent
| where EventID in (4625, 4624)  // Failed + Successful logins
| where LogonType in (3, 10)
| summarize 
    FailedAttempts = countif(EventID == 4625),
    SuccessfulLogins = countif(EventID == 4624),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated),
    TargetAccounts = make_set(TargetUserName)
    by SourceIP = IpAddress, TargetMachine = Computer
| where FailedAttempts > 10  // Threshold for brute force
| extend AttackDuration = LastAttempt - FirstAttempt
| order by FailedAttempts desc
```

---

## Phase 2: Validate the RDP Connection

### What to check
- Event 1149 → RDP connection attempt
- Event 4624 (Type 10 or 7) → Successful logon
- Events 21, 22, 25 → Session activity

### KQL: Correlate RDP Attempt (1149) with Successful Logon (4624)

```kql
let RDPAttempts = 
    Event
    | where Source == "Microsoft-Windows-TerminalServices-RemoteConnectionManager"
    | where EventID == 1149
    | extend SourceIP = extract(@"Source Network Address:\s+(\S+)", 1, RenderedDescription)
    | extend AttemptUser = extract(@"User:\s+(\S+)", 1, RenderedDescription)
    | project AttemptTime = TimeGenerated, Computer, SourceIP, AttemptUser;
let RDPSuccess = 
    SecurityEvent
    | where EventID == 4624
    | where LogonType == 10
    | project LogonTime = TimeGenerated, Computer, SourceIP = IpAddress, LogonUser = TargetUserName;
RDPAttempts
| join kind=inner (RDPSuccess) on Computer, SourceIP
| where abs(datetime_diff('second', AttemptTime, LogonTime)) < 60
| project 
    AttemptTime,
    LogonTime,
    TargetMachine = Computer,
    SourceIP,
    User = LogonUser,
    TimeDelta = datetime_diff('second', LogonTime, AttemptTime)
```

### KQL: Track Full RDP Session Lifecycle

```kql
Event
| where Source in (
    "Microsoft-Windows-TerminalServices-LocalSessionManager",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager"
)
| where EventID in (21, 22, 23, 24, 25, 39, 40, 1149)
| extend EventDescription = case(
    EventID == 1149, "RDP Connection Attempt",
    EventID == 21, "Session Logon Succeeded",
    EventID == 22, "Shell Started (Desktop Ready)",
    EventID == 23, "Session Logoff",
    EventID == 24, "Session Disconnected",
    EventID == 25, "Session Reconnected",
    EventID == 39, "Session Disconnected (X)",
    EventID == 40, "Session Disconnected (Y)",
    "Other"
)
| project TimeGenerated, Computer, EventID, EventDescription, RenderedDescription
| order by Computer, TimeGenerated asc
```

---

## Phase 3: Investigate the Source Machine

### What to check
- **mstsc.exe** execution (UserAssist, BAM, Prefetch)
- **Registry MRU** → list of RDP targets
- **Bitmap Cache** → visual evidence

### KQL: Detect mstsc.exe Execution (Defender for Endpoint)

```kql
DeviceProcessEvents
| where FileName =~ "mstsc.exe"
| project 
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

### KQL: Find RDP Targets from Command Line

```kql
DeviceProcessEvents
| where FileName =~ "mstsc.exe"
| where ProcessCommandLine contains "/v:"  // Target specified in command
| extend RDPTarget = extract(@"/v[:\s]+([^\s]+)", 1, ProcessCommandLine)
| project 
    Timestamp,
    SourceMachine = DeviceName,
    User = AccountName,
    RDPTarget,
    FullCommand = ProcessCommandLine
| order by Timestamp desc
```

### KQL: Detect Credential Dumping Before RDP (Mimikatz Pattern)

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("mimikatz.exe", "procdump.exe", "rundll32.exe")
    or ProcessCommandLine has_any ("sekurlsa", "lsass", "comsvcs.dll", "MiniDump")
| project 
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine
| order by Timestamp desc
```

---

## Phase 4: Investigate the Target Machine

### What to check
- **tstheme.exe** and **rdpclip.exe** execution
- Post-exploitation activity after RDP session starts
- New processes spawned under RDP session

### KQL: Detect RDP Session Indicators on Target

```kql
DeviceProcessEvents
| where FileName in~ ("tstheme.exe", "rdpclip.exe")
| project 
    Timestamp,
    TargetMachine = DeviceName,
    FileName,
    AccountName,
    InitiatingProcessFileName
| order by Timestamp desc
```

### KQL: Detect Suspicious Activity After RDP Login

```kql
let RDPLogins = 
    SecurityEvent
    | where EventID == 4624 and LogonType == 10
    | project RDPTime = TimeGenerated, TargetMachine = Computer, RDPUser = TargetUserName, SourceIP = IpAddress;
let SuspiciousProcesses = 
    DeviceProcessEvents
    | where FileName in~ (
        "powershell.exe", "cmd.exe", "whoami.exe", "net.exe", 
        "nltest.exe", "ping.exe", "systeminfo.exe", "tasklist.exe",
        "reg.exe", "wmic.exe", "certutil.exe", "bitsadmin.exe"
    )
    | project ProcessTime = Timestamp, TargetMachine = DeviceName, User = AccountName, FileName, ProcessCommandLine;
RDPLogins
| join kind=inner (SuspiciousProcesses) on TargetMachine
| where ProcessTime between (RDPTime .. (RDPTime + 30m))  // Within 30 min of RDP
| project 
    RDPTime,
    ProcessTime,
    TargetMachine,
    RDPUser,
    SourceIP,
    SuspiciousProcess = FileName,
    Command = ProcessCommandLine
| order by RDPTime, ProcessTime
```

---

## Phase 5: Map the Full Attack Path

### KQL: Build RDP Lateral Movement Chain

```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| project 
    Timestamp = TimeGenerated,
    TargetMachine = Computer,
    User = TargetUserName,
    SourceIP = IpAddress,
    SourceWorkstation = WorkstationName
| order by Timestamp asc
| extend Step = row_number()
| project Step, Timestamp, SourceWorkstation, SourceIP, TargetMachine, User
```

### KQL: Visualize RDP Movement Over Time

```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| summarize 
    Connections = count(),
    Users = make_set(TargetUserName)
    by SourceIP = IpAddress, TargetMachine = Computer, bin(TimeGenerated, 1h)
| order by TimeGenerated asc
| render timechart
```

---

## Quick Reference: Event IDs to Remember

| Event ID | Source | Meaning |
|----------|--------|---------|
| **1149** | RemoteConnectionManager | RDP connection attempted |
| **4624** | Security | Successful logon (Type 10 = RDP, Type 7 = reconnect) |
| **4625** | Security | Failed logon (brute force indicator) |
| **21** | LocalSessionManager | Session logon succeeded |
| **22** | LocalSessionManager | Shell/desktop started |
| **23** | LocalSessionManager | Session logged off |
| **24/39/40** | LocalSessionManager | Session disconnected |
| **25** | LocalSessionManager | Session reconnected |

---

## Investigation Checklist

When you suspect RDP lateral movement:

1. **Identify the alert/anomaly** — what triggered the investigation?
2. **Pull Event 4624 Type 10** — who logged in, from where, when?
3. **Check for brute force (4625 spikes)** — was access forced?
4. **Check source machine** — did mstsc.exe run? Check registry MRU
5. **Check target machine** — tstheme/rdpclip execution? What happened after?
6. **Look for credential theft** — Mimikatz, LSASS dumps before RDP?
7. **Map the chain** — how many hops? Where did attacker go next?
8. **Check bitmap cache** — can you reconstruct what attacker saw?
