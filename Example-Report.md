# :chart: Strategic Threat Intelligence & Detection Coverage Report

**Platform**: OpenCTI + Sigma + ATT&CK + Elastic + Gitlab
**Date**: <DATE>
**Author**: CTI Engineer

## :mag: Executive Summary
The Organisation has prioritised the following actors; **APT28, XYZABC, Turla, APT29, APT32, APT33, UNC5435, UNC5687, HOUND SPIDER, APT38, APT39, APT40, APT41, APT42** however there is no details in OpenCTI on **XYZABC**. The report provides an overview of available actors techniques, coverage by Elastic rules and suggested Sigma rules.
There is a total of **13** actors, **2935** Sigma rules, **1003** Elastic rules, and **301** unique techniques identified in the organisation's threat landscape.


# :scroll: Landscape Overview
| Intrusion Sets | Sigma Rules | Elastic Rules | Attack Patterns |
|----------------|-------------|----------------|----------------|
 | 13| 2935 | 1003  | 301 |

## :fire: TOP 10 ACTORS
| Name | Aliases | # of Techniques |
|------|---------|-----------------| 
| APT29 | IRON RITUAL, IRON HEMLOCK, NobleBaron, Dark Halo, NOBELIUM, UNC2452, YTTRIUM, The Dukes, Cozy Bear, CozyDuke, SolarStorm, Blue Kitsune, UNC3524, Midnight Blizzard, COZYBEAR, Office Monkeys, UAC-0029, JACKMACKEREL, Cloaked Ursa, CozyCar | 211 |
| APT41 | Wicked Panda, Brass Typhoon, BARIUM | 191 |
| APT28 | IRON TWILIGHT, SNAKEMACKEREL, Swallowtail, Group 74, Sednit, Sofacy, Pawn Storm, Fancy Bear, STRONTIUM, Tsar Team, Threat Group-4127, TG-4127, Forest Blizzard, FROZENLAKE, GruesomeLarch, FANCYBEAR, Sofacy Group, Zebrocy, Fighting Ursa, Tsar-Team, UAC-0001, UAC-0028 | 138 |
| APT32 | SeaLotus, OceanLotus, APT-C-00, Canvas Cyclone, BISMUTH | 78 |
| VENOMOUS BEAR | VENOMOUSBEAR, Secret Blizzard, Waterbug, Blue Python, Uroboros, BELUGASTURGEON, SUMMIT, KRYPTON, IRON HUNTER, Snake, Group 88, WhiteBear, Venomous Bear, Turla | 68 |
| APT38 | NICKEL GLADSTONE, BeagleBoyz, Bluenoroff, Stardust Chollima, Sapphire Sleet, COPERNICIUM, STARDUSTCHOLLIMA | 55 |
| APT39 | ITG07, Chafer, Remix Kitten | 53 |
| Leviathan | MUDCARP, Kryptonite Panda, Gadolinium, BRONZE MOHAWK, TEMP.Jumper, TEMP.Periscope, Gingham Typhoon, KRYPTONITEPANDA, APT40 | 50 |
| APT42 |  | 47 |
| APT33 | HOLMIUM, Elfin, Peach Sandstorm, REFINEDKITTEN, REFINED KITTEN | 34 |

## :triangular_flag_on_post: Coverage by MITRE Tactic

| MITRE Tactic          | # Techniques Used | Elastic Rules | Sigma Rules | Coverage % | High-Risk Techniques Without Coverage |
|-----------------------|-------------------|----------------|-------------|------------|--------------------------------------|


## :top: Top 10 Targetted Techniques by Actors
| Technique | Used by Actors | Count |
|-----------|----------------|-------|
| T1105 Ingress Tool Transfer | VENOMOUS BEAR, APT32, UNC5435, APT41, APT39, UNC5687, APT33, Leviathan, APT38, APT28, APT29 | 11 |
| T1059.001 PowerShell | APT42, VENOMOUS BEAR, APT32, UNC5435, APT41, APT39, APT33, Leviathan, APT38, APT28, APT29 | 11 |
| T1071.001 Web Protocols | APT42, VENOMOUS BEAR, APT32, UNC5435, APT41, APT39, APT33, APT38, APT28, APT29 | 10 |
| T1588.002 Tool | APT42, VENOMOUS BEAR, APT32, APT41, APT39, APT33, APT38, APT28, APT29 | 9 |
| T1547.001 Registry Run Keys / Startup Folder | VENOMOUS BEAR, APT32, APT41, APT39, UNC5687, APT33, Leviathan, APT28, APT29 | 9 |
| T1566.002 Spearphishing Link | APT42, VENOMOUS BEAR, APT32, APT39, APT33, Leviathan, APT28, APT29 | 8 |
| T1566.001 Spearphishing Attachment | APT32, APT41, APT39, APT33, Leviathan, APT38, APT28, APT29 | 8 |
| T1204.001 Malicious Link | VENOMOUS BEAR, APT32, APT39, APT33, Leviathan, APT38, APT28, APT29 | 8 |
| T1059.005 Visual Basic | APT42, VENOMOUS BEAR, APT32, APT41, APT39, APT33, Leviathan, APT38 | 8 |
| T1059.003 Windows Command Shell | VENOMOUS BEAR, APT32, UNC5435, APT41, APT38, APT28, APT29 | 7 |

## :mag: Detection Coverage
This section provides an overview of the coverage of techniques by Elastic and Sigma rules.  

### :dart: Top 10 Techniques with Elastic Rules and Sigma Rules
|Technique | Elastic rules | Sigma Rules | Covered |
|----------|---------------|-------------|---------|
| T1562 Impair Defenses | 94 | 21 | YES |
| T1098 Account Manipulation | 52 | 26 | YES |
| T1543 Create or Modify System Process | 50 | 9 | YES |
| T1021 Remote Services | 49 | 9 | YES |
| T1003 OS Credential Dumping | 46 | 29 | YES |
| T1036 Masquerading | 44 | 38 | YES |
| T1562.001 Disable or Modify Tools | 43 | 105 | YES |
| T1574 Hijack Execution Flow | 38 | 7 | YES |
| T1068 Exploitation for Privilege Escalation | 34 | 18 | YES |
| T1547 Boot or Logon Autostart Execution | 34 | 7 | YES |

### :warning: Top 10 Techniques with lowest Elastic Rules and/or Sigma Rules  
|Technique | Elastic Rules | Sigma Rules | Covered |
|----------|----------------|------------|---------|
| T1591 Gather Victim Org Information | 0 | 0 | NO |
| T1586.002 Email Accounts | 0 | 0 | NO |
| T1071.003 Mail Protocols | 0 | 0 | NO |
| T1001.001 Junk Data | 0 | 0 | NO |
| T1583.006 Web Services | 0 | 0 | NO |
| T1048.002 Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | 0 | 0 | NO |
| T1596 Search Open Technical Databases | 0 | 0 | NO |
| T1584.008 Network Devices | 0 | 0 | NO |
| T1583.001 Domains | 0 | 0 | NO |
| T1557.004 Evil Twin | 0 | 0 | NO |

### :rocket: 10 techniques with Sigma Rules but no Elastic Rules
| Technique | Sigma Rules | Elastic Rules | 5 Sigma Rule suggestions |
|-----------|-------------|---------------|----------------------|
| T1059.001 PowerShell | 177 | 0 | [SIGMA] Invoke-Obfuscation VAR+ Launcher - PowerShell, <br> [SIGMA] Non Interactive PowerShell Process Spawned, <br> [SIGMA] Remote PowerShell Session (PS Classic), <br> [SIGMA] Obfuscated PowerShell OneLiner Execution, <br> [SIGMA] Suspicious Interactive PowerShell as SYSTEM |
| T1059 Command and Scripting Interpreter | 75 | 0 | [SIGMA] Forfiles Command Execution, <br> [SIGMA] Add New Download Source To Winget, <br> [SIGMA] Potential Persistence Via VMwareToolBoxCmd.EXE VM State Change Script, <br> [SIGMA] Suspicious File Created In PerfLogs, <br> [SIGMA] Install New Package Via Winget Local Manifest |
| T1078 Valid Accounts | 50 | 0 | [SIGMA] OpenCanary - SSH Login Attempt, <br> [SIGMA] Azure Kubernetes Admission Controller, <br> [SIGMA] Unfamiliar Sign-In Properties, <br> [SIGMA] Guest Users Invited To Tenant By Non Approved Inviters, <br> [SIGMA] Microsoft 365 - Impossible Travel Activity |
| T1078.004 Cloud Accounts | 38 | 0 | [SIGMA] Sign-ins by Unknown Devices, <br> [SIGMA] Account Disabled or Blocked for Sign in Attempts, <br> [SIGMA] Use of Legacy Authentication Protocols, <br> [SIGMA] User Added To Privilege Role, <br> [SIGMA] Sign-ins from Non-Compliant Devices |
| T1059.003 Windows Command Shell | 23 | 0 | [SIGMA] HackTool - RedMimicry Winnti Playbook Execution, <br> [SIGMA] Suspicious HWP Sub Processes, <br> [SIGMA] Read Contents From Stdin Via Cmd.EXE, <br> [SIGMA] HackTool - Jlaive In-Memory Assembly Execution, <br> [SIGMA] AWS EC2 Startup Shell Script Change |
| T1090 Proxy | 21 | 0 | [SIGMA] Suspicious TCP Tunnel Via PowerShell Script, <br> [SIGMA] PUA- IOX Tunneling Tool Execution, <br> [SIGMA] Sign-In From Malware Infected IP, <br> [SIGMA] Connection Proxy, <br> [SIGMA] Potentially Suspicious Usage Of Qemu |
| T1059.007 JavaScript | 17 | 0 | [SIGMA] Csc.EXE Execution Form Potentially Suspicious Parent, <br> [SIGMA] Node Process Executions, <br> [SIGMA] File Was Not Allowed To Run, <br> [SIGMA] Potential SquiblyTwo Technique Execution, <br> [SIGMA] HackTool - CACTUSTORCH Remote Thread Creation |
| T1059.005 Visual Basic | 17 | 0 | [SIGMA] Adwind RAT / JRAT File Artifact, <br> [SIGMA] Suspicious Reconnaissance Activity Via GatherNetworkInfo.VBS, <br> [SIGMA] Suspicious Scripting in a WMI Consumer, <br> [SIGMA] Cscript/Wscript Uncommon Script Extension Execution, <br> [SIGMA] Csc.EXE Execution Form Potentially Suspicious Parent |
| T1059.004 Unix Shell | 12 | 0 | [SIGMA] JexBoss Command Sequence, <br> [SIGMA] Potential Abuse of Linux Magic System Request Key, <br> [SIGMA] BPFtrace Unsafe Option Usage, <br> [SIGMA] Linux Reverse Shell Indicator, <br> [SIGMA] Suspicious Download and Execute Pattern via Curl/Wget |
| T1113 Screen Capture | 9 | 0 | [SIGMA] Screen Capture Activity Via Psr.EXE, <br> [SIGMA] Windows Screen Capture with CopyFromScreen, <br> [SIGMA] Windows Recall Feature Enabled Via Reg.EXE, <br> [SIGMA] Windows Recall Feature Enabled - Registry, <br> [SIGMA] Screen Capture with Xwd |

### :chart: Coverage Summary
| Metric | Value | % |
|--------|-------|---|
| Total Techniques | 301 | 100% |
| Covered by Elastic | 185 | 61.46% |
| Covered by Sigma | 225 | 74.75% |
| Uncovered | 57 | 18.94% |

