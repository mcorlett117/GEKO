# :chart: Strategic Threat Intelligence & Detection Coverage Report

**Platform**: OpenCTI + Sigma + ATT&CK + Elastic + Gitlab
**Date**: 2025-08-12
**Author**: CTI Engineer

## :mag: Executive Summary
The Organisation has prioritised the following actors; **APT28, XYZABC, Turla, APT29, APT32, APT33, UNC5435, UNC5687, HOUND SPIDER, APT38, APT39, APT40, APT41, APT42** however there is no details in OpenCTI on **XYZABC**. The report provides an overview of available actors techniques, coverage by Elastic rules and suggested Sigma rules.
There is a total of **13** actors, **2258** Sigma rules, **1345** Elastic rules, and **301** unique techniques identified in the organisation's threat landscape.


# :scroll: Landscape Overview
| Intrusion Sets | Sigma Rules | Elastic Rules | Attack Patterns |
|----------------|--------------|------|------------------|
 | 13| 2258 | 1345  | 301 |

## :fire: TOP 10 ACTORS
| Name | Aliases | # of Techniques |
|------|---------|----------------| 
| APT29 | IRON RITUAL, IRON HEMLOCK, NobleBaron, Dark Halo, NOBELIUM, UNC2452, YTTRIUM, The Dukes, Cozy Bear, CozyDuke, SolarStorm, Blue Kitsune, UNC3524, Midnight Blizzard, COZYBEAR, Office Monkeys, UAC-0029, JACKMACKEREL, Cloaked Ursa, CozyCar | 211 |
| APT41 | Wicked Panda, Brass Typhoon, BARIUM | 191 |
| APT28 | IRON TWILIGHT, SNAKEMACKEREL, Swallowtail, Group 74, Sednit, Sofacy, Pawn Storm, Fancy Bear, STRONTIUM, Tsar Team, Threat Group-4127, TG-4127, Forest Blizzard, FROZENLAKE, GruesomeLarch, FANCYBEAR, Sofacy Group, Zebrocy, Fighting Ursa, Tsar-Team, UAC-0001, UAC-0028 | 138 |
| APT32 | SeaLotus, OceanLotus, APT-C-00, Canvas Cyclone, BISMUTH | 78 |
| Turla | IRON HUNTER, Group 88, Waterbug, WhiteBear, Snake, Krypton, Venomous Bear, Secret Blizzard, BELUGASTURGEON, VENOMOUSBEAR, SUMMIT, Uroboros, Blue Python | 68 |
| APT38 | NICKEL GLADSTONE, BeagleBoyz, Bluenoroff, Stardust Chollima, Sapphire Sleet, COPERNICIUM, STARDUSTCHOLLIMA | 55 |
| APT39 | ITG07, Chafer, Remix Kitten | 53 |
| Leviathan | MUDCARP, Kryptonite Panda, Gadolinium, BRONZE MOHAWK, TEMP.Jumper, TEMP.Periscope, Gingham Typhoon, KRYPTONITEPANDA, APT40 | 50 |
| APT42 |  | 47 |
| APT33 | HOLMIUM, Elfin, Peach Sandstorm, REFINEDKITTEN, REFINED KITTEN | 34 |

## :top: Top 10 Targetted Techniques by Actors
| Technique | Used by Actors | Count |
|--------------|----------------|-----------------|
| T1105 Ingress Tool Transfer | Turla, APT38, Leviathan, APT33, APT29, APT41, APT28, APT32, UNC5435, APT39, UNC5687 | 11 |
| T1059.001 PowerShell | Turla, APT38, Leviathan, APT33, APT29, APT41, APT28, APT32, UNC5435, APT39, APT42 | 11 |
| T1071.001 Web Protocols | Turla, APT38, APT33, APT29, APT41, APT28, APT32, UNC5435, APT39, APT42 | 10 |
| T1588.002 Tool | Turla, APT38, APT33, APT29, APT41, APT28, APT32, APT39, APT42 | 9 |
| T1547.001 Registry Run Keys / Startup Folder | Turla, Leviathan, APT33, APT29, APT41, APT28, APT32, APT39, UNC5687 | 9 |
| T1566.002 Spearphishing Link | Turla, Leviathan, APT33, APT29, APT28, APT32, APT39, APT42 | 8 |
| T1566.001 Spearphishing Attachment | APT38, Leviathan, APT33, APT29, APT41, APT28, APT32, APT39 | 8 |
| T1204.001 Malicious Link | Turla, APT38, Leviathan, APT33, APT29, APT28, APT32, APT39 | 8 |
| T1059.005 Visual Basic | Turla, APT38, Leviathan, APT33, APT41, APT32, APT39, APT42 | 8 |
| T1059.003 Windows Command Shell | Turla, APT38, APT29, APT41, APT28, APT32, UNC5435 | 7 |

## :mag: Detection Coverage
This section provides an overview of the coverage of techniques by Elastic and Sigma rules.  

### :dart: Top 10 Techniques with Elastic Rules and Sigma Rules
|Technique | Elastic rules | Sigma Rules | Covered |
|-------------|------------------|------------------|------------------------|
| T1059 Command and Scripting Interpreter | 172 | 55 | YES |
| T1562 Impair Defenses | 104 | 18 | YES |
| T1059.001 PowerShell | 76 | 176 | YES |
| T1078 Valid Accounts | 71 | 6 | YES |
| T1543 Create or Modify System Process | 64 | 9 | YES |
| T1098 Account Manipulation | 61 | 13 | YES |
| T1059.004 Unix Shell | 59 | 0 | YES |
| T1003 OS Credential Dumping | 56 | 23 | YES |
| T1021 Remote Services | 55 | 3 | YES |
| T1036 Masquerading | 52 | 36 | YES |

### :warning: Top 10 Techniques with lowest Elastic Rules and/or Sigma Rules  
|Technique | Elastic Rules | Sigma Rules | Covered |
|-------------|------------------|------------------|------------------------|
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
| Technique | Sigma Rules | Elastic Rules |
|-------------|------------------|------------------|
| T1090 Proxy | 14 | 0 |
| T1588.002 Tool | 9 | 0 |
| T1003.005 Cached Domain Credentials | 8 | 0 |
| T1587.001 Malware | 7 | 0 |
| T1090.001 Internal Proxy | 6 | 0 |
| T1552.006 Group Policy Preferences | 5 | 0 |
| T1119 Automated Collection | 4 | 0 |
| T1027.005 Indicator Removal from Tools | 4 | 0 |
| T1649 Steal or Forge Authentication Certificates | 4 | 0 |
| T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol | 4 | 0 |

### :chart: Coverage Summary
| Metric | Value | % |
|--------|-------|---|
| Total Techniques | 301 | 100% |
| Covered by Elastic | 204 | 67.77% |
| Covered by Sigma | 190 | 63.12% |
| Uncovered | 64 | 21.26% |

