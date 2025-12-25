# SkiaHelios Forensic Analysis Report

- **Generated:** 2025-12-25 11:10:56.469327
- Custom DFIR framework for high-resolution artifact correlation.

## 0. Methodology & Artifact Legend
SkiaHelios correlates disparate artifacts to reconstruct attacker intent.

### Modules:
- **Chaos**: Master Timeline construction.
- **Chronos**: MFT Time Paradox (Timestomp) detection.
- **AION**: Persistence hunting correlated with MFT.
- **Plutos**: Exfiltration tracking via USB/Network.
- **Sphinx**: Decoding obfuscated scripts.

### Tag Legend:
- `TIMESTOMP_BACKDATE`: $SI < $FN Creation Time discrepancy.
- `USER_PERSISTENCE`: Persistence detected in HKCU (User-level).
- `WMI_PERSISTENCE`: WMI Eventing used for fileless persistence.

## 1. Executive Summary

| Module | Risk Level | Detection Count |
|---|---|---|
| Plutos | CRITICAL | 0 |
| Sphinx | CRITICAL | 7 |

## 2. Anomalous Storyline (Event Sequence)
> Chronological fusion of all high-priority anomalies.

| Timestamp | Module | Anomaly Description |
|---|---|---|
| 2025-12-21 11:51:52.9071767 | **Sphinx** | Decoded: [FORCE DECODE] Attack Keyword Found: HostApplication=C:\WINDOWS\System32\WindowsPowerSh... (ATTACK_SIG_DETECTED) |
| 2025-12-21 11:51:52.9108124 | **Sphinx** | Decoded: [FORCE DECODE] Attack Keyword Found: HostApplication=C:\WINDOWS\System32\WindowsPowerSh... (ATTACK_SIG_DETECTED) |
| 2025-12-21 11:51:52.9135893 | **Sphinx** | Decoded: [FORCE DECODE] Attack Keyword Found: HostApplication=C:\WINDOWS\System32\WindowsPowerSh... (ATTACK_SIG_DETECTED) |
| 2025-12-21 11:51:52.9219339 | **Sphinx** | Decoded: [FORCE DECODE] Attack Keyword Found: HostApplication=C:\WINDOWS\System32\WindowsPowerSh... (ATTACK_SIG_DETECTED) |
| 2025-12-21 11:51:52.9232563 | **Sphinx** | Decoded: [FORCE DECODE] Attack Keyword Found: HostApplication=C:\WINDOWS\System32\WindowsPowerSh... (ATTACK_SIG_DETECTED) |
| 2025-12-21 11:51:52.9248439 | **Sphinx** | Decoded: [FORCE DECODE] Attack Keyword Found: HostApplication=C:\WINDOWS\System32\WindowsPowerSh... (ATTACK_SIG_DETECTED) |
| 2025-12-21 11:51:54.0237174 | **Sphinx** | Decoded: [FORCE DECODE] Attack Keyword Found: HostApplication=C:\WINDOWS\System32\WindowsPowerSh... (ATTACK_SIG_DETECTED) |

## 3. High-Priority Detection Details


### Obfuscation Decoded (Sphinx)
| Score | Tags | Hint |
|---|---|---|
| **150** | ATTACK_SIG_DETECTED | [FORCE DECODE] Attack Keyword Found: HostApplication=C:\WINDOWS\System32\WindowsPowerSh... |
| **150** | ATTACK_SIG_DETECTED | [FORCE DECODE] Attack Keyword Found: HostApplication=C:\WINDOWS\System32\WindowsPowerSh... |
| **150** | ATTACK_SIG_DETECTED | [FORCE DECODE] Attack Keyword Found: HostApplication=C:\WINDOWS\System32\WindowsPowerSh... |
| **150** | ATTACK_SIG_DETECTED | [FORCE DECODE] Attack Keyword Found: HostApplication=C:\WINDOWS\System32\WindowsPowerSh... |
| **150** | ATTACK_SIG_DETECTED | [FORCE DECODE] Attack Keyword Found: HostApplication=C:\WINDOWS\System32\WindowsPowerSh... |

---
*End of SkiaHelios Report.*