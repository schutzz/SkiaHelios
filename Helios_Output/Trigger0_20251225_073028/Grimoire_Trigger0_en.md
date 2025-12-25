# SkiaHelios Forensic Analysis Report

- **Generated:** 2025-12-25 07:30:29.647678
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
| Chronos | CRITICAL | 12 |
| Plutos | CRITICAL | 4 |
| Sphinx | CRITICAL | 1 |

## 2. Anomalous Storyline (Event Sequence)
> Chronological fusion of all high-priority anomalies.

| Timestamp | Module | Anomaly Description |
|---|---|---|
| 2025-09-15 19:39:40.3522077 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in PJLMON.DLL |
| 2025-09-15 19:39:40.3678354 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in MXDWDRV.DLL |
| 2025-09-15 19:39:40.3678354 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in PSCRIPT5.DLL |
| 2025-09-15 19:39:40.3678354 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in UNIDRV.DLL |
| 2025-09-15 19:39:40.3834709 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in PS5UI.DLL |
| 2025-09-15 19:39:40.3990841 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in UNIRES.DLL |
| 2025-09-15 19:39:40.4147139 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in UNIDRVUI.DLL |
| 2025-09-15 19:39:40.4147139 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in mxdwdrv.dll |
| 2025-09-15 19:39:40.6334754 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in PrintConfig.dll |
| 2025-09-15 19:39:40.6647141 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in PrintConfig.dll |
| 2025-09-15 19:40:08.4228220 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in winprint.dll |
| 2025-09-15 19:40:08.4696980 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in PrintBrmPs.dll |
| 2025-12-21 10:40:22 | **Plutos** | Exfil/Access: msedge.exe (POTENTIAL_EXFILTRATION) |
| 2025-12-21 10:40:22 | **Plutos** | Exfil/Access: msedge.exe (POTENTIAL_EXFILTRATION) |
| 2025-12-21 11:26:26.2047109 | **Sphinx** | Decoded: AppID: {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\magn... (SUSPICIOUS) |
| 2025-12-21 11:28:02 | **Plutos** | Exfil/Access: msedge.exe (POTENTIAL_EXFILTRATION) |
| 2025-12-21 11:30:22 | **Plutos** | Exfil/Access: onedrive.exe (CONFIRMED_EXFILTRATION) |

## 3. High-Priority Detection Details


### Obfuscation Decoded (Sphinx)
| Score | Tags | Hint |
|---|---|---|
| **46** | SUSPICIOUS | AppID: {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\magn... |

---
*End of SkiaHelios Report.*