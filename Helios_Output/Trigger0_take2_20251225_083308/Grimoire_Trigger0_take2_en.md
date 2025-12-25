# SkiaHelios Forensic Analysis Report

- **Generated:** 2025-12-25 08:33:10.076924
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
| Chronos | CRITICAL | 2 |
| Plutos | CRITICAL | 4 |
## 2. Anomalous Storyline (Event Sequence)
> Chronological fusion of all high-priority anomalies.

| Timestamp | Module | Anomaly Description |
|---|---|---|
| 2025-09-15 19:40:08.4228220 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in winprint.dll |
| 2025-09-15 19:40:08.4696980 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in PrintBrmPs.dll |
| 2025-12-21 10:40:22 | **Plutos** | Exfil/Access: msedge.exe (NORMAL_APP_ACCESS) |
| 2025-12-21 10:40:22 | **Plutos** | Exfil/Access: msedge.exe (NORMAL_APP_ACCESS) |
| 2025-12-21 11:28:02 | **Plutos** | Exfil/Access: msedge.exe (NORMAL_APP_ACCESS) |
| 2025-12-21 11:30:22 | **Plutos** | Exfil/Access: onedrive.exe (SYSTEM_INTERNAL_ACTIVITY) |

## 3. High-Priority Detection Details


---
*End of SkiaHelios Report.*