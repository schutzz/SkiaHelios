# SkiaHelios Forensic Analysis Report

- **Generated:** 2025-12-25 11:06:20.179711
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
| Chronos | CRITICAL | 4 |
| Plutos | CRITICAL | 0 |
## 2. Anomalous Storyline (Event Sequence)
> Chronological fusion of all high-priority anomalies.

| Timestamp | Module | Anomaly Description |
|---|---|---|
| 2024-04-01 07:22:07.6534661 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in TaskScheduler.dll |
| 2024-04-01 16:33:09.6173245 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in TaskScheduler.resources.dll |
| 2024-04-01 16:37:17.0014995 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in TaskScheduler.ni.dll |
| 2024-04-01 16:37:17.4233365 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in TaskScheduler.ni.dll |

## 3. High-Priority Detection Details


---
*End of SkiaHelios Report.*