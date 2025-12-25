# SkiaHelios Forensic Analysis Report

- **Generated:** 2025-12-25 07:17:11.303210
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
| Chronos | CRITICAL | 30 |
| Plutos | CRITICAL | 4 |
| Sphinx | CRITICAL | 3 |

## 2. Anomalous Storyline (Event Sequence)
> Chronological fusion of all high-priority anomalies.

| Timestamp | Module | Anomaly Description |
|---|---|---|
| 2024-04-01 16:38:39.1038381 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in SecHealthUI.exe |
| 2024-04-01 16:38:39.1663418 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in SecHealthUIDataModel.dll |
| 2024-04-01 16:38:39.1975916 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in SecHealthUITelemetry.dll |
| 2024-04-01 16:38:39.2132026 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in SecHealthUIViewModels.dll |
| 2024-04-01 16:39:43.3932787 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in NotepadExplorerCommand.dll |
| 2024-04-01 16:39:43.4400308 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in msptls.dll |
| 2024-04-01 16:39:43.4713115 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in Notepad.exe |
| 2024-04-01 16:39:43.5025815 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in NotepadXamlUI.dll |
| 2024-04-01 16:39:43.5806551 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in riched20.dll |
| 2024-04-01 16:42:38.2257227 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in Microsoft.Windows.Widgets.dll |
| 2024-04-01 16:42:45.9135425 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in WebView2Loader.dll |
| 2024-04-01 16:42:45.9292307 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in WidgetPicker.dll |
| 2024-04-01 16:42:46.1479297 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in Widgets.exe |
| 2024-04-01 16:42:46.1792429 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in WidgetService.exe |
| 2024-04-01 16:42:46.1792429 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in wv2winrt.dll |
| 2024-04-01 16:42:46.8510636 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in GamePassWidget.exe |
| 2024-04-01 16:42:46.8510636 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in GamePassWidgetAppService.dll |
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
| 2025-12-21 12:25:56 | **Plutos** | Exfil/Access: set-persistenceaudit.ps1 (POTENTIAL_EXFILTRATION) |
| 2025-12-24 21:46:35.4965214 | **Sphinx** | Decoded: Target: NT AUTHORITY\SYSTEM... (SUSPICIOUS) |
| 2025-12-24 21:47:48.1571932 | **Sphinx** | Decoded: Parent process: C:\Windows\System32\appidcertstore... (SUSPICIOUS) |
| 2025-12-24 21:50:20.0550000 | **Chronos** | FALSIFIED_FUTURE (Score: 100) in OneDriveSetup.exe |

## 3. High-Priority Detection Details


### Obfuscation Decoded (Sphinx)
| Score | Tags | Hint |
|---|---|---|
| **46** | SUSPICIOUS | AppID: {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\magn... |
| **44** | SUSPICIOUS | Parent process: C:\Windows\System32\appidcertstore... |
| **41** | SUSPICIOUS | Target: NT AUTHORITY\SYSTEM... |

---
*End of SkiaHelios Report.*