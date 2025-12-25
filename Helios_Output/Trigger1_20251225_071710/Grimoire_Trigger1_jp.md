# SkiaHelios フォレンジック解析報告書

- **Generated:** 2025-12-25 07:17:11.323382
- アーティファクト間の相関分析に特化した自動生成報告書。

## 0. 調査手法および凡例
SkiaHeliosは、分散した証拠を紐付け、攻撃者の意図を再構成します。

### Modules:
- **Chaos**: マスタータイムラインの構築
- **Chronos**: MFTタイムスタンプ矛盾の検知
- **AION**: MFT相関型永続化メカニズムの探索
- **Plutos**: 情報持ち出しトラッキング
- **Sphinx**: 難読化スクリプトの解読

### Tag Legend:
- `TIMESTOMP_BACKDATE`: $SI時刻が$FN時刻より古い矛盾
- `USER_PERSISTENCE`: HKCU(ユーザー権限)での永続化検知
- `WMI_PERSISTENCE`: WMIを利用したファイルレス潜伏

## 1. エグゼクティブ・サマリー

| モジュール | リスクレベル | 検知件数 |
|---|---|---|
| Chronos | 【警告】要調査 | 30 |
| Plutos | 【警告】要調査 | 4 |
| Sphinx | 【警告】要調査 | 3 |

## 2. 異常イベント・ストーリーライン
> 各モジュールが検知した不審なイベントを時系列で構成しています。

| 発生時刻 | 検知モジュール | イベント内容 |
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

## 3. 高優先度検知詳細


### 難読化解除結果 (Sphinx)
| Score | Tags | Hint |
|---|---|---|
| **46** | SUSPICIOUS | AppID: {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\magn... |
| **44** | SUSPICIOUS | Parent process: C:\Windows\System32\appidcertstore... |
| **41** | SUSPICIOUS | Target: NT AUTHORITY\SYSTEM... |

---
*End of SkiaHelios Report.*