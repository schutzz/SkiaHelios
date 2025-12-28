# Incident Investigation Report (Mock Final)

### 🛡️ Evidence & Case Info
| Item | Details |
|---|---|
| **Case Name** | Operation Mock Final |
| **Date** | 2025-12-28 |
| **Examiner** | Antigravity Agent |
| **Status** | Analyzed (SkiaHelios v15.23) |

---

## 1. Executive Summary
**結論:**
2025-01-01T16:10:00 (UTC) 頃、端末 Operation Mock Final において、**悪意あるスクリプトの実行を起点とした攻撃活動**を検知しました。

**侵害されたアカウント:**
主に **MockUser** アカウントでの活動が確認されています。

**被害範囲:**
攻撃者により、以下の活動が行われた痕跡を確認しました。
* **C2通信、永続化設定、証拠隠滅、不正スクリプトの実行、不正ツールの作成**

## 2. Investigative Timeline
### 📅 Phase 1 (2025-01-01)
| Time (UTC) | User | フェーズ | イベント概要 | 証拠ソース |
|---|---|---|---|---|
| 15:59:59 | System/Inferred | File Drop | Lifecycle Trace [Birth]: BadScript.bat | Nemesis (MFT) |
| 15:59:59 | System/Unknown | File Drop | File Creation (Inferred): cmd.exe (Origin: Local/Consistent Timestamp) | Inferred from Execution (Log) |
| 16:00:00 | System/Inferred | File Drop | Lifecycle Trace [Birth]: BadScript.bat [PROVISIONAL ORIGIN] | Nemesis (USN) |
| 16:09:59 | MockUser | File Drop | File Creation (Inferred): updateservice.exe (Origin: Local/Consistent Timestamp) | Inferred from Execution (Log) |
| 16:00:00 | System/Unknown | Initial Access | Script Execution: ATTACK | PowerShell Evtx (4104) |
| 16:05:00 | System/Unknown | C2 Communication | C2 Connection: http://malicious-c2.com/beacon | EventLog |
| 16:10:00 | MockUser | Persistence | Persistence: UpdateService.exe | Registry (Persistence) |
| None | System/Unknown | Anti-Forensics | File Deletion: None | USN Journal |

## 3. Technical Findings
### 3.1. Initial Access
- **検出事項:** Script Execution: ATTACK
  - **検知日時:** 2025-01-01 16:00:00 (UTC)
  - **実行ユーザー:** System/Unknown
  - **分析:** 不審なスクリプトブロックの実行を検知しました。
  - **起源推測:** Zone.Identifier（Webダウンロード痕跡）が確認できません。ドロッパーによるローカル作成、Zip解凍、または物理メディア経由の持ち込みと推測されます。
  - **証拠:** PowerShell Evtx (4104)
  - **関連要素:** `cmd.exe`
  - **詳細ログ:**
```text
cmd.exe /c start C:\Temp\BadScript.bat...
```


### 3.2. File Drop
- **検出事項:** Lifecycle Trace [Birth]: BadScript.bat
  - **検知日時:** 2025-01-01 15:59:59 (UTC)
  - **実行ユーザー:** System/Inferred
  - **分析:** ディスク上での新規ファイル作成（File Drop）を確認しました。実行の前段階として攻撃ツールが配置された痕跡です。
  - **起源推測:** Zone.Identifier（Webダウンロード痕跡）が確認できません。ドロッパーによるローカル作成、Zip解凍、または物理メディア経由の持ち込みと推測されます。
  - **証拠:** Nemesis (MFT)
  - **関連要素:** `BadScript.bat`
  - **詳細ログ:**
```text
Mode: Origin Trace (Execution) | Reason: FILE_CREATE
Path: C:\Temp
Owner: N/A...
```

- **検出事項:** File Creation (Inferred): cmd.exe (Origin: Local/Consistent Timestamp)
  - **検知日時:** 2025-01-01 15:59:59 (UTC)
  - **実行ユーザー:** System/Unknown
  - **分析:** ディスク上での新規ファイル作成（File Drop）を確認しました。実行の前段階として攻撃ツールが配置された痕跡です。
  - **起源推測:** Zone.Identifier（Webダウンロード痕跡）が確認できません。ドロッパーによるローカル作成、Zip解凍、または物理メディア経由の持ち込みと推測されます。
  - **証拠:** Inferred from Execution (Log)
  - **関連要素:** `cmd.exe`
  - **詳細ログ:**
```text
File 'cmd.exe' executed but has no anomaly record.
Creation inferred from first execution time....
```

- **検出事項:** Lifecycle Trace [Birth]: BadScript.bat [PROVISIONAL ORIGIN]
  - **検知日時:** 2025-01-01 16:00:00 (UTC)
  - **実行ユーザー:** System/Inferred
  - **分析:** ディスク上での新規ファイル作成（File Drop）を確認しました。実行の前段階として攻撃ツールが配置された痕跡です。
  - **起源推測:** Zone.Identifier（Webダウンロード痕跡）が確認できません。ドロッパーによるローカル作成、Zip解凍、または物理メディア経由の持ち込みと推測されます。
  - **証拠:** Nemesis (USN)
  - **関連要素:** `BadScript.bat`
  - **詳細ログ:**
```text
Mode: Origin Trace (Execution) | Reason: FILE_CREATE
Path: C:\Temp
Owner: N/A (Reason: Oldest Trace / Birth Missing | Reliability Source: USN)...
```

- **検出事項:** File Creation (Inferred): updateservice.exe (Origin: Local/Consistent Timestamp)
  - **検知日時:** 2025-01-01 16:09:59 (UTC)
  - **実行ユーザー:** MockUser
  - **分析:** ディスク上での新規ファイル作成（File Drop）を確認しました。実行の前段階として攻撃ツールが配置された痕跡です。
  - **起源推測:** Zone.Identifier（Webダウンロード痕跡）が確認できません。ドロッパーによるローカル作成、Zip解凍、または物理メディア経由の持ち込みと推測されます。
  - **証拠:** Inferred from Execution (Log)
  - **関連要素:** `updateservice.exe`
  - **詳細ログ:**
```text
File 'updateservice.exe' executed but has no anomaly record.
Creation inferred from first execution time....
```


### 3.3. C2 Communication
- **検出事項:** C2 Connection: http://malicious-c2.com/beacon
  - **検知日時:** 2025-01-01 16:05:00 (UTC)
  - **実行ユーザー:** System/Unknown
  - **分析:** 外部への不審な通信（C2）を検知しました。
  - **証拠:** EventLog
  - **関連要素:** `http://malicious-c2.com/beacon`
  - **詳細ログ:**
```text
Connect http://malicious-c2.com/beacon...
```


### 3.4. Persistence
- **検出事項:** Persistence: UpdateService.exe
  - **検知日時:** 2025-01-01 16:10:00 (UTC)
  - **実行ユーザー:** MockUser
  - **分析:** 永続化設定が確認されました。
  - **起源推測:** Zone.Identifier（Webダウンロード痕跡）が確認できません。ドロッパーによるローカル作成、Zip解凍、または物理メディア経由の持ち込みと推測されます。
  - **証拠:** Registry (Persistence)
  - **関連要素:** `UpdateService.exe`
  - **詳細ログ:**
```text
Path: C:\Windows\Temp\UpdateService.exe
Location: HKCU\Software\Microsoft\Windows\CurrentVersion\Run...
```


### 3.5. Anti-Forensics
- **検出事項:** File Deletion: None
  - **検知日時:** None (UTC)
  - **実行ユーザー:** System/Unknown
  - **分析:** 攻撃活動の痕跡隠滅（ファイル削除）です。
  - **証拠:** USN Journal
  - **関連要素:** `None`
  - **詳細ログ:**
```text
Restored Path: C:\Temp...
```


## 4. Conclusion & Recommendations
**封じ込め:**
端末をネットワークから切断し、全社環境において同様のIoC（ファイルハッシュ、通信先）を持つ端末がないかスキャンを実施してください。

**根絶:**
特定された永続化ファイル（UpdateService.exe等）および関連するレジストリキー、タスクスケジューラ設定を削除してください。

**回復:**
バックアップから削除されたファイル（Confidential_Design.docx等）を復元し、**影響を受けたアカウント（MockUser）**のパスワードリセットを行ってください。

## 5. Appendix
Appendix A: Master Timeline CSV
Appendix B: Tool Output Logs

---
*Report generated by SkiaHelios v15.23*